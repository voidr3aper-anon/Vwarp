package preflightbind

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bepass-org/warp-plus/wireguard/conn"
	"github.com/bepass-org/warp-plus/wireguard/device"
)

var rng = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

// AmneziaConfig holds the Amnezia WireGuard obfuscation parameters
type AmneziaConfig struct {
	// I1-I5: Signature packets for protocol imitation
	I1 string // Main obfuscation packet (hex string)
	I2 string // Additional signature packet
	I3 string // Additional signature packet
	I4 string // Additional signature packet
	I5 string // Additional signature packet

	// S1, S2: Random prefixes for Init/Response packets (0-64 bytes)
	S1 int // Random prefix for Init packets
	S2 int // Random prefix for Response packets

	// Junk packet configuration
	Jc   int // Number of junk packets (0-10)
	Jmin int // Minimum junk packet size (bytes)
	Jmax int // Maximum junk packet size (bytes)

	// Enhanced timing parameters for junk packets
	JcAfterI1  int // Junk packets to send after I1 packet
	JcBeforeHS int // Junk packets to send before handshake
	JcAfterHS  int // Junk packets to send after handshake

	// Timing configuration
	JunkInterval   time.Duration // Interval between junk packets
	AllowZeroSize  bool          // Allow zero-size junk packets
	HandshakeDelay time.Duration // Delay before actual handshake after I1
}

// Bind wraps a conn.Bind and fires QUIC-like preflight when WG sends a handshake initiation.
type Bind struct {
	inner            conn.Bind
	port443          int            // usually 443
	payload          []byte         // I1 bytes
	amneziaConfig    *AmneziaConfig // Amnezia configuration
	mu               sync.Mutex
	lastSent         map[netip.Addr]time.Time // rate-limit per dst IP
	interval         time.Duration            // e.g., 1s to avoid duplicate bursts
	postHandshakeSent map[netip.Addr]bool      // track if post-handshake junk sent per IP
}

func New(inner conn.Bind, hexPayload string, port int, minInterval time.Duration) (*Bind, error) {
	// hexPayload may start with "0x..."
	h := hexPayload
	if len(h) >= 2 && (h[:2] == "0x" || h[:2] == "0X") {
		h = h[2:]
	}
	p, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return &Bind{
		inner:             inner,
		port443:           port,
		payload:           p,
		lastSent:          make(map[netip.Addr]time.Time),
		postHandshakeSent: make(map[netip.Addr]bool),
		interval:          minInterval,
	}, nil
}

// NewWithAmnezia creates a new Bind with Amnezia configuration
func NewWithAmnezia(inner conn.Bind, amneziaConfig *AmneziaConfig, port int, minInterval time.Duration) (*Bind, error) {
	var payload []byte
	var err error

	if amneziaConfig != nil && amneziaConfig.I1 != "" {
		// Parse I1 using CPS format
		payload, err = parseCPSPacket(amneziaConfig.I1)
		if err != nil {
			return nil, fmt.Errorf("invalid I1 CPS format: %w", err)
		}
	}

	return &Bind{
		inner:             inner,
		port443:           port,
		payload:           payload,
		amneziaConfig:     amneziaConfig,
		lastSent:          make(map[netip.Addr]time.Time),
		interval:          minInterval,
		postHandshakeSent: make(map[netip.Addr]bool),
	}, nil
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) { return b.inner.Open(port) }
func (b *Bind) Close() error                                         { return b.inner.Close() }
func (b *Bind) SetMark(m uint32) error                               { return b.inner.SetMark(m) }
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error)        { return b.inner.ParseEndpoint(s) }
func (b *Bind) BatchSize() int                                       { return b.inner.BatchSize() }

// handshakeInitiation reports whether buf looks like a WG handshake initiation.
// Per spec: first byte == 1 (init), next 3 bytes are reserved = 0. Size is 148 for init.
// However, Cloudflare Warp uses reserved bytes, so we only check the first byte and size.
func handshakeInitiation(buf []byte) bool {
	if len(buf) < device.MessageInitiationSize {
		return false
	}
	// Check if it's a WireGuard handshake initiation (type 1) with correct size
	// We don't check the reserved bytes since Cloudflare uses custom values
	return buf[0] == byte(device.MessageInitiationType) && len(buf) >= device.MessageInitiationSize
}

// parseCPSPacket parses a Custom Protocol Signature packet format
// Format: <b hex_data><c><t><r length>
func parseCPSPacket(cps string) ([]byte, error) {
	if cps == "" {
		return nil, nil
	}

	var result []byte
	remaining := cps

	// Parse CPS tags using regex
	tagRegex := regexp.MustCompile(`<([btcr])\s*([^>]*)>`)
	matches := tagRegex.FindAllStringSubmatch(remaining, -1)

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		tagType := match[1]
		tagData := strings.TrimSpace(match[2])

		switch tagType {
		case "b": // Static bytes
			if tagData != "" {
				// Remove 0x prefix if present
				if strings.HasPrefix(tagData, "0x") || strings.HasPrefix(tagData, "0X") {
					tagData = tagData[2:]
				}
				// Remove spaces
				tagData = strings.ReplaceAll(tagData, " ", "")
				bytes, err := hex.DecodeString(tagData)
				if err != nil {
					return nil, fmt.Errorf("invalid hex data in <b> tag: %w", err)
				}
				result = append(result, bytes...)
			}
		case "c": // Counter (32-bit, network byte order)
			counter := uint32(time.Now().Unix() % 0xFFFFFFFF)
			counterBytes := []byte{
				byte(counter >> 24),
				byte(counter >> 16),
				byte(counter >> 8),
				byte(counter),
			}
			result = append(result, counterBytes...)
		case "t": // Timestamp (32-bit, network byte order)
			timestamp := uint32(time.Now().Unix())
			timestampBytes := []byte{
				byte(timestamp >> 24),
				byte(timestamp >> 16),
				byte(timestamp >> 8),
				byte(timestamp),
			}
			result = append(result, timestampBytes...)
		case "r": // Random bytes
			length := 0
			if tagData != "" {
				var err error
				length, err = strconv.Atoi(tagData)
				if err != nil {
					return nil, fmt.Errorf("invalid length in <r> tag: %w", err)
				}
				if length > 1000 {
					length = 1000 // Cap at 1000 bytes as per spec
				}
			}
			if length > 0 {
				randomBytes := make([]byte, length)
				_, err := rand.Read(randomBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to generate random bytes: %w", err)
				}
				result = append(result, randomBytes...)
			}
		}
	}

	return result, nil
}

// wrapInIKEv2Header wraps payload in IKEv2/IPsec header to mimic legitimate IKE negotiation
// This adds 52 bytes of IKEv2 framing to match Amnezia's behavior exactly
func wrapInIKEv2Header(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}

	// Full IKEv2 packet structure to match Amnezia (52 bytes overhead):
	// - IKEv2 Header: 28 bytes
	// - Security Association Payload: 24 bytes (header + minimal SA data)
	// Total overhead: 52 bytes

	// Extract or generate SPIs
	initiatorSPI := make([]byte, 8)
	if len(payload) >= 8 {
		copy(initiatorSPI, payload[:8])
	} else {
		rand.Read(initiatorSPI)
	}

	responderSPI := make([]byte, 8)
	rand.Read(responderSPI)

	// Calculate total length: 28 (IKEv2 header) + 24 (SA payload) + payload length
	totalLength := uint32(28 + 24 + len(payload))

	header := make([]byte, 0, int(totalLength))

	// ===== IKEv2 Header (28 bytes) =====
	header = append(header, initiatorSPI...)        // 8 bytes: Initiator SPI
	header = append(header, responderSPI...)        // 8 bytes: Responder SPI
	header = append(header, 0x21)                   // 1 byte: Next Payload (Security Association)
	header = append(header, 0x20)                   // 1 byte: Version 2.0
	header = append(header, 0x22)                   // 1 byte: Exchange Type (IKE_SA_INIT)
	header = append(header, 0x08)                   // 1 byte: Flags (Initiator)
	header = append(header, 0x00, 0x00, 0x00, 0x00) // 4 bytes: Message ID
	header = append(header, byte(totalLength>>24))  // 4 bytes: Total Length (big-endian)
	header = append(header, byte(totalLength>>16))
	header = append(header, byte(totalLength>>8))
	header = append(header, byte(totalLength))

	// ===== Security Association Payload (24 bytes minimum) =====
	saPayloadLength := uint16(24 + len(payload)) // SA payload length including data

	// SA Payload Header (4 bytes)
	header = append(header, 0x00)                     // 1 byte: Next Payload (last one)
	header = append(header, 0x00)                     // 1 byte: Critical + Reserved
	header = append(header, byte(saPayloadLength>>8)) // 2 bytes: Payload Length (big-endian)
	header = append(header, byte(saPayloadLength))

	// SA Proposal (20 bytes - minimal proposal structure)
	header = append(header, 0x00)       // 1 byte: Last proposal
	header = append(header, 0x00)       // 1 byte: Reserved
	header = append(header, 0x00, 0x14) // 2 bytes: Proposal Length (20 bytes)
	header = append(header, 0x01)       // 1 byte: Proposal number
	header = append(header, 0x01)       // 1 byte: Protocol ID (IKE)
	header = append(header, 0x00)       // 1 byte: SPI Size
	header = append(header, 0x04)       // 1 byte: Number of transforms

	// Transform substructures (12 bytes for 4 minimal transforms)
	// Transform 1 (Encryption)
	header = append(header, 0x03, 0x00, 0x00, 0x08) // 4 bytes: More transforms, length 8
	header = append(header, 0x01, 0x00, 0x00, 0x0c) // 4 bytes: Type 1 (ENCR), ID 12 (AES-CBC)

	// Remaining 4 bytes for minimal transform data
	header = append(header, 0x00, 0x00, 0x00, 0x00) // 4 bytes: padding/reserved

	// Append actual payload after the 52-byte header
	header = append(header, payload...)

	return header
}

// generateJunkPacket creates a junk packet with specified size constraints
func (b *Bind) generateJunkPacket() []byte {
	if b.amneziaConfig == nil {
		return nil
	}

	minSize := b.amneziaConfig.Jmin
	maxSize := b.amneziaConfig.Jmax

	// UDP cannot send true 0-byte payloads - minimum is 1 byte
	// When config specifies 0, we send minimal 1-byte packets
	if minSize == 0 && maxSize == 0 {
		return []byte{0x00} // Minimal 1-byte packet (UDP requirement)
	}

	// If Jmin is 0, treat it as 1 (UDP minimum)
	if minSize == 0 {
		minSize = 1
		if maxSize == 0 {
			maxSize = 1
		}
		// Random size from minSize to maxSize
		size := minSize
		if maxSize > minSize {
			size = minSize + rng.Intn(maxSize-minSize+1)
		}

		junk := make([]byte, size)
		_, err := rand.Read(junk)
		if err != nil {
			// Fallback to math/rand if crypto/rand fails
			for i := range junk {
				junk[i] = byte(rng.Intn(256))
			}
		}
		return junk
	}

	// Ensure minimum 1 byte for UDP
	if minSize < 1 {
		minSize = 1
	}
	if maxSize < minSize {
		maxSize = minSize
	}

	var size int
	if maxSize == minSize {
		size = minSize
	} else {
		size = minSize + rng.Intn(maxSize-minSize+1)
	}

	junk := make([]byte, size)
	_, err := rand.Read(junk)
	if err != nil {
		// Fallback to math/rand if crypto/rand fails
		for i := range junk {
			junk[i] = byte(rng.Intn(256))
		}
	}
	return junk
}

// sendJunkPackets sends a series of junk packets synchronously to control exact count
func (b *Bind) sendJunkPackets(host string, count int, interval time.Duration) {
	if count <= 0 {
		return
	}

	// Send packets synchronously to ensure exact count
	for i := 0; i < count; i++ {
		junk := b.generateJunkPacket()

		// Send immediately without goroutine to control count
		b.sendUDPPacket(host, junk)

		// Wait interval between packets (except for last one)
		if i < count-1 && interval > 0 {
			time.Sleep(interval)
		}
	}
}

// sendUDPPacket sends a UDP packet - attempts true zero-byte for empty data
func (b *Bind) sendUDPPacket(host string, data []byte) {
	if len(data) == 0 {
		// Send true zero-byte UDP packet
		b.sendTrueZeroByteUDP(host)
		return
	}

	// Normal UDP packet with data
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 400*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Write(data)
}

// sendTrueZeroByteUDP sends true zero-byte UDP packets using standard Go methods
func (b *Bind) sendTrueZeroByteUDP(host string) {
	// Use standard Go UDP methods which work reliably for zero-byte packets
	b.sendStandardZeroByte(host)
}

// sendStandardZeroByte sends zero-byte UDP packets using standard Go UDP methods
func (b *Bind) sendStandardZeroByte(host string) {
	// Method 1: Direct UDP connection with empty byte slice
	if conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 200*time.Millisecond); err == nil {
		_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		conn.Write([]byte{})
		conn.Close()
	}

	// Method 2: PacketConn interface for additional reliability
	if conn, err := net.ListenPacket("udp", ":0"); err == nil {
		defer conn.Close()
		if addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(b.port443))); err == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			conn.WriteTo([]byte{}, addr)
		}
	}
}

func (b *Bind) maybePreflight(ep conn.Endpoint, bufs [][]byte) {
	dst := ep.DstIP()
	var seenInit bool
	for _, buf := range bufs {
		if handshakeInitiation(buf) {
			seenInit = true
			break
		}
	}
	if !seenInit {
		return
	}

	now := time.Now()
	b.mu.Lock()
	last := b.lastSent[dst]
	if now.Sub(last) < b.interval {
		b.mu.Unlock()
		return
	}
	b.lastSent[dst] = now
	b.mu.Unlock()

	host := dst.String()

	// Execute Amnezia sequence BEFORE sending the actual handshake
	if b.amneziaConfig != nil {
		// Send I1 packet and critical junk packets SYNCHRONOUSLY before handshake
		b.executeMinimalPreHandshakeSequence(host)
	} else {
		// Fallback to simple preflight SYNCHRONOUSLY
		b.executeSimplePreflight(host)
	}
}

// maybePreflightUsingSameSocket sends preflight packets using the WireGuard socket (same source port)
func (b *Bind) maybePreflightUsingSameSocket(ep conn.Endpoint, bufs [][]byte) {
	dst := ep.DstIP()
	var seenInit bool
	for _, buf := range bufs {
		if handshakeInitiation(buf) {
			seenInit = true
			break
		}
	}
	if !seenInit {
		return
	}

	now := time.Now()
	b.mu.Lock()
	last := b.lastSent[dst]
	if now.Sub(last) < b.interval {
		b.mu.Unlock()
		return
	}
	b.lastSent[dst] = now
	b.mu.Unlock()

	// Execute Amnezia sequence using the SAME socket as WireGuard
	if b.amneziaConfig != nil {
		b.executeAmneziaPreflightUsingSameSocket(ep)
	}
}

// executeAmneziaPreflightUsingSameSocket sends obfuscation packets using WireGuard's socket
func (b *Bind) executeAmneziaPreflightUsingSameSocket(ep conn.Endpoint) {
	config := b.amneziaConfig
	if config == nil {
		return
	}

	// Step 1: Send I1 packet with IKEv2 framing using WireGuard socket
	if config.I1 != "" && b.payload != nil {
		framedPayload := wrapInIKEv2Header(b.payload)
		_ = b.inner.Send([][]byte{framedPayload}, ep)
		time.Sleep(2 * time.Millisecond)
	}

	// Step 2: Send junk packets using WireGuard socket (SAME source port)
	if config.JcBeforeHS > 0 {
		for i := 0; i < config.JcBeforeHS; i++ {
			junkPacket := b.generateJunkPacket()
			_ = b.inner.Send([][]byte{junkPacket}, ep)
			time.Sleep(1 * time.Millisecond)
		}
	}

	// Step 3: Send I2-I5 signature packets using WireGuard socket
	signatures := []string{"", config.I2, config.I3, config.I4, config.I5}
	for i, sig := range signatures {
		if i == 0 || sig == "" {
			continue
		}
		packet, err := parseCPSPacket(sig)
		if err == nil && len(packet) > 0 {
			_ = b.inner.Send([][]byte{packet}, ep)
			time.Sleep(1 * time.Millisecond)
		}
	}
}

// executeSimplePreflight sends a simple preflight packet (original behavior)
func (b *Bind) executeSimplePreflight(host string) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 400*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Write(b.payload)
}

// executeMinimalPreHandshakeSequence sends critical packets synchronously before handshake
// Uses a SINGLE connection (same source port) to match Amnezia's behavior
func (b *Bind) executeMinimalPreHandshakeSequence(host string) {
	config := b.amneziaConfig
	if config == nil {
		return
	}

	// Create a SINGLE UDP connection that will be reused for all packets (same source port)
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 500*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()

	// Step 1: Send I1 packet FIRST with IKEv2 framing
	if config.I1 != "" && b.payload != nil {
		framedPayload := wrapInIKEv2Header(b.payload)
		_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = conn.Write(framedPayload)
		time.Sleep(2 * time.Millisecond) // Small delay after I1
	}

	// Step 2: Send junk packets BEFORE handshake (same connection = same port)
	if config.JcBeforeHS > 0 {
		for i := 0; i < config.JcBeforeHS; i++ {
			junkPacket := b.generateJunkPacket()
			_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			_, _ = conn.Write(junkPacket)
			time.Sleep(1 * time.Millisecond)
		}
	}

	// Step 3: Send I2-I5 signature packets (same connection)
	signatures := []string{"", config.I2, config.I3, config.I4, config.I5}
	for i, sig := range signatures {
		if i == 0 || sig == "" {
			continue
		}
		packet, err := parseCPSPacket(sig)
		if err == nil && len(packet) > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			_, _ = conn.Write(packet)
			time.Sleep(1 * time.Millisecond)
		}
	}

	// Connection will close when function exits, now WireGuard handshake can proceed
}

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.maybePreflightUsingSameSocket(ep, bufs)
	
	// Send post-handshake junk packets if needed
	b.maybeSendPostHandshakeJunk(ep, bufs)

	// For Cloudflare Warp compatibility, don't apply S1/S2 prefixes
	// The obfuscation is achieved through junk packets and I1-I5 signature packets
	return b.inner.Send(bufs, ep)
}

// maybeSendPostHandshakeJunk sends remaining junk packets after handshake request
func (b *Bind) maybeSendPostHandshakeJunk(ep conn.Endpoint, bufs [][]byte) {
	if b.amneziaConfig == nil {
		return
	}
	
	config := b.amneziaConfig
	
	// Calculate remaining junk packets to send after handshake
	remainingJunk := config.Jc - config.JcBeforeHS
	if remainingJunk <= 0 {
		return
	}
	
	// Check if this is a handshake initiation (type 1)
	var seenHandshakeRequest bool
	for _, buf := range bufs {
		if len(buf) > 0 && buf[0] == 1 {
			seenHandshakeRequest = true
			break
		}
	}
	
	if !seenHandshakeRequest {
		return
	}
	
	dst := ep.DstIP()
	b.mu.Lock()
	alreadySent := b.postHandshakeSent[dst]
	if alreadySent {
		b.mu.Unlock()
		return
	}
	b.postHandshakeSent[dst] = true
	b.mu.Unlock()
	
	// Send remaining junk packets using WireGuard socket (same source port)
	// Send immediately after handshake request without delay
	go func() {
		for i := 0; i < remainingJunk; i++ {
			junkPacket := b.generateJunkPacket()
			_ = b.inner.Send([][]byte{junkPacket}, ep)
			time.Sleep(1 * time.Millisecond)
		}
	}()
}

// applyAmneziaPrefix adds S1/S2 random prefixes to WireGuard packets
// Note: Only apply prefixes to handshake packets, not data packets for Cloudflare compatibility
func (b *Bind) applyAmneziaPrefix(buf []byte) []byte {
	if b.amneziaConfig == nil || len(buf) == 0 {
		return buf
	}

	var prefixSize int

	// Only apply prefixes to handshake packets (types 1 and 2)
	// For Cloudflare Warp compatibility, don't modify data packets
	if len(buf) >= 1 {
		messageType := buf[0]
		switch messageType {
		case 1: // Init packet (handshake initiation)
			prefixSize = b.amneziaConfig.S1
		case 2: // Response packet (handshake response)
			prefixSize = b.amneziaConfig.S2
		default:
			// For data packets, don't add prefixes to maintain Cloudflare compatibility
			return buf
		}
	}

	// Cap at 64 bytes as per spec
	if prefixSize > 64 {
		prefixSize = 64
	}

	if prefixSize <= 0 {
		return buf
	}

	// Generate random prefix
	prefix := make([]byte, prefixSize)
	_, err := rand.Read(prefix)
	if err != nil {
		// Fallback to math/rand if crypto/rand fails
		for i := range prefix {
			prefix[i] = byte(rng.Intn(256))
		}
	}

	// Prepend prefix to the original packet
	result := make([]byte, len(prefix)+len(buf))
	copy(result, prefix)
	copy(result[len(prefix):], buf)

	return result
}
