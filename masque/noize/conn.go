package noize

import (
	"net"
	"sync"
	"time"
)

// NoizeUDPConn wraps a UDP connection with obfuscation
type NoizeUDPConn struct {
	*net.UDPConn
	noize   *Noize
	mu      sync.RWMutex
	enabled bool
	addrMap map[string]*net.UDPAddr
}

// WrapUDPConn wraps a UDP connection with noize obfuscation
func WrapUDPConn(conn *net.UDPConn, config *NoizeConfig) *NoizeUDPConn {
	noize := New(config)
	wrapped := &NoizeUDPConn{
		UDPConn: conn,
		noize:   noize,
		enabled: true,
		addrMap: make(map[string]*net.UDPAddr),
	}
	noize.WrapConn(conn)
	return wrapped
}

// WriteToUDP writes obfuscated data to UDP
func (c *NoizeUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if !c.enabled || c.noize == nil {
		return c.UDPConn.WriteToUDP(b, addr)
	}

	// Obfuscate the packet
	obfuscated, err := c.noize.ObfuscateWrite(b, addr)
	if err != nil {
		return 0, err
	}

	// Write obfuscated packet
	return c.UDPConn.WriteToUDP(obfuscated, addr)
}

// WriteTo implements the WriterTo interface (used by QUIC)
func (c *NoizeUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return c.UDPConn.WriteTo(b, addr)
	}
	return c.WriteToUDP(b, udpAddr)
}

// ReadFrom implements the ReaderFrom interface (used by QUIC)
func (c *NoizeUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// For now, don't obfuscate reads (only writes need obfuscation)
	return c.UDPConn.ReadFrom(b)
}

// ReadFromUDP reads from UDP (no de-obfuscation needed)
func (c *NoizeUDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	return c.UDPConn.ReadFromUDP(b)
}

// Write writes obfuscated data (requires prior Connect or stored addr)
func (c *NoizeUDPConn) Write(b []byte) (int, error) {
	if !c.enabled || c.noize == nil {
		return c.UDPConn.Write(b)
	}

	// Get remote address - try stored address first for better WiFi compatibility
	var remoteAddr net.Addr
	c.mu.RLock()
	if len(c.addrMap) > 0 {
		for _, addr := range c.addrMap {
			remoteAddr = addr
			break
		}
	}
	c.mu.RUnlock()

	// Fallback to connection's remote address
	if remoteAddr == nil {
		remoteAddr = c.UDPConn.RemoteAddr()
	}

	if remoteAddr == nil {
		return c.UDPConn.Write(b)
	}

	udpAddr, ok := remoteAddr.(*net.UDPAddr)
	if !ok {
		return c.UDPConn.Write(b)
	}

	return c.WriteToUDP(b, udpAddr)
}

// Enable enables obfuscation
func (c *NoizeUDPConn) Enable() {
	c.mu.Lock()
	c.enabled = true
	c.mu.Unlock()
}

// Disable disables obfuscation
func (c *NoizeUDPConn) Disable() {
	c.mu.Lock()
	c.enabled = false
	c.mu.Unlock()
}

// SetConfig updates the noize configuration
func (c *NoizeUDPConn) SetConfig(config *NoizeConfig) {
	c.mu.Lock()
	c.noize = New(config)
	c.noize.WrapConn(c.UDPConn)
	c.mu.Unlock()
}

// StoreAddr stores an address for later use
func (c *NoizeUDPConn) StoreAddr(key string, addr *net.UDPAddr) {
	c.mu.Lock()
	c.addrMap[key] = addr
	c.mu.Unlock()
}

// GetConfig returns current configuration
func (c *NoizeUDPConn) GetConfig() *NoizeConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.noize.config
}

// PresetConfigs provides preset obfuscation configurations

// LightObfuscationConfig - minimal obfuscation with junk packets to bypass DPI
func LightObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "",    // No signature packet
		FragmentInitial:  false, // Don't fragment
		PaddingMin:       0,     // Minimal padding
		PaddingMax:       0,     // Light padding
		RandomPadding:    true,
		Jc:               6, // 6 junk packets total (reduced from 12)
		JcBeforeHS:       3, // 3 before handshake
		JcAfterI1:        0,
		JcDuringHS:       0,
		JcAfterHS:        3, // 3 after handshake
		Jmin:             40,
		Jmax:             60,
		JunkInterval:     2 * time.Millisecond, // Minimal delay
		JunkRandom:       true,
		HandshakeDelay:   5 * time.Millisecond, // Minimal delay
		MimicProtocol:    "",
		RandomDelay:      false,
		DelayMin:         0,
		DelayMax:         0,
		SNIFragmentation: false,
		UseTimestamp:     false,
		UseNonce:         false,
		RandomizeInitial: false,
		AllowZeroSize:    false,
	}
}

// MediumObfuscationConfig - balanced obfuscation
func MediumObfuscationConfig() *NoizeConfig {
	return DefaultConfig()
}

// HeavyObfuscationConfig - maximum obfuscation, higher overhead
func HeavyObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "<b 0d0a0d0a><t><r 32>",
		I2:               "<b 474554202f20485454502f312e31><r 16>",
		I3:               "<r 64>",
		FragmentSize:     256,
		FragmentInitial:  true,
		FragmentDelay:    3 * time.Millisecond,
		PaddingMin:       32,
		PaddingMax:       128,
		RandomPadding:    true,
		Jc:               10,
		Jmin:             128,
		Jmax:             512,
		JcBeforeHS:       3,
		JcAfterI1:        2,
		JcDuringHS:       2,
		JcAfterHS:        3,
		JunkInterval:     8 * time.Millisecond,
		JunkRandom:       true,
		MimicProtocol:    "dtls",
		HandshakeDelay:   20 * time.Millisecond,
		RandomDelay:      true,
		DelayMin:         2 * time.Millisecond,
		DelayMax:         15 * time.Millisecond,
		SNIFragmentation: true,
		SNIFragment:      16,
		UseTimestamp:     true,
		UseNonce:         true,
		RandomizeInitial: true,
	}
}

// StealthObfuscationConfig - looks like regular HTTPS traffic
func StealthObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "<b 160301><r 2><b 0100>", // TLS ClientHello start
		MimicProtocol:    "https",
		PaddingMin:       16,
		PaddingMax:       48,
		RandomPadding:    true,
		Jc:               3,
		Jmin:             40,
		Jmax:             200,
		JcBeforeHS:       1,
		JcAfterI1:        1,
		JcAfterHS:        1,
		JunkInterval:     10 * time.Millisecond,
		HandshakeDelay:   15 * time.Millisecond,
		RandomDelay:      true,
		DelayMin:         5 * time.Millisecond,
		DelayMax:         25 * time.Millisecond,
		UseTimestamp:     false, // Don't use obvious timestamps
		RandomizeInitial: true,
	}
}

// GFWBypassConfig - specifically designed to bypass Great Firewall
func GFWBypassConfig() *NoizeConfig {
	return &NoizeConfig{
		// Mimic HTTP/3 QUIC with realistic patterns
		I1: "<b 0d0a0d0a><t><r 24>",
		I2: "<r 48>",

		// Heavy fragmentation to break DPI patterns
		FragmentSize:    128,
		FragmentInitial: true,
		FragmentDelay:   1 * time.Millisecond,

		// Significant padding to mask packet sizes
		PaddingMin:    48,
		PaddingMax:    192,
		RandomPadding: true,

		// Many junk packets to confuse statistical analysis
		Jc:   8,
		Jmin: 64,
		Jmax: 384,

		JcBeforeHS:   3,
		JcAfterI1:    2,
		JcDuringHS:   2,
		JcAfterHS:    1,
		JunkInterval: 3 * time.Millisecond,
		JunkRandom:   true,

		// Mimic legitimate DTLS/QUIC traffic
		MimicProtocol: "dtls",

		// Timing randomization to avoid pattern detection
		HandshakeDelay: 25 * time.Millisecond,
		RandomDelay:    true,
		DelayMin:       1 * time.Millisecond,
		DelayMax:       20 * time.Millisecond,

		// SNI fragmentation to bypass SNI-based blocking
		SNIFragmentation: true,
		SNIFragment:      8,

		// Advanced fingerprinting mitigation
		UseTimestamp:     true,
		UseNonce:         true,
		RandomizeInitial: true,
		DuplicatePackets: false, // Avoid triggering DPI
		FakeLoss:         0.02,  // 2% fake loss to appear natural
	}
}

// NoObfuscationConfig - disable all obfuscation
func NoObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		Jc:              0,
		FragmentInitial: false,
		PaddingMin:      0,
		PaddingMax:      0,
		HandshakeDelay:  0,
	}
}

// MinimalObfuscationConfig - very light obfuscation, least likely to break handshake
func MinimalObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		// Just add simple padding, no fragmentation or junk packets
		PaddingMin:      0,
		PaddingMax:      0,
		RandomPadding:   true,
		Jc:              10,   // No junk packets
		FragmentInitial: true, // Don't fragment
		HandshakeDelay:  5,    // No delay
	}
}

// WiFiOptimizedConfig - specifically optimized for WiFi network conditions
// Uses light obfuscation with minimal junk packets for WiFi compatibility
func WiFiOptimizedConfig() *NoizeConfig {
	return LightObfuscationConfig()
}
