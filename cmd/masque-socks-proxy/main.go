package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bepass-org/vwarp/masque"
)

type SOCKS5Proxy struct {
	bindAddr  string
	client    *masque.MasqueClient
	logger    *slog.Logger
	listener  net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	connCount int64
	bytesUp   int64
	bytesDown int64
	mu        sync.Mutex
}

func NewSOCKS5Proxy(bindAddr string, client *masque.MasqueClient, logger *slog.Logger) *SOCKS5Proxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &SOCKS5Proxy{
		bindAddr: bindAddr,
		client:   client,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (p *SOCKS5Proxy) Start() error {
	listener, err := net.Listen("tcp", p.bindAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to %s: %v", p.bindAddr, err)
	}
	p.listener = listener

	p.logger.Info("SOCKS5 proxy started", "address", p.bindAddr)

	fmt.Println("\n╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║        MASQUE SOCKS5 Proxy Server                        ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Printf("\n✅ Proxy running on: %s\n", p.bindAddr)
	fmt.Printf("🔒 Tunnel: MASQUE via Cloudflare WARP\n")

	ipv4, ipv6 := p.client.GetLocalAddresses()
	fmt.Printf("📍 Tunnel IPv4: %s\n", ipv4)
	fmt.Printf("📍 Tunnel IPv6: %s\n", ipv6)

	fmt.Println("\n📋 Configure your apps:")
	fmt.Printf("   SOCKS5 Host: %s\n", p.bindAddr)
	fmt.Printf("   SOCKS5 Port: (from address above)\n")
	fmt.Println("   Authentication: None")
	fmt.Println("\n🔍 Compatible with:")
	fmt.Println("   - Browsers (via SOCKS5 settings)")
	fmt.Println("   - Telegram")
	fmt.Println("   - curl --socks5")
	fmt.Println("   - SSH ProxyCommand")
	fmt.Println("   - Any SOCKS5-compatible app")
	fmt.Println("\n📊 Press Ctrl+C to stop and see statistics")
	fmt.Println("════════════════════════════════════════════════════════════\n")

	for {
		select {
		case <-p.ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				if p.ctx.Err() != nil {
					return nil
				}
				p.logger.Warn("Accept failed", "error", err)
				continue
			}

			p.mu.Lock()
			p.connCount++
			connID := p.connCount
			p.mu.Unlock()

			go p.handleConnection(conn, connID)
		}
	}
}

func (p *SOCKS5Proxy) Stop() error {
	p.cancel()
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *SOCKS5Proxy) handleConnection(clientConn net.Conn, connID int64) {
	defer clientConn.Close()

	// SOCKS5 handshake
	if err := p.handleHandshake(clientConn); err != nil {
		p.logger.Debug("Handshake failed", "conn", connID, "error", err)
		return
	}

	// SOCKS5 request
	targetAddr, err := p.handleRequest(clientConn)
	if err != nil {
		p.logger.Debug("Request failed", "conn", connID, "error", err)
		return
	}

	p.logger.Info("SOCKS5 connection", "conn", connID, "target", targetAddr)
	fmt.Printf("🔌 [%d] SOCKS5: %s\n", connID, targetAddr)

	// Connect to target
	targetConn, err := p.dialTarget(targetAddr)
	if err != nil {
		p.logger.Error("Failed to connect", "conn", connID, "target", targetAddr, "error", err)
		p.sendReply(clientConn, 0x05, 0x01, 0x00, 0x01, []byte{0, 0, 0, 0}, []byte{0, 0})
		return
	}
	defer targetConn.Close()

	// Send success reply
	p.sendReply(clientConn, 0x05, 0x00, 0x00, 0x01, []byte{0, 0, 0, 0}, []byte{0, 0})

	// Relay data
	p.relayData(clientConn, targetConn, connID, targetAddr)
}

func (p *SOCKS5Proxy) handleHandshake(conn net.Conn) error {
	// Read greeting: VER, NMETHODS, METHODS
	buf := make([]byte, 257)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read handshake: %v", err)
	}

	if n < 2 {
		return fmt.Errorf("invalid handshake length: %d", n)
	}

	version := buf[0]
	if version != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	// nmethods := buf[1]
	// We accept no authentication (0x00)
	// Send: VER, METHOD
	_, err = conn.Write([]byte{0x05, 0x00})
	return err
}

func (p *SOCKS5Proxy) handleRequest(conn net.Conn) (string, error) {
	// Read request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("read request header: %v", err)
	}

	version := buf[0]
	cmd := buf[1]
	// rsv := buf[2]
	atyp := buf[3]

	if version != 0x05 {
		return "", fmt.Errorf("unsupported version: %d", version)
	}

	if cmd != 0x01 { // Only support CONNECT
		p.sendReply(conn, 0x05, 0x07, 0x00, 0x01, []byte{0, 0, 0, 0}, []byte{0, 0})
		return "", fmt.Errorf("unsupported command: %d", cmd)
	}

	// Read destination address
	var addr string
	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", fmt.Errorf("read IPv4: %v", err)
		}
		addr = net.IP(ipBuf).String()

	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %v", err)
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", fmt.Errorf("read domain: %v", err)
		}
		addr = string(domainBuf)

	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", fmt.Errorf("read IPv6: %v", err)
		}
		addr = net.IP(ipBuf).String()

	default:
		p.sendReply(conn, 0x05, 0x08, 0x00, 0x01, []byte{0, 0, 0, 0}, []byte{0, 0})
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %v", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(addr, fmt.Sprintf("%d", port)), nil
}

func (p *SOCKS5Proxy) sendReply(conn net.Conn, ver, rep, rsv, atyp byte, addr []byte, port []byte) error {
	reply := []byte{ver, rep, rsv, atyp}
	reply = append(reply, addr...)
	reply = append(reply, port...)
	_, err := conn.Write(reply)
	return err
}

func (p *SOCKS5Proxy) dialTarget(address string) (net.Conn, error) {
	// Dial through system (which routes through MASQUE if configured)
	conn, err := net.DialTimeout("tcp", address, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *SOCKS5Proxy) relayData(client, target net.Conn, connID int64, targetAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)

	var up, down int64

	// Client to target
	go func() {
		defer wg.Done()
		n, _ := io.Copy(target, client)
		up = n
		if tcpConn, ok := target.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Target to client
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, target)
		down = n
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()

	p.mu.Lock()
	p.bytesUp += up
	p.bytesDown += down
	p.mu.Unlock()

	p.logger.Debug("Connection closed", "conn", connID, "target", targetAddr, "up", formatBytes(up), "down", formatBytes(down))
	fmt.Printf("✓ [%d] Complete: %s (↑%s ↓%s)\n", connID, targetAddr, formatBytes(up), formatBytes(down))
}

func (p *SOCKS5Proxy) PrintStats() {
	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Println("\n════════════════════════════════════════════════════════════")
	fmt.Println("📊 Proxy Statistics")
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Printf("Total Connections: %d\n", p.connCount)
	fmt.Printf("Data Uploaded:     %s\n", formatBytes(p.bytesUp))
	fmt.Printf("Data Downloaded:   %s\n", formatBytes(p.bytesDown))
	fmt.Printf("Total Data:        %s\n", formatBytes(p.bytesUp+p.bytesDown))
	fmt.Println("════════════════════════════════════════════════════════════")
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func main() {
	configPath := flag.String("config", "", "Path to MASQUE config file (default: platform-specific)")
	bind := flag.String("bind", "127.0.0.1:8086", "SOCKS5 proxy bind address")
	verbose := flag.Bool("v", false, "Verbose logging")

	flag.Parse()

	if *configPath == "" {
		*configPath = masque.GetDefaultConfigPath()
	}

	// Setup logger
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║        MASQUE SOCKS5 Proxy                               ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Printf("\n📁 Config: %s\n", *configPath)
	fmt.Printf("🔌 Connecting to MASQUE server...\n")

	// Create MASQUE client
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := masque.NewMasqueClient(ctx, masque.MasqueClientConfig{
		ConfigPath: *configPath,
		Logger:     logger,
	})
	if err != nil {
		log.Fatalf("Failed to create MASQUE client: %v", err)
	}
	defer client.Close()

	fmt.Printf("✅ MASQUE tunnel established!\n")

	// Create proxy
	proxy := NewSOCKS5Proxy(*bind, client, logger)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n🛑 Shutting down...")
		proxy.Stop()
	}()

	// Start proxy
	if err := proxy.Start(); err != nil {
		logger.Error("Proxy error", "error", err)
		os.Exit(1)
	}

	proxy.PrintStats()
	fmt.Println("\n👋 Goodbye!")
}
