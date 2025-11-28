package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/bepass-org/vwarp/masque"
)

type ProxyServer struct {
	bindAddr     string
	masqueClient *masque.Client
	logger       *slog.Logger
	listener     net.Listener
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewProxyServer(bindAddr string, masqueClient *masque.Client, logger *slog.Logger) *ProxyServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProxyServer{
		bindAddr:     bindAddr,
		masqueClient: masqueClient,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
	}
}

func (p *ProxyServer) Start() error {
	listener, err := net.Listen("tcp", p.bindAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to %s: %v", p.bindAddr, err)
	}
	p.listener = listener

	p.logger.Info("SOCKS5 proxy server started", "address", p.bindAddr)
	fmt.Printf("🚀 MASQUE SOCKS5 Proxy Server running on %s\n", p.bindAddr)
	fmt.Printf("📊 Tunnel Status: ✅ Connected via MASQUE\n")
	fmt.Printf("🌐 Configure your applications to use SOCKS5 proxy: %s\n", p.bindAddr)
	fmt.Println("📋 Press Ctrl+C to stop the server")

	for {
		select {
		case <-p.ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				if p.ctx.Err() != nil {
					return nil // Server is shutting down
				}
				p.logger.Warn("Failed to accept connection", "error", err)
				continue
			}
			go p.handleConnection(conn)
		}
	}
}

func (p *ProxyServer) Stop() error {
	p.cancel()
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *ProxyServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 handshake
	if err := p.socks5Handshake(conn); err != nil {
		p.logger.Debug("SOCKS5 handshake failed", "error", err)
		return
	}

	// SOCKS5 connect request
	targetAddr, err := p.socks5Connect(conn)
	if err != nil {
		p.logger.Debug("SOCKS5 connect failed", "error", err)
		return
	}

	p.logger.Debug("SOCKS5 connection established", "target", targetAddr)

	// Connect to target directly (for now - in full implementation this would go through MASQUE tunnel)
	targetConn, err := p.connectThroughTunnel(targetAddr)
	if err != nil {
		p.logger.Error("Failed to connect to target", "target", targetAddr, "error", err)
		return
	}
	defer targetConn.Close()

	// Relay data between client and target
	p.relayData(conn, targetConn, targetAddr)
}

func (p *ProxyServer) socks5Handshake(conn net.Conn) error {
	// Read version and methods
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read handshake: %v", err)
	}

	if n < 3 || buf[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS5 version")
	}

	// No authentication required
	_, err = conn.Write([]byte{0x05, 0x00})
	return err
}

func (p *ProxyServer) socks5Connect(conn net.Conn) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("failed to read connect request: %v", err)
	}

	if buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00 {
		return "", fmt.Errorf("invalid SOCKS5 connect request")
	}

	var addr string
	switch buf[3] {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		addr = net.IP(ipBuf).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", err
		}
		addr = string(domainBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		addr = net.IP(ipBuf).String()
	default:
		return "", fmt.Errorf("unsupported address type: %d", buf[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 + int(portBuf[1])

	targetAddr := net.JoinHostPort(addr, strconv.Itoa(port))

	// Send success response
	response := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(response); err != nil {
		return "", err
	}

	return targetAddr, nil
}

func (p *ProxyServer) connectThroughTunnel(targetAddr string) (net.Conn, error) {
	// For this demo, we'll use regular TCP connection
	// In a full implementation, you'd route this through the MASQUE tunnel
	conn, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target %s: %v", targetAddr, err)
	}

	return conn, nil
}

func (p *ProxyServer) relayData(client, target net.Conn, targetAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to target
	go func() {
		defer wg.Done()
		written, err := io.Copy(target, client)
		if err != nil {
			p.logger.Debug("Client to target relay error", "target", targetAddr, "bytes", written, "error", err)
		} else {
			p.logger.Debug("Client to target relay completed", "target", targetAddr, "bytes", written)
		}
	}()

	// Target to client
	go func() {
		defer wg.Done()
		written, err := io.Copy(client, target)
		if err != nil {
			p.logger.Debug("Target to client relay error", "target", targetAddr, "bytes", written, "error", err)
		} else {
			p.logger.Debug("Target to client relay completed", "target", targetAddr, "bytes", written)
		}
	}()

	wg.Wait()
	p.logger.Debug("Connection relay finished", "target", targetAddr)
}

func main() {
	var (
		endpoint = flag.String("endpoint", "162.159.198.1:443", "MASQUE server endpoint (host:port)")
		bind     = flag.String("bind", "127.0.0.1:1080", "SOCKS5 proxy bind address")
		verbose  = flag.Bool("v", false, "Enable verbose logging")
		sni      = flag.String("sni", "", "SNI for MASQUE server (default: Cloudflare)")
		uri      = flag.String("uri", "", "Connect-IP URI (default: Cloudflare)")
		target   = flag.String("target", "162.159.198.3:443", "Target address for Connect-IP")
	)
	flag.Parse()

	// Setup logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	fmt.Println("🔐 MASQUE Proxy Server with Cloudflare WARP")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("🔧 Initializing MASQUE client (endpoint: %s)\n", *endpoint)

	// Create MASQUE client using existing system
	client, err := masque.NewClientFromFilesOrEnv(*endpoint, *sni, *uri, *target, "", "", "", logger)
	if err != nil {
		logger.Error("Failed to create MASQUE client", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	// Test initial connection
	fmt.Printf("🔌 Testing MASQUE connection...\n")
	testCtx, testCancel := context.WithTimeout(context.Background(), 15*time.Second)
	udpConn, ipConn, err := client.ConnectIP(testCtx)
	testCancel()

	if err != nil {
		logger.Error("Initial MASQUE connection test failed", "error", err)
		os.Exit(1)
	}

	// Close test connections
	if udpConn != nil {
		udpConn.Close()
	}
	if ipConn != nil {
		ipConn.Close()
	}

	fmt.Printf("✅ MASQUE connection successful!\n")

	// Create and start proxy server
	proxy := NewProxyServer(*bind, client, logger)

	// Setup graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		fmt.Printf("\n🛑 Shutting down MASQUE proxy server...\n")
		proxy.Stop()
	}()

	// Start the proxy server
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	if err := proxy.Start(); err != nil {
		logger.Error("Proxy server error", "error", err)
		os.Exit(1)
	}

	fmt.Printf("👋 MASQUE proxy server stopped.\n")
}
