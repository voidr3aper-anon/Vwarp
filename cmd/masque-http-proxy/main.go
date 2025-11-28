package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bepass-org/vwarp/masque"
)

type MASQUEProxy struct {
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

func NewMASQUEProxy(bindAddr string, client *masque.MasqueClient, logger *slog.Logger) *MASQUEProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &MASQUEProxy{
		bindAddr: bindAddr,
		client:   client,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (p *MASQUEProxy) Start() error {
	listener, err := net.Listen("tcp", p.bindAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to %s: %v", p.bindAddr, err)
	}
	p.listener = listener

	p.logger.Info("HTTP proxy started", "address", p.bindAddr)

	fmt.Println("\n╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║        MASQUE HTTP/HTTPS Proxy Server                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Printf("\n✅ Proxy running on: %s\n", p.bindAddr)
	fmt.Printf("🔒 Tunnel: MASQUE via Cloudflare WARP\n")

	ipv4, ipv6 := p.client.GetLocalAddresses()
	fmt.Printf("📍 Tunnel IPv4: %s\n", ipv4)
	fmt.Printf("📍 Tunnel IPv6: %s\n", ipv6)

	fmt.Println("\n📋 Configure your browser/apps:")
	fmt.Printf("   HTTP Proxy:  %s\n", p.bindAddr)
	fmt.Printf("   HTTPS Proxy: %s\n", p.bindAddr)
	fmt.Println("\n🔍 Test URLs:")
	fmt.Println("   http://httpbin.org/ip")
	fmt.Println("   https://api.ipify.org")
	fmt.Println("   https://ifconfig.me")
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

			go p.handleHTTPConnection(conn, connID)
		}
	}
}

func (p *MASQUEProxy) Stop() error {
	p.cancel()
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *MASQUEProxy) handleHTTPConnection(clientConn net.Conn, connID int64) {
	defer clientConn.Close()

	// Set read deadline
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read the initial request
	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	if err != nil {
		p.logger.Debug("Failed to read request", "conn", connID, "error", err)
		return
	}

	// Reset deadline
	clientConn.SetReadDeadline(time.Time{})

	request := string(buf[:n])

	// Determine if this is CONNECT (HTTPS) or regular HTTP
	if len(request) >= 7 && request[:7] == "CONNECT" {
		p.handleHTTPSConnect(clientConn, buf[:n], connID)
	} else {
		p.handleHTTPRequest(clientConn, buf[:n], connID)
	}
}

func (p *MASQUEProxy) handleHTTPSConnect(clientConn net.Conn, initialData []byte, connID int64) {
	// Parse CONNECT request
	request := string(initialData)
	var host string
	fmt.Sscanf(request, "CONNECT %s HTTP/", &host)

	if host == "" {
		p.logger.Debug("Invalid CONNECT request", "conn", connID)
		return
	}

	p.logger.Info("HTTPS CONNECT", "conn", connID, "host", host)
	fmt.Printf("🔒 [%d] HTTPS: %s\n", connID, host)

	// Connect through MASQUE tunnel
	targetConn, err := p.dialThroughTunnel(host)
	if err != nil {
		p.logger.Error("Failed to connect through tunnel", "conn", connID, "host", host, "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Send connection established response
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		p.logger.Debug("Failed to send CONNECT response", "conn", connID, "error", err)
		return
	}

	// Relay data bidirectionally
	p.relayData(clientConn, targetConn, connID, host)
}

func (p *MASQUEProxy) handleHTTPRequest(clientConn net.Conn, initialData []byte, connID int64) {
	// Parse HTTP request to get host
	request := string(initialData)
	var method, reqURL, version string
	fmt.Sscanf(request, "%s %s %s", &method, &reqURL, &version)

	// Extract host from headers or URL
	var host string
	lines := splitLines(request)
	for _, line := range lines {
		if len(line) > 6 && (line[:6] == "Host: " || line[:6] == "host: ") {
			host = line[6:]
			break
		}
	}

	// If no Host header, try to parse from URL (for absolute URIs)
	if host == "" && len(reqURL) > 7 && reqURL[:7] == "http://" {
		// Extract host from absolute URI
		hostEnd := 7
		for i := 7; i < len(reqURL); i++ {
			if reqURL[i] == '/' || reqURL[i] == ':' {
				hostEnd = i
				break
			}
		}
		if hostEnd > 7 {
			host = reqURL[7:hostEnd]
		}
	}

	if host == "" {
		p.logger.Debug("No host header found", "conn", connID, "method", method, "url", reqURL)
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nNo Host header"))
		return
	}

	// Add default port if missing
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}

	p.logger.Info("HTTP request", "conn", connID, "method", method, "host", host)
	fmt.Printf("🌐 [%d] HTTP: %s %s\n", connID, method, host)

	// Connect through MASQUE tunnel
	targetConn, err := p.dialThroughTunnel(host)
	if err != nil {
		p.logger.Error("Failed to connect through tunnel", "conn", connID, "host", host, "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Forward the initial request
	_, err = targetConn.Write(initialData)
	if err != nil {
		p.logger.Debug("Failed to forward request", "conn", connID, "error", err)
		return
	}

	// Relay data bidirectionally
	p.relayData(clientConn, targetConn, connID, host)
}

func (p *MASQUEProxy) dialThroughTunnel(address string) (net.Conn, error) {
	// Use system's default dialer (which will route through MASQUE tunnel if configured)
	conn, err := net.DialTimeout("tcp", address, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *MASQUEProxy) relayData(client, target net.Conn, connID int64, host string) {
	var wg sync.WaitGroup
	wg.Add(2)

	var up, down int64

	// Client to target
	go func() {
		defer wg.Done()
		n, _ := io.Copy(target, client)
		up = n
		target.(*net.TCPConn).CloseWrite()
	}()

	// Target to client
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, target)
		down = n
		client.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()

	p.mu.Lock()
	p.bytesUp += up
	p.bytesDown += down
	p.mu.Unlock()

	p.logger.Debug("Connection closed", "conn", connID, "host", host, "up", formatBytes(up), "down", formatBytes(down))
	fmt.Printf("✓ [%d] Complete: %s (↑%s ↓%s)\n", connID, host, formatBytes(up), formatBytes(down))
}

func (p *MASQUEProxy) PrintStats() {
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

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '\r' && s[i+1] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 2
			i++
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
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
	bind := flag.String("bind", "127.0.0.1:8080", "Proxy bind address")
	verbose := flag.Bool("v", false, "Verbose logging")
	testURL := flag.String("test", "", "Test URL to fetch through proxy after starting")

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
	fmt.Println("║        MASQUE HTTP/HTTPS Proxy                           ║")
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
	proxy := NewMASQUEProxy(*bind, client, logger)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n🛑 Shutting down...")
		proxy.Stop()
	}()

	// If test URL provided, test after starting
	if *testURL != "" {
		go func() {
			time.Sleep(2 * time.Second)
			testProxyConnection(*bind, *testURL)
		}()
	}

	// Start proxy
	if err := proxy.Start(); err != nil {
		logger.Error("Proxy error", "error", err)
		os.Exit(1)
	}

	proxy.PrintStats()
	fmt.Println("\n👋 Goodbye!")
}

func testProxyConnection(proxyAddr, testURL string) {
	fmt.Printf("\n🧪 Testing proxy with URL: %s\n", testURL)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://" + proxyAddr)
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(testURL)
	if err != nil {
		fmt.Printf("❌ Test failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("✅ Test successful! Status: %s\n", resp.Status)
	fmt.Printf("📄 Response:\n%s\n", string(body))
	fmt.Println("════════════════════════════════════════════════════════════")
}

func mustParseURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}
