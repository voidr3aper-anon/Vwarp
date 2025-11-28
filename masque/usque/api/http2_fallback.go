package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"

	"github.com/bepass-org/vwarp/masque/usque/internal"
)

// CreateMasqueClientWithFallback tries HTTP/3 (QUIC) with multiple retry attempts and longer timeouts
func CreateMasqueClientWithFallback(ctx context.Context, privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, endpoint string, sni string, enableNoize bool, noizeConfig interface{}) (interface{}, *connectip.Conn, error) {
	// Parse endpoint
	fmt.Printf("[DEBUG] Parsing endpoint: %s\n", endpoint)
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		// If no port specified, add default
		host = endpoint
		port = "443"
		fmt.Printf("[DEBUG] No port specified, using default: %s:%s\n", host, port)
	} else {
		fmt.Printf("[DEBUG] Parsed endpoint - host: %s, port: %s\n", host, port)
	}

	// Check if host is an IP or domain
	ip := net.ParseIP(host)
	isIPAddress := ip != nil

	// Convert to UDP address (for QUIC)
	var udpAddr *net.UDPAddr
	if isIPAddress {
		portNum := 443
		if p, err := net.LookupPort("tcp", port); err == nil {
			portNum = p
		}

		udpAddr = &net.UDPAddr{
			IP:   ip,
			Port: portNum,
		}
	} else {
		// For domains, resolve to IP for QUIC
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("failed to resolve domain %s: %w", host, err)
		}

		portNum := 443
		if p, err := net.LookupPort("tcp", port); err == nil {
			portNum = p
		}

		udpAddr = &net.UDPAddr{
			IP:   ips[0],
			Port: portNum,
		}

		fmt.Printf("[INFO] Resolved %s to %s\n", host, ips[0].String())
	}

	// Try HTTP/3 (QUIC) with retries
	fmt.Println("[INFO] Attempting MASQUE connection via HTTP/3 (QUIC)...")
	fmt.Printf("[DEBUG] Resolved endpoint: %s (IP: %s)\n", endpoint, udpAddr.IP.String())

	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("[INFO] Connection attempt %d/%d...\n", attempt, maxRetries)
		fmt.Printf("[DEBUG] Attempt %d: Connecting to %s\n", attempt, udpAddr.String())

		// Create a longer timeout context for each attempt
		attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

		udpConn, ipConn, err := CreateMasqueClient(attemptCtx, privKey, peerPubKey, udpAddr, sni, enableNoize, noizeConfig)
		cancel()

		if err == nil {
			fmt.Println("[SUCCESS] Connected via HTTP/3 (QUIC)")
			return udpConn, ipConn, nil
		}

		fmt.Printf("[WARN] Attempt %d failed: %v\n", attempt, err)

		// Retry on all errors for QUIC (likely GFW blocking)
		if attempt < maxRetries {
			fmt.Printf("[INFO] Retrying in 2 seconds...\n")
			time.Sleep(2 * time.Second)
		}
	}

	// If all QUIC attempts failed, try HTTP/2 over TCP as fallback
	fmt.Println("[WARN] All HTTP/3 (QUIC) attempts failed")
	fmt.Println("[INFO] Attempting HTTP/2 (TCP) fallback for GFW/firewall bypass...")

	// Try domain-based connection for better GFW bypass
	var tcpEndpoint string
	if isIPAddress {
		tcpEndpoint = net.JoinHostPort(host, port)
	} else {
		// Keep domain for SNI-based routing
		tcpEndpoint = net.JoinHostPort(host, port)
	}

	// Try multiple alternative endpoints for GFW bypass
	alternativeEndpoints := []string{
		tcpEndpoint,
	}

	// If using IP, also try via alternative Cloudflare endpoints
	if isIPAddress && port == "443" {
		alternativeEndpoints = append(alternativeEndpoints,
			"engage.cloudflareclient.com:443",
			"162.159.198.1:443",
		)
	}

	var lastErr error
	for i, ep := range alternativeEndpoints {
		if i > 0 {
			fmt.Printf("[INFO] Trying alternative endpoint: %s\n", ep)
		}

		tcpConn, ipConn, err := CreateMasqueClientHTTP2(ctx, privKey, peerPubKey, ep, sni)
		if err == nil {
			fmt.Println("[SUCCESS] Connected via HTTP/2 (TCP) - GFW bypass successful!")
			return tcpConn, ipConn, nil
		}

		fmt.Printf("[WARN] HTTP/2 attempt via %s failed: %v\n", ep, err)
		lastErr = err
	}

	return nil, nil, fmt.Errorf("all connection attempts failed. Last error: %w", lastErr)
}

// CreateMasqueClientHTTP2 creates a MASQUE client over HTTP/2 (TCP)
func CreateMasqueClientHTTP2(ctx context.Context, privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, endpoint string, sni string) (*net.Conn, *connectip.Conn, error) {
	// Generate self-signed certificate
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert: %w", err)
	}

	// Prepare TLS config
	tlsConfig, err := PrepareTlsConfig(privKey, peerPubKey, cert, sni)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare TLS config: %w", err)
	}

	// For HTTP/2, we need h2 in NextProtos
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	// Create TCP dialer with timeout
	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
	}

	// Dial TCP
	tcpConn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	fmt.Printf("[DEBUG] TCP connection established to %s\n", endpoint)

	// Upgrade to TLS
	tlsConn := tls.Client(tcpConn, tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	negotiatedProto := tlsConn.ConnectionState().NegotiatedProtocol
	fmt.Printf("[DEBUG] TLS handshake complete. Negotiated protocol: %s\n", negotiatedProto)

	// MASQUE/Connect-IP requires HTTP/3 with datagram support
	// HTTP/2 doesn't support datagrams, so we cannot establish a functional MASQUE tunnel
	// Close the connection and return an error
	tlsConn.Close()

	fmt.Println("[WARN] HTTP/2 connection established but connect-ip requires HTTP/3 datagrams")
	fmt.Println("[INFO] Cloudflare MASQUE requires HTTP/3. If GFW is blocking QUIC/UDP:")
	fmt.Println("      - Try different Cloudflare IPs (scanner mode)")
	fmt.Println("      - Use a proxy/VPN to bypass GFW first")
	fmt.Println("      - Use Cloudflare WARP with obfuscation (WireGuard mode)")

	return nil, nil, fmt.Errorf("MASQUE requires HTTP/3 with datagram support. HTTP/2 fallback not possible for this protocol")
}
