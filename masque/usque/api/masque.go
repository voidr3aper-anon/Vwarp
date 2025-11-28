package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/bepass-org/vwarp/masque/usque/internal"
)

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI.
// It also verifies the peer's public key against the provided public key.
func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// we pin to the endpoint public key
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
				// we only support ECDSA
				return x509.ErrUnsupportedAlgorithm
			}

			if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
				// reason is incorrect, but the best I could figure
				// detail explains the actual reason

				//10 is NoValidChains, but we support go1.22 where it's not defined
				return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
			}

			return nil
		},
	}

	return tlsConfig, nil
}

// ConnectTunnel establishes a QUIC connection and sets up a Connect-IP tunnel
func ConnectTunnel(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, connectUri string, endpoint *net.UDPAddr) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	var udpConn *net.UDPConn
	var err error

	// Try to bind to the VPN interface first
	vpnAddr := net.ParseIP("172.18.0.1") // singbox_tun interface

	if endpoint.IP.To4() == nil {
		// IPv6 endpoint
		fmt.Printf("[DEBUG] Creating UDP socket for IPv6 endpoint\n")
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv6zero,
			Port: 0,
		})
	} else {
		// IPv4 endpoint - try VPN interface first
		fmt.Printf("[DEBUG] Attempting to bind to VPN interface (172.18.0.1)\n")
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   vpnAddr,
			Port: 0,
		})

		if err != nil {
			fmt.Printf("[DEBUG] VPN binding failed: %v, trying default interface\n", err)
			udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			})
		} else {
			fmt.Printf("[DEBUG] Successfully bound to VPN interface\n")
		}
	}

	if err != nil {
		return udpConn, nil, nil, nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	// Debug: Log UDP socket details
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	fmt.Printf("[DEBUG] Created UDP socket: %s -> %s\n", localAddr.String(), endpoint.String())

	// Create a context with timeout if one isn't set
	dialCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, 10*time.Second) // Reduced timeout for testing
		fmt.Printf("[DEBUG] Created dial context with 10s timeout\n")
		defer cancel()
	} else {
		if deadline, ok := ctx.Deadline(); ok {
			fmt.Printf("[DEBUG] Using existing context deadline: %v\n", deadline)
			// Override with shorter timeout for testing
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			fmt.Printf("[DEBUG] Overriding with 10s timeout for testing\n")
			defer cancel()
		}
	}

	fmt.Printf("[DEBUG] Starting QUIC dial to %s (SNI: %s)...\n", endpoint.String(), tlsConfig.ServerName)

	// Test basic UDP connectivity first
	fmt.Printf("[DEBUG] Testing UDP connectivity to %s...\n", endpoint.String())
	testData := []byte("test")
	_, udpErr := udpConn.WriteToUDP(testData, endpoint)
	if udpErr != nil {
		fmt.Printf("[DEBUG] UDP write test failed: %v\n", udpErr)
	} else {
		fmt.Printf("[DEBUG] UDP write test successful\n")
	}

	fmt.Printf("[DEBUG] Initiating QUIC dial (timeout context: %v)\n", dialCtx)
	conn, err := quic.Dial(
		dialCtx,
		udpConn,
		endpoint,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		fmt.Printf("[DEBUG] QUIC dial failed: %v\n", err)
		fmt.Printf("[DEBUG] Error type: %T\n", err)
		if dialCtx.Err() == context.DeadlineExceeded {
			fmt.Printf("[DEBUG] Context deadline exceeded - connection timed out\n")
		} else if dialCtx.Err() == context.Canceled {
			fmt.Printf("[DEBUG] Context was canceled\n")
		}
		udpConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
	}

	fmt.Printf("[DEBUG] QUIC handshake completed successfully!\n")
	fmt.Printf("[DEBUG] QUIC connection established to %s\n", conn.RemoteAddr())
	fmt.Printf("[DEBUG] Local UDP address: %s\n", udpConn.LocalAddr())
	fmt.Printf("[DEBUG] QUIC version: %s\n", conn.ConnectionState().Version)

	fmt.Printf("[DEBUG] Creating HTTP/3 transport with datagrams enabled\n")
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			0x276: 1,
		},
		DisableCompression: true,
	}

	fmt.Printf("[DEBUG] Creating HTTP/3 client connection\n")
	hconn := tr.NewClientConn(conn)

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	fmt.Printf("[DEBUG] Creating Connect-IP template from URI: %s\n", connectUri)
	template := uritemplate.MustNew(connectUri)
	fmt.Printf("[DEBUG] Initiating Connect-IP dial\n")
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		fmt.Printf("[DEBUG] Connect-IP dial failed: %v\n", err)
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			fmt.Printf("[DEBUG] TLS access denied - authentication issue\n")
			return udpConn, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return udpConn, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %w", err)
	}

	fmt.Printf("[DEBUG] Connect-IP dial successful, response status: %d\n", rsp.StatusCode)

	return udpConn, tr, ipConn, rsp, nil
}

// CreateMasqueClient creates a MASQUE client with proper TLS configuration
func CreateMasqueClient(ctx context.Context, privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, endpoint *net.UDPAddr, sni string, enableNoize bool, noizeConfig interface{}) (*net.UDPConn, *connectip.Conn, error) {
	// Generate self-signed certificate
	fmt.Printf("[DEBUG] Generating self-signed certificate for MASQUE connection\n")
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert: %w", err)
	}
	fmt.Printf("[DEBUG] Certificate generated successfully\n")

	// Prepare TLS config
	fmt.Printf("[DEBUG] Preparing TLS config (SNI: %s)\n", sni)
	tlsConfig, err := PrepareTlsConfig(privKey, peerPubKey, cert, sni)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare TLS config: %w", err)
	}
	fmt.Printf("[DEBUG] TLS config prepared successfully\n")

	// Use default QUIC config (1242 initial packet size, 30s keepalive)
	fmt.Printf("[DEBUG] Creating QUIC config (keepalive: 30s, initial packet size: 1242)\n")
	quicConfig := internal.DefaultQuicConfig(30*time.Second, 1242)

	// Use the same ConnectURI as working usque implementation
	// The connect-ip library handles the actual URI expansion
	connectURI := "https://cloudflareaccess.com"
	fmt.Printf("[DEBUG] Using Connect-IP URI: %s\n", connectURI)

	// Connect to the tunnel (with or without noize)
	var udpConn *net.UDPConn
	var ipConn *connectip.Conn
	var rsp *http.Response

	if enableNoize && noizeConfig != nil {
		// Use noize-wrapped connection from noize_integration.go
		fmt.Println("[NOIZE] Enabling packet obfuscation...")
		fmt.Printf("[DEBUG] Using noize-wrapped connection to %s\n", endpoint.String())
		udpConn, _, ipConn, err = ConnectTunnelWithNoize(
			ctx,
			privKey,
			peerPubKey,
			cert,
			sni,
			connectURI,
			endpoint,
			noizeConfig,
		)
	} else {
		// Regular connection
		fmt.Printf("[DEBUG] Using regular QUIC connection to %s\n", endpoint.String())
		udpConn, _, ipConn, rsp, err = ConnectTunnel(
			ctx,
			tlsConfig,
			quicConfig,
			connectURI,
			endpoint,
		)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect tunnel: %w", err)
	}

	// Check response status (only for non-noize connections that return response)
	if rsp != nil && rsp.StatusCode != 200 {
		if ipConn != nil {
			ipConn.Close()
		}
		if udpConn != nil {
			udpConn.Close()
		}
		return nil, nil, fmt.Errorf("tunnel connection failed: %s", rsp.Status)
	}

	return udpConn, ipConn, nil
}
