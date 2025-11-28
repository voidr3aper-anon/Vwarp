package api

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"net/http"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/bepass-org/vwarp/masque/noize"
)

// ConnectTunnelWithNoize establishes a QUIC connection with noise obfuscation
func ConnectTunnelWithNoize(
	ctx context.Context,
	privKey *ecdsa.PrivateKey,
	peerPubKey *ecdsa.PublicKey,
	cert [][]byte,
	sni string,
	connectUri string,
	endpoint *net.UDPAddr,
	noizeConfigInterface interface{},
) (*net.UDPConn, *http3.Transport, *connectip.Conn, error) {
	// Type assert to noize config
	noizeConfig, ok := noizeConfigInterface.(*noize.NoizeConfig)
	if !ok || noizeConfig == nil {
		// Fall back to no obfuscation
		noizeConfig = noize.NoObfuscationConfig()
	}

	// Prepare TLS config
	tlsConfig, err := PrepareTlsConfig(privKey, peerPubKey, cert, sni)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to prepare TLS config: %w", err)
	}

	// Create UDP connection
	var udpConn *net.UDPConn
	if endpoint.IP.To4() == nil {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv6zero,
			Port: 0,
		})
	} else {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		})
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	// Wrap UDP connection with noize obfuscation
	var wrappedConn *noize.NoizeUDPConn
	if noizeConfig != nil {
		fmt.Printf("[NOIZE] Enabling obfuscation (protocol: %s, junk: %d, fragment: %v)\n",
			noizeConfig.MimicProtocol, noizeConfig.Jc, noizeConfig.FragmentInitial)
		wrappedConn = noize.WrapUDPConn(udpConn, noizeConfig)
	} else {
		// Create wrapper with no obfuscation
		wrappedConn = noize.WrapUDPConn(udpConn, noize.NoObfuscationConfig())
		wrappedConn.Disable()
	}

	// Store endpoint for later use
	wrappedConn.StoreAddr("endpoint", endpoint)

	// Create QUIC config
	quicConfig := &quic.Config{
		EnableDatagrams: true,
	}

	// Establish QUIC connection (using wrapped UDP conn)
	fmt.Printf("[DEBUG] Starting QUIC dial to %s (SNI: %s) with obfuscation...\n", endpoint.String(), sni)

	conn, err := quic.Dial(
		ctx,
		wrappedConn,
		endpoint,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		wrappedConn.Close()
		return nil, nil, nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
	}

	fmt.Printf("[DEBUG] QUIC handshake completed with obfuscation!\n")

	// Create HTTP/3 transport
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			0x276: 1, // SETTINGS_H3_DATAGRAM_00
		},
	}

	// Setup HTTP/3 transport to use our QUIC connection
	tr.TLSClientConfig = tlsConfig

	// Create Connect-IP tunnel
	template := uritemplate.MustNew(connectUri)
	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	hconn := tr.NewClientConn(conn)
	ipConn, resp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		conn.CloseWithError(0, "")
		wrappedConn.Close()
		return nil, nil, nil, fmt.Errorf("failed to establish Connect-IP tunnel: %w", err)
	}

	if resp.StatusCode != 200 {
		conn.CloseWithError(0, "")
		wrappedConn.Close()
		return nil, nil, nil, fmt.Errorf("Connect-IP tunnel failed with status %d", resp.StatusCode)
	}

	fmt.Printf("[DEBUG] Connect-IP tunnel established with obfuscation\n")

	return wrappedConn.UDPConn, tr, ipConn, nil
}

// CreateMasqueClientWithNoize creates a MASQUE client with noise obfuscation
func CreateMasqueClientWithNoize(
	ctx context.Context,
	privKey *ecdsa.PrivateKey,
	peerPubKey *ecdsa.PublicKey,
	cert [][]byte,
	ipv4 string,
	ipv6 string,
	endpointV4 string,
	endpointV6 string,
	sni string,
	useIPv6 bool,
	connectPort int,
	noizeConfig *noize.NoizeConfig,
) (*net.UDPConn, *http3.Transport, *connectip.Conn, error) {
	// Select endpoint
	var endpointAddr *net.UDPAddr
	var connectUri string
	var err error

	if useIPv6 && endpointV6 != "" {
		endpointAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("[%s]:%d", endpointV6, connectPort))
	} else {
		endpointAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", endpointV4, connectPort))
	}

	// Use the same ConnectURI as working usque implementation
	connectUri = "https://cloudflareaccess.com"

	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve endpoint: %w", err)
	}

	// Connect with noize
	return ConnectTunnelWithNoize(ctx, privKey, peerPubKey, cert, sni, connectUri, endpointAddr, noizeConfig)
}
