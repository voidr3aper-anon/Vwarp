package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/voidr3aper-anon/Vwarp/masque/noize"
	"github.com/yosida95/uritemplate/v3"
)

// ConnectTunnelWithNoize connects to MASQUE server with optional noize obfuscation
// This is a modified version of usque's ConnectTunnel that supports UDP connection wrapping
// Note: Noize obfuscation is automatically disabled after successful tunnel establishment
func ConnectTunnelWithNoize(
	ctx context.Context,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
	connectUri string,
	endpoint *net.UDPAddr,
	noizeConfig *noize.NoizeConfig,
	logger *slog.Logger,
) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {

	// Create UDP connection
	var udpConn *net.UDPConn
	var err error
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
		return nil, nil, nil, nil, err
	}

	// Wrap UDP connection with noize if config is provided
	var quicConn net.PacketConn = udpConn
	var noizeConn *noize.NoizeUDPConn
	if noizeConfig != nil {
		noizeConn = noize.WrapUDPConn(udpConn, noizeConfig)
		quicConn = noizeConn

		if logger != nil {
			logger.Info("Noize wrapper created", "jcBeforeHS", noizeConfig.JcBeforeHS, "jcAfterI1", noizeConfig.JcAfterI1)
		}

		// Enable debug logging only if explicitly requested via environment
		if os.Getenv("VWARP_NOIZE_DEBUG") == "1" {
			noizeConn.EnableDebugPadding()
		}
	} else {
		if logger != nil {
			logger.Warn("No noize config provided - using plain UDP connection")
		}
	}

	// Configure UDP socket buffers for optimal QUIC performance
	// Note: Apply this after noize wrapping to ensure compatibility
	if logger != nil {
		if bufferErr := configureUDPBuffer(udpConn, logger); bufferErr != nil {
			logger.Warn("Failed to optimize UDP buffer settings", "error", bufferErr)
			// Continue anyway - this is not a fatal error
		}
	}

	// Dial QUIC connection
	if logger != nil {
		logger.Info("About to call quic.Dial", "packetConnType", fmt.Sprintf("%T", quicConn), "hasNoize", noizeConn != nil)
	}

	// Send initial junk packets proactively before QUIC dial
	// This ensures obfuscation happens before the real handshake begins
	if noizeConn != nil {
		if logger != nil {
			logger.Info("Sending pre-handshake obfuscation before QUIC dial")
		}
		// Trigger pre-handshake sequence directly
		testData := []byte("init")
		if _, err := quicConn.WriteTo(testData, endpoint); err != nil {
			if logger != nil {
				logger.Warn("Pre-handshake trigger failed", "error", err)
			}
		}
	}

	conn, err := quic.Dial(
		ctx,
		quicConn,
		endpoint,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		return udpConn, nil, nil, nil, err
	}

	// Create HTTP/3 transport
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			0x276: 1,
		},
		DisableCompression: true,
	}

	hconn := tr.NewClientConn(conn)

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	template := uritemplate.MustNew(connectUri)
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return udpConn, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return udpConn, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %v", err)
	}

	// IMPORTANT: Disable noize obfuscation after successful tunnel establishment
	// Noize is only needed during connection setup - sending junk through established tunnel wastes bandwidth
	if noizeConn != nil {
		noizeConn.DisableObfuscation()
		if logger != nil {
			logger.Info("Noize obfuscation disabled after successful tunnel establishment")
		}
	}

	return udpConn, tr, ipConn, rsp, nil
}

// ConnectTunnelOptimized is an enhanced version of api.ConnectTunnel that applies UDP buffer optimizations
// This function wraps the standard usque ConnectTunnel with UDP socket buffer configuration for optimal QUIC performance
func ConnectTunnelOptimized(
	ctx context.Context,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
	connectUri string,
	endpoint *net.UDPAddr,
	logger *slog.Logger,
) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {

	// Create UDP connection
	var udpConn *net.UDPConn
	var err error
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
		return nil, nil, nil, nil, err
	}

	// Configure UDP socket buffers for optimal QUIC performance
	if logger != nil {
		if bufferErr := configureUDPBuffer(udpConn, logger); bufferErr != nil {
			logger.Warn("Failed to optimize UDP buffer settings", "error", bufferErr)
			// Continue anyway - this is not a fatal error
		}
	}

	// Dial QUIC connection
	conn, err := quic.Dial(
		ctx,
		udpConn,
		endpoint,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		return udpConn, nil, nil, nil, err
	}

	// Create HTTP/3 transport
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			0x276: 1,
		},
		DisableCompression: true,
	}

	hconn := tr.NewClientConn(conn)

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	template := uritemplate.MustNew(connectUri)
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return udpConn, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return udpConn, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %v", err)
	}

	return udpConn, tr, ipConn, rsp, nil
}
