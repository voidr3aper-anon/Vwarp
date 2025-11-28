package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"golang.org/x/net/http2"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// NewClientFromFilesOrEnv initializes a MASQUE client from file paths or environment variables.
// privKeyPath, certPath, and peerPubKeyPath can be empty to use environment variables:
//
//	MASQUE_PRIVKEY_B64, MASQUE_CERT_B64, MASQUE_PEER_PUBKEY_B64
//
// endpointStr is the MASQUE server address (host:port)
func NewClientFromFilesOrEnv(endpointStr, sni, connectURI, target string, privKeyPath, certPath, peerPubKeyPath string, logger *slog.Logger) (*Client, error) {
	// Helper to load base64 or PEM data from file or env
	loadOrEnv := func(path, env string) ([]byte, error) {
		if path != "" {
			if logger != nil {
				logger.Debug("Loading from file", "path", path)
			}
			return os.ReadFile(path)
		}
		val := os.Getenv(env)
		if val == "" {
			if logger != nil {
				logger.Debug("Missing value for", "env", env)
			}
			return nil, fmt.Errorf("missing %s (file or env)", env)
		}
		if logger != nil {
			logger.Debug("Loaded from env", "env", env)
		}
		return []byte(val), nil
	}

	// Load private key
	var privKey *ecdsa.PrivateKey
	if privKeyPath != "" || os.Getenv("MASQUE_PRIVKEY_B64") != "" {
		if logger != nil {
			logger.Info("Loading ECDSA private key")
		}
		privKeyBytes, err := loadOrEnv(privKeyPath, "MASQUE_PRIVKEY_B64")
		if err != nil {
			if logger != nil {
				logger.Error("Failed to load private key", "error", err)
			}
			return nil, fmt.Errorf("load privkey: %w", err)
		}
		privKey, err = ParseECPrivateKey(string(privKeyBytes))
		if err != nil {
			if logger != nil {
				logger.Error("Failed to parse private key", "error", err)
			}
			return nil, fmt.Errorf("parse privkey: %w", err)
		}
		if logger != nil {
			logger.Debug("Private key loaded and parsed successfully")
		}
	} else {
		if logger != nil {
			logger.Info("Skipping private key")
		}
	}

	// Load certificate (DER or base64-encoded DER)
	var cert [][]byte
	if certPath != "" || os.Getenv("MASQUE_CERT_B64") != "" {
		if logger != nil {
			logger.Info("Loading certificate")
		}
		certBytes, err := loadOrEnv(certPath, "MASQUE_CERT_B64")
		if err != nil {
			if logger != nil {
				logger.Error("Failed to load certificate", "error", err)
			}
			return nil, fmt.Errorf("load cert: %w", err)
		}
		// Accept both base64 and raw DER
		var certDER []byte
		certDER, err = base64.StdEncoding.DecodeString(string(certBytes))
		if err != nil {
			if logger != nil {
				logger.Debug("Certificate not base64, using as raw DER")
			}
			certDER = certBytes
		} else {
			if logger != nil {
				logger.Debug("Certificate loaded from base64")
			}
		}
		cert = [][]byte{certDER}
	} else {
		if logger != nil {
			logger.Info("Skipping client certificate")
		}
	}

	// Load peer public key
	var peerPubKey *ecdsa.PublicKey
	if peerPubKeyPath != "" || os.Getenv("MASQUE_PEER_PUBKEY_B64") != "" {
		if logger != nil {
			logger.Info("Loading peer public key")
		}
		peerPubKeyBytes, err := loadOrEnv(peerPubKeyPath, "MASQUE_PEER_PUBKEY_B64")
		if err != nil {
			if logger != nil {
				logger.Error("Failed to load peer public key", "error", err)
			}
			return nil, fmt.Errorf("load peer pubkey: %w", err)
		}
		peerPubKey, err = ParseECPublicKey(peerPubKeyBytes)
		if err != nil {
			if logger != nil {
				logger.Error("Failed to parse peer public key", "error", err)
			}
			return nil, fmt.Errorf("parse peer pubkey: %w", err)
		}
		if logger != nil {
			logger.Debug("Peer public key loaded and parsed successfully")
		}
	} else {
		if logger != nil {
			logger.Info("Skipping peer public key pinning")
		}
	}

	// Parse endpoint
	if logger != nil {
		logger.Info("Parsing MASQUE server endpoint", "endpoint", endpointStr)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", endpointStr)
	if err != nil {
		if logger != nil {
			logger.Error("Failed to resolve endpoint", "endpoint", endpointStr, "error", err)
		}
		return nil, fmt.Errorf("resolve endpoint: %w", err)
	}
	if logger != nil {
		logger.Debug("Endpoint parsed successfully", "udpAddr", udpAddr.String())
	}
	// Determine if the provided endpoint was an IP literal (rather than domain)
	var endpointIsIP bool
	if host, _, serr := net.SplitHostPort(endpointStr); serr == nil {
		// strip [] for IPv6 literal
		host = strings.Trim(host, "[]")
		if net.ParseIP(host) != nil {
			endpointIsIP = true
		}
	}

	if sni == "" {
		sni = ConnectSNI
	}
	if connectURI == "" {
		connectURI = ConnectURI
	}

	// Generate self-signed certificate if none provided (required for Connect-IP authentication)
	if cert == nil {
		// For Connect-IP authentication, we should use the WARP private key if available
		// Check if this is a MASQUE config load and we can use the WARP private key
		warpPrivKey := privKey

		// Generate a key pair if no private key is provided at all
		if warpPrivKey == nil {
			if logger != nil {
				logger.Debug("No WARP private key available, generating new ECDSA key pair for certificate")
			}
			warpPrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				if logger != nil {
					logger.Error("Failed to generate private key", "error", err)
				}
				return nil, fmt.Errorf("generate private key: %w", err)
			}
		} else {
			if logger != nil {
				logger.Debug("Using WARP private key from config for Connect-IP authentication")
			}
		}

		if logger != nil {
			logger.Debug("Generating self-signed certificate for MASQUE connection")
		}
		cert, err = GenerateSelfSignedCert(warpPrivKey)
		if err != nil {
			if logger != nil {
				logger.Error("Failed to generate certificate", "error", err)
			}
			return nil, fmt.Errorf("generate certificate: %w", err)
		}
		if logger != nil {
			logger.Debug("Certificate generated successfully with WARP credentials")
		}

		// Update privKey to the one used for certificate generation
		privKey = warpPrivKey
	}

	if logger != nil {
		logger.Info("Preparing TLS config", "sni", sni)
	}
	tlsConfig, err := PrepareTLSConfig(privKey, peerPubKey, cert, sni, logger)
	if err != nil {
		if logger != nil {
			logger.Error("Failed to prepare TLS config", "error", err)
		}
		return nil, fmt.Errorf("prepare tls config: %w", err)
	}
	if logger != nil {
		logger.Debug("TLS config prepared successfully")
	}

	if logger != nil {
		logger.Info("Creating MASQUE client instance")
	}
	resolveConnectHost := true
	if v := os.Getenv("MASQUE_RESOLVE_CONNECT_HOST"); v != "" {
		if strings.ToLower(v) == "0" || strings.ToLower(v) == "false" {
			resolveConnectHost = false
		}
	}
	return NewClient(Config{
		Endpoint:           udpAddr,
		TLSConfig:          tlsConfig,
		QUICConfig:         DefaultQUICConfig(30*time.Second, 1242),
		ConnectURI:         connectURI,
		Target:             target,
		Logger:             logger,
		ResolveConnectHost: resolveConnectHost,
		EndpointIsIP:       endpointIsIP,
	})
}

// Client represents a MASQUE client using Connect-IP protocol
type Client struct {
	endpoint           *net.UDPAddr
	tlsConfig          *tls.Config
	quicConfig         *quic.Config
	connectURI         string
	target             string
	logger             *slog.Logger
	resolveConnectHost bool
	endpointIsIP       bool
}

// connectipAdapter adapts a *connectip.Conn to io.ReadWriteCloser so callers
// can use the same interface for stream-based (HTTP/2) and QUIC-based (connectip.Conn) paths.
type connectipAdapter struct {
	c *connectip.Conn
}

func (a *connectipAdapter) Read(p []byte) (int, error) {
	// allowAny=false ensures we only return proxied IP packets
	return a.c.ReadPacket(p, false)
}

func (a *connectipAdapter) Write(p []byte) (int, error) {
	// WritePacket may return an ICMP response which callers may need to handle
	_, err := a.c.WritePacket(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *connectipAdapter) Close() error {
	return a.c.Close()
}

// (removed) computePubkeyFingerprint: we rely on TLS VerifyPeerCertificate for pinning

// Config holds the configuration for a MASQUE client
type Config struct {
	Endpoint           *net.UDPAddr
	TLSConfig          *tls.Config
	QUICConfig         *quic.Config
	ConnectURI         string
	Target             string
	Logger             *slog.Logger
	ResolveConnectHost bool
	EndpointIsIP       bool
	// Optional: a fingerprint (sha256 hex) of the expected server public key
}

// NewClient creates a new MASQUE client using Connect-IP
func NewClient(cfg Config) (*Client, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("TLS config is required")
	}

	if cfg.Endpoint == nil {
		return nil, fmt.Errorf("endpoint is required")
	}

	if cfg.ConnectURI == "" {
		cfg.ConnectURI = ConnectURI
	}

	if cfg.QUICConfig == nil {
		cfg.QUICConfig = DefaultQUICConfig(30*time.Second, 1242)
	}

	return &Client{
		endpoint:           cfg.Endpoint,
		tlsConfig:          cfg.TLSConfig,
		quicConfig:         cfg.QUICConfig,
		connectURI:         cfg.ConnectURI,
		target:             cfg.Target,
		logger:             cfg.Logger,
		resolveConnectHost: cfg.ResolveConnectHost,
		endpointIsIP:       cfg.EndpointIsIP,
		// no extra expected fingerprint or skip flags; pinning handled by TLS VerifyPeerCertificate
	}, nil
}

// ConnectIP establishes a Connect-IP tunnel (full IP tunneling)
func (c *Client) ConnectIP(ctx context.Context) (*net.UDPConn, io.ReadWriteCloser, error) {
	c.logger.Debug("establishing Connect-IP tunnel", "endpoint", c.endpoint.String())
	c.logger.Debug("Creating UDP socket for QUIC")

	// Create UDP connection
	var udpConn *net.UDPConn
	var err error
	if c.endpoint.IP.To4() == nil {
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
		return nil, nil, fmt.Errorf("failed to create UDP conn: %w", err)
	}

	// Try QUIC/HTTP3 first
	c.logger.Info("Attempting QUIC/HTTP3 connection", "target", c.target, "server", c.endpoint.String())
	c.logger.Debug("TLS ServerName", "sni", c.tlsConfig.ServerName)
	c.logger.Debug("Next protocols", "protocols", c.tlsConfig.NextProtos)
	// NB: We intentionally do not change the configured endpoint based on the connectURI host.
	// The `masque-plus`/`usque` flow resolves endpoint at config/write time; we preserve
	// the configured endpoint here and use `resolveConnectHost` only to consider candidate
	// IPs when dialing HTTP/2 fallbacks (see below).

	quicConn, err := quic.Dial(
		ctx,
		udpConn,
		c.endpoint,
		c.tlsConfig,
		c.quicConfig,
	)
	if err == nil {
		c.logger.Debug("QUIC/HTTP3 handshake succeeded")
		// HTTP/3 transport with datagram support - match usque exactly
		// The TLS config is already applied to the QUIC connection, so the transport inherits it
		roundTripper := &http3.Transport{
			EnableDatagrams: true,
			AdditionalSettings: map[uint64]uint64{
				// official client still sends this out as well, even though
				// it's deprecated, see https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
				// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
				// https://github.com/cloudflare/quiche/blob/7c66757dbc55b8d0c3653d4b345c6785a181f0b7/quiche/src/h3/frame.rs#L46
				0x276: 1,
			},
			DisableCompression: true,
		}
		template, err := uritemplate.New(c.connectURI)
		if err != nil {
			c.logger.Error("Failed to parse URI template for QUIC", "error", err)
			udpConn.Close()
			return nil, nil, fmt.Errorf("failed to parse URI template: %w", err)
		}
		c.logger.Info("Dialing Connect-IP over HTTP/3 (QUIC)")
		c.logger.Debug("Using Connect-IP URI template", "template", c.connectURI)

		// Create HTTP/3 client connection with TLS config that includes our certificates
		hconn := roundTripper.NewClientConn(quicConn)

		// Add User-Agent header like usque does
		additionalHeaders := http.Header{
			"User-Agent": []string{""},
		}

		c.logger.Debug("Calling connectip.Dial with certificates")
		ipConnExt, resp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
		if err != nil {
			c.logger.Error("Failed to dial connect-ip over QUIC", "error", err)
			c.logger.Debug("QUIC connection state", "remote", quicConn.RemoteAddr().String())
			udpConn.Close()
			return nil, nil, fmt.Errorf("failed to dial connect-ip: %w", err)
		}
		if resp.StatusCode != 200 {
			c.logger.Error("Connect-IP over QUIC failed", "status", resp.StatusCode, "status_text", resp.Status)
			if resp.Header != nil {
				c.logger.Debug("Response headers", "headers", resp.Header)
			}
			// Close the connection returned by connectip if possible
			if ipConnExt != nil {
				_ = ipConnExt.Close()
			}
			udpConn.Close()
			return nil, nil, fmt.Errorf("connect-ip failed with status %d (%s)", resp.StatusCode, resp.Status)
		}
		c.logger.Info("Connect-IP tunnel established successfully via HTTP/3 (QUIC)")
		// convert to our local ConnectIPConn wrapper if needed
		// ipConnExt is a *connectip.Conn. Wrap it into an adapter that
		// exposes io.ReadWriteCloser so the rest of the code can use it.
		adapter := &connectipAdapter{c: ipConnExt}
		return udpConn, adapter, nil
	}

	// Fallback to HTTP/2
	c.logger.Warn("QUIC/HTTP3 failed, falling back to HTTP/2", "error", err)
	c.logger.Debug("Closing UDP socket, not needed for HTTP/2")
	udpConn.Close()

	// Prepare HTTP/2 TLS config
	c.logger.Debug("Preparing HTTP/2 TLS config")
	h2tls := c.tlsConfig.Clone()
	h2tls.NextProtos = []string{"h2"}

	// Note: We'll perform a Connect-IP host reachability check below after we can expand the connectURI template.

	// Use uritemplate for Connect-IP URI
	c.logger.Debug("Parsing Connect-IP URI template for HTTP/2")
	template, err := uritemplate.New(c.connectURI)
	if err != nil {
		c.logger.Error("Failed to parse URI template for HTTP/2", "error", err)
		return nil, nil, fmt.Errorf("failed to parse URI template: %w", err)
	}

	// Expand the template to find the host:port we will actually connect to (use target components)
	// Split target into host and port for correct template expansion
	thost, tport, _ := net.SplitHostPort(c.target)
	if thost == "" {
		thost = c.target
	}
	// For IPv6 addresses, bracket them when used in the URI path
	expHost := thost
	if net.ParseIP(thost) != nil && net.ParseIP(thost).To4() == nil {
		expHost = "[" + thost + "]"
	}
	var tcpHost string
	var resolvedDialAddr string
	var connectHostIPs []net.IP
	expandedURI, err := template.Expand(uritemplate.Values{
		"target_host": uritemplate.String(expHost),
		"target_port": uritemplate.String(tport),
	})
	if err != nil {
		c.logger.Warn("Failed to expand URI for reachability check; continuing to HTTP/2 dial", "error", err)
	} else {
		if u, perr := url.Parse(expandedURI); perr == nil {
			tcpHost = u.Host
			if !strings.Contains(tcpHost, ":") {
				tcpHost = tcpHost + ":443"
			}
			// Do a TCP reachability check against the Connect-IP host (may be a hostname like cloudflareaccess.com)
			c.logger.Debug("Checking TCP reachability to Connect-IP host", "addr", tcpHost)
			dialTest := &net.Dialer{Timeout: 5 * time.Second}
			var lastErr error
			for attempt := 1; attempt <= 3; attempt++ {
				tcpTestConn, err := dialTest.DialContext(ctx, "tcp", tcpHost)
				if err != nil {
					c.logger.Debug("TCP reachability attempt failed", "attempt", attempt, "error", err)
					lastErr = err
					time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
					continue
				}
				c.logger.Debug("TCP reachability check OK", "local", tcpTestConn.LocalAddr().String(), "remote", tcpTestConn.RemoteAddr().String())
				tcpTestConn.Close()
				lastErr = nil
				break
			}

			// We'll resolve connect host later (after we set connectHost) to prefer the domain IP instead of the configured endpoint IP
			if lastErr != nil {
				// If DNS/lookup error or other contact issue, fallback to dialing the endpoint IP (which may be set by --endpoint)
				c.logger.Warn("TCP reachability check failed, attempting fallback to endpoint IP", "error", lastErr, "endpoint", c.endpoint.String())
				// Try dialing endpoint IP
				for attempt := 1; attempt <= 2; attempt++ {
					tcpTestConn, err := dialTest.DialContext(ctx, "tcp", c.endpoint.String())
					if err != nil {
						c.logger.Debug("TCP reachability fallback attempt failed", "attempt", attempt, "error", err)
						lastErr = err
						time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
						continue
					}
					c.logger.Debug("TCP reachability fallback OK", "local", tcpTestConn.LocalAddr().String(), "remote", tcpTestConn.RemoteAddr().String(), "endpoint", c.endpoint.String())
					tcpTestConn.Close()
					lastErr = nil
					break
				}
				if lastErr != nil {
					c.logger.Warn("TCP reachability final failure", "error", lastErr)
				}
			}
		} else {
			c.logger.Debug("Failed to parse expanded Connect-IP URI for reachability check", "uri", expandedURI, "error", perr)
		}
	}

	// tcpHost is declared above and will be used for dial override
	// Set server name (SNI) for HTTP/2 transport to the connectURI host
	var connectHost string
	if expandedURI != "" {
		if u, perr := url.Parse(expandedURI); perr == nil {
			if h2tls != nil {
				h2tls.ServerName = u.Hostname()
				c.logger.Debug("Set HTTP/2 TLS ServerName for SNI", "serverName", u.Hostname())
			}
			connectHost = u.Hostname()
			// Resolve the connect host to prefer the domain IP instead of the configured endpoint IP
			portStr := u.Port()
			if portStr == "" {
				portStr = "443"
			}
			if connectHost != "" {
				// try default resolver first (may use Go or cgo depending on platform)
				if addrs, derr := net.DefaultResolver.LookupIPAddr(ctx, connectHost); derr == nil && len(addrs) > 0 {
					resolvedDialAddr = net.JoinHostPort(addrs[0].IP.String(), portStr)
					c.logger.Debug("Resolved Connect-IP host via net.DefaultResolver", "host", connectHost, "ip", addrs[0].IP.String(), "usingDialAddr", resolvedDialAddr)
					// collect IPs for candidate dialing
					for _, a := range addrs {
						connectHostIPs = append(connectHostIPs, a.IP)
					}
				} else {
					// Try system resolver explicitly via net.Resolver PreferGo=false
					r := &net.Resolver{PreferGo: false}
					if addrs2, derr2 := r.LookupIPAddr(ctx, connectHost); derr2 == nil && len(addrs2) > 0 {
						resolvedDialAddr = net.JoinHostPort(addrs2[0].IP.String(), portStr)
						c.logger.Debug("Resolved Connect-IP host via system resolver", "host", connectHost, "ip", addrs2[0].IP.String(), "usingDialAddr", resolvedDialAddr)
						for _, a := range addrs2 {
							connectHostIPs = append(connectHostIPs, a.IP)
						}
					} else {
						// As a last fallback, try net.LookupIP (simpler API)
						if ips, derr3 := net.LookupIP(connectHost); derr3 == nil && len(ips) > 0 {
							resolvedDialAddr = net.JoinHostPort(ips[0].String(), portStr)
							c.logger.Debug("Resolved Connect-IP host via net.LookupIP fallback", "host", connectHost, "ip", ips[0].String(), "usingDialAddr", resolvedDialAddr)
							connectHostIPs = append(connectHostIPs, ips...)
						} else {
							// Fallback to the configured endpoint IP
							resolvedDialAddr = net.JoinHostPort(c.endpoint.IP.String(), strconv.Itoa(c.endpoint.Port))
							c.logger.Debug("Failed to resolve Connect-IP host; falling back to endpoint IP", "host", connectHost, "errorA", derr, "errorB", derr2, "errorC", derr3, "usingDialAddr", resolvedDialAddr)
						}
					}
				}
			} else {
				resolvedDialAddr = net.JoinHostPort(c.endpoint.IP.String(), strconv.Itoa(c.endpoint.Port))
			}
		}
	}

	// Create HTTP/2 transport (http.RoundTripper) with custom DialTLS so we can override dial address
	c.logger.Debug("Creating HTTP/2 transport with custom DialTLS")
	h2Transport := &http2.Transport{
		TLSClientConfig: h2tls,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			if c.logger != nil {
				c.logger.Debug("HTTP/2 dial start", "network", network, "addr", addr)
			}
			d := &net.Dialer{Timeout: 15 * time.Second}
			// When dialing the connectHost over HTTP/2, prefer DNS-resolved IPs (preserve SNI)
			hostPart, portPart, _ := net.SplitHostPort(addr)
			if connectHost != "" && hostPart == connectHost {
				var candidates []string
				// If endpoint was provided as IP, prefer dialing it first (like usque/masque)
				if c.endpointIsIP && c.endpoint != nil {
					candidates = append(candidates, c.endpoint.String())
				}
				if c.resolveConnectHost && len(connectHostIPs) > 0 {
					for _, ip := range connectHostIPs {
						ipStr := ip.String()
						if ip.To4() == nil {
							ipStr = "[" + ipStr + "]"
						}
						candidates = append(candidates, net.JoinHostPort(ipStr, portPart))
					}
				}
				// Append resolvedDialAddr (string) if present
				if c.resolveConnectHost && resolvedDialAddr != "" {
					candidates = append(candidates, resolvedDialAddr)
				}
				// If endpoint was not an IP literal, append configured endpoint as last resort
				if !c.endpointIsIP && c.endpoint != nil {
					candidates = append(candidates, c.endpoint.String())
				}

				var lastErr error
				for _, dialCandidate := range candidates {
					if c.logger != nil {
						c.logger.Debug("Attempting HTTP/2 TLS dial candidate", "candidate", dialCandidate)
					}
					conn, err := tls.DialWithDialer(d, network, dialCandidate, cfg)
					if err == nil {
						if c.logger != nil {
							c.logger.Debug("HTTP/2 dial succeeded", "remote", conn.RemoteAddr().String(), "candidate", dialCandidate)
						}
						// If handshake succeeded, return conn and let TLS VerifyPeerCertificate
						// perform public-key pinning if configured. If it failed, the handshake
						// would have returned an error and we'd continue to next candidate.
						return conn, nil
					}
					lastErr = err
					if c.logger != nil {
						c.logger.Debug("HTTP/2 dial candidate failed", "candidate", dialCandidate, "error", err)
					}
					// Continue trying next candidate
				}
				if lastErr != nil {
					return nil, lastErr
				}
			}
			// Default: dial the exact addr provided
			conn, err := tls.DialWithDialer(d, network, addr, cfg)
			if err != nil {
				if oerr, ok := err.(*net.OpError); ok {
					if c.logger != nil {
						c.logger.Error("HTTP/2 dial failed (net.OpError)", "addr", addr, "op", oerr.Op, "net", oerr.Net, "source", fmt.Sprintf("%v", oerr.Source), "addrerr", fmt.Sprintf("%v", oerr.Addr), "error", oerr.Err)
					}
				} else {
					if c.logger != nil {
						c.logger.Error("HTTP/2 dial failed", "addr", addr, "error", err)
					}
				}
				return nil, err
			}
			if c.logger != nil {
				c.logger.Debug("HTTP/2 dial succeeded", "remote", conn.RemoteAddr().String())
			}
			return conn, nil
		},
	}
	// The http2.Transport will handle dialing using DialTLS above.

	// DialConnectIP with HTTP/2 transport (use our local DialConnectIP which can use http.RoundTripper)
	c.logger.Debug("Dialing Connect-IP over HTTP/2", "target", c.target, "server", c.endpoint.String())
	ipConn, resp, err := DialConnectIP(ctx, h2Transport, template, "cf-connect-ip", nil, true, c.target, c.logger)
	if err != nil {
		c.logger.Error("Failed to dial connect-ip over HTTP/2", "error", err)
		return nil, nil, fmt.Errorf("failed to dial connect-ip (HTTP/2): %w", err)
	}
	if resp.StatusCode != 200 {
		c.logger.Error("Connect-IP over HTTP/2 failed", "status", resp.StatusCode)
		if ipConn != nil {
			ipConn.Close()
		}
		return nil, nil, fmt.Errorf("connect-ip failed with status %d (HTTP/2)", resp.StatusCode)
	}
	c.logger.Info("Connect-IP tunnel established successfully via HTTP/2")
	return nil, ipConn, nil
}

// Close closes the MASQUE client
func (c *Client) Close() error {
	// Client doesn't hold persistent connections
	return nil
}

// setResolveConnectHost toggles whether the client will resolve the connectURI host
// and use its IP for dialing. This allows CLI tools to opt-in.
func (c *Client) setResolveConnectHost(v bool) {
	c.resolveConnectHost = v
}

// SetResolveConnectHost toggles whether the client will resolve the connectURI host
// and use its IP for dialing. This allows CLI tools to opt-in.
func (c *Client) SetResolveConnectHost(v bool) {
	c.setResolveConnectHost(v)
}

// PrepareTLSConfig creates a TLS configuration with certificate pinning for Cloudflare
func PrepareTLSConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string, logger *slog.Logger) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName:         sni,
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: true, // We verify via VerifyPeerCertificate
		// Don't force TLS version - let it negotiate automatically for better compatibility
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Skip certificate pinning if requested via environment variable
			if os.Getenv("MASQUE_SKIP_PUBKEY_PINNING") == "1" || os.Getenv("MASQUE_SKIP_PUBKEY_PINNING") == "true" {
				if logger != nil {
					logger.Info("Skipping certificate pinning verification due to MASQUE_SKIP_PUBKEY_PINNING")
				}
				return nil
			}

			// Simplified verification like usque - only pin if we have a specific peer public key
			if peerPubKey != nil && len(rawCerts) > 0 {
				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}

				if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
					// we only support ECDSA like usque
					return x509.ErrUnsupportedAlgorithm
				}

				if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
					// Use usque's error format
					return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
				}
			}

			if logger != nil {
				logger.Debug("Certificate verification passed")
			}
			return nil
		},
	}

	// Optional: set TLS KeyLogWriter for debugging (set MASQUE_TLS_KEYLOG=/path/to/keys.log)
	if keyLogPath := os.Getenv("MASQUE_TLS_KEYLOG"); keyLogPath != "" {
		if f, err := os.OpenFile(keyLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
			tlsConfig.KeyLogWriter = f
		}
	}

	// Add debugging info about the TLS configuration
	if logger != nil {
		logger.Debug("TLS configuration details",
			"server_name", tlsConfig.ServerName,
			"next_protos", tlsConfig.NextProtos,
			"min_version", tlsConfig.MinVersion,
			"max_version", tlsConfig.MaxVersion,
			"insecure_skip_verify", tlsConfig.InsecureSkipVerify,
			"has_client_cert", len(tlsConfig.Certificates) > 0)
	}

	return tlsConfig, nil
}
