package app

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/voidr3aper-anon/Vwarp/wireguard/conn"
	"github.com/voidr3aper-anon/Vwarp/wireguard/device"
	"github.com/voidr3aper-anon/Vwarp/wireguard/preflightbind"
	wgtun "github.com/voidr3aper-anon/Vwarp/wireguard/tun"
	"github.com/voidr3aper-anon/Vwarp/wireguard/tun/netstack"
	"github.com/voidr3aper-anon/Vwarp/wiresocks"
)

func usermodeTunTest(ctx context.Context, l *slog.Logger, tnet *netstack.Net, url string) error {
	// Wait a bit after handshake to ensure connection is stable
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
	}

	l.Info("testing connectivity", "url", url)

	// Create HTTP client with appropriate timeouts
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Try tunnel DNS first
			conn, err := tnet.DialContext(ctx, network, addr)
			if err != nil {
				// Log DNS issues but don't fail immediately
				if strings.Contains(err.Error(), "lookup") && strings.Contains(err.Error(), "timeout") {
					l.Debug("DNS lookup timeout via tunnel", "address", addr, "error", err)
				}
			}
			return conn, err
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}

	client := http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		l.Error("connectivity test socket failed", "error", err, "url", url)
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		l.Error("connectivity test failed", "error", err, "url", url)
		return err
	}
	defer resp.Body.Close()

	l.Info("connectivity test completed successfully", "status", resp.StatusCode, "url", url)
	return nil
}

// dnsIndependentConnectivityTest performs a connectivity test without requiring DNS resolution
func dnsIndependentConnectivityTest(ctx context.Context, l *slog.Logger, tnet *netstack.Net) error {
	l.Info("performing DNS-independent connectivity test")

	// Test basic network connectivity by trying to establish a TCP connection
	// to a known Cloudflare IP address
	testIPs := []string{
		"1.1.1.1:443",        // Cloudflare DNS
		"8.8.8.8:443",        // Google DNS
		"104.16.132.229:443", // Cloudflare CDN
		"172.67.74.226:443",  // Another Cloudflare IP
		"104.21.2.20:443",    // Alternative Cloudflare IP
	}

	successCount := 0
	for _, addr := range testIPs {
		testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := tnet.DialContext(testCtx, "tcp", addr)
		cancel()
		if err != nil {
			l.Debug("TCP connectivity test failed", "address", addr, "error", err)
			continue
		}

		// Successfully connected
		conn.Close()
		successCount++
		l.Debug("TCP connectivity test succeeded", "address", addr)

		// If we get at least 2 successful connections, consider it working
		if successCount >= 2 {
			l.Info("DNS-independent connectivity test passed", "successful_connections", successCount)
			return nil
		}
	}

	if successCount > 0 {
		l.Info("Partial connectivity detected", "successful_connections", successCount, "total_tested", len(testIPs))
		return nil // Accept partial connectivity
	}

	return fmt.Errorf("all DNS-independent connectivity tests failed")
}

// enhancedConnectivityTest performs a more comprehensive connectivity test
func enhancedConnectivityTest(ctx context.Context, l *slog.Logger, tnet *netstack.Net, url string) error {
	l.Info("performing enhanced connectivity test", "url", url)

	// First try the original test with reasonable timeout
	testCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	if err := usermodeTunTest(testCtx, l, tnet, url); err == nil {
		cancel()
		return nil
	}
	cancel()

	// If that fails, try direct IP connections to common services with more generous timeouts
	directTests := []struct {
		name string
		url  string
	}{
		{"google", "http://142.250.191.14/"}, // Google IP
		{"cloudflare", "http://104.16.132.229/"},
		{"quad9", "http://149.112.112.112/"},
	}

	passedTests := 0
	for _, test := range directTests {
		testCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		if err := usermodeTunTest(testCtx, l, tnet, test.url); err == nil {
			cancel()
			l.Info("Enhanced connectivity test passed", "test", test.name)
			passedTests++
			// If at least one test passes, consider it successful
			if passedTests >= 1 {
				return nil
			}
		} else {
			l.Debug("Enhanced connectivity test failed", "test", test.name, "error", err)
		}
		cancel()
	}

	return fmt.Errorf("all enhanced connectivity tests failed")
}

func waitHandshake(ctx context.Context, l *slog.Logger, dev *device.Device) error {
	lastHandshakeSecs := "0"
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		get, err := dev.IpcGet()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(get))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}

			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}

			if key == "last_handshake_time_sec" {
				lastHandshakeSecs = value
				break
			}
		}
		if lastHandshakeSecs != "0" {
			l.Debug("handshake complete")
			break
		}

		l.Debug("waiting on handshake")
		time.Sleep(1 * time.Second)
	}

	return nil
}

func establishWireguard(ctx context.Context, l *slog.Logger, conf *wiresocks.Configuration, tunDev wgtun.Device, fwmark uint32, t string, AtomicNoizeConfig *preflightbind.AtomicNoizeConfig, proxyAddress string) error {
	// create the IPC message to establish the wireguard conn
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.Interface.PrivateKey))
	if fwmark != 0 {
		request.WriteString(fmt.Sprintf("fwmark=%d\n", fwmark))
	}

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
		request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.KeepAlive))
		request.WriteString(fmt.Sprintf("preshared_key=%s\n", peer.PreSharedKey))
		request.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))

		// Only set trick if AtomicNoize is not being used
		if AtomicNoizeConfig == nil {
			request.WriteString(fmt.Sprintf("trick=%s\n", t))
		} else {
			// Set trick to empty/t0 to disable old obfuscation when using AtomicNoize
			request.WriteString("trick=t0\n")
		}

		request.WriteString(fmt.Sprintf("reserved=%d,%d,%d\n", peer.Reserved[0], peer.Reserved[1], peer.Reserved[2]))

		for _, cidr := range peer.AllowedIPs {
			request.WriteString(fmt.Sprintf("allowed_ip=%s\n", cidr))
		}
	}

	// Create the appropriate bind based on configuration
	var bind conn.Bind

	// If proxy address is provided, create a proxy-aware bind
	if proxyAddress != "" {
		l.Info("using SOCKS proxy for WireGuard traffic", "proxy", proxyAddress)
		bind = conn.NewProxyBind(proxyAddress)
	} else {
		bind = conn.NewDefaultBind()
	}

	// If AtomicNoizeConfig configuration is provided, wrap the bind
	if AtomicNoizeConfig != nil {
		l.Info("using AtomicNoize WireGuard obfuscation")

		// Extract port from the first peer endpoint
		preflightPort := 443 // default fallback
		if len(conf.Peers) > 0 && conf.Peers[0].Endpoint != "" {
			_, portStr, err := net.SplitHostPort(conf.Peers[0].Endpoint)
			if err == nil {
				if port, err := strconv.Atoi(portStr); err == nil {
					preflightPort = port
				}
			}
		}

		l.Info("using preflight port", "port", preflightPort)
		amnesiaBind, err := preflightbind.NewWithAtomicNoize(
			bind, // Use the already created bind instead of creating a new one
			AtomicNoizeConfig,
			preflightPort,        // extracted port for preflight packets
			100*time.Millisecond, // minimum interval between preflights (reduced from 1 second)
		)
		if err != nil {
			l.Error("failed to create AtomicNoize bind", "error", err)
			return err
		}
		bind = amnesiaBind
	}

	dev := device.NewDevice(
		tunDev,
		bind,
		device.NewSLogger(l.With("subsystem", "wireguard-go")),
	)

	IpcSetCh := make(chan error, 1)
	go func() {
		IpcSetCh <- dev.IpcSet(request.String())
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-IpcSetCh:
		if err != nil {
			return err
		}
	}

	if err := dev.Up(); err != nil {
		return err
	}

	handshakeCTX, handshakeCancel := context.WithDeadline(ctx, time.Now().Add(15*time.Second))
	defer handshakeCancel()
	if err := waitHandshake(handshakeCTX, l, dev); err != nil {
		dev.BindClose()
		dev.Close()
		return err
	}

	return nil
}
