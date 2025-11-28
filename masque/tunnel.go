package masque

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
)

// Tunnel represents a MASQUE Connect-IP tunnel for WireGuard traffic
type Tunnel struct {
	client     *Client
	udpConn    *net.UDPConn
	ipConn     io.ReadWriteCloser
	localAddr  netip.AddrPort
	remoteAddr netip.AddrPort
	logger     *slog.Logger
	closeOnce  sync.Once
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewTunnel creates a new MASQUE tunnel for WireGuard using Connect-IP
func NewTunnel(ctx context.Context, cfg MasqueConfig, logger *slog.Logger) (*Tunnel, error) {
	if err := cfg.Validate(); err != nil {
		if logger != nil {
			logger.Error("MASQUE tunnel config validation failed", "error", err)
		}
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if logger == nil {
		logger = slog.Default()
	}

	logger.Debug("Parsing MASQUE endpoint", "endpoint", cfg.WarpEndpoint.String())
	// Parse endpoint from server URL
	endpoint, err := net.ResolveUDPAddr("udp", cfg.WarpEndpoint.String())
	if err != nil {
		logger.Error("Failed to resolve MASQUE endpoint", "endpoint", cfg.WarpEndpoint.String(), "error", err)
		return nil, fmt.Errorf("failed to resolve endpoint: %w", err)
	}

	logger.Debug("Creating MASQUE client", "endpoint", endpoint)
	// Create MASQUE client
	client, err := NewClient(Config{
		Endpoint:   endpoint,
		TLSConfig:  cfg.TLSConfig,
		QUICConfig: nil,
		ConnectURI: ConnectURI,
		Target:     cfg.WarpEndpoint.String(),
		Logger:     logger,
	})
	if err != nil {
		logger.Error("Failed to create MASQUE client", "error", err)
		return nil, fmt.Errorf("failed to create MASQUE client: %w", err)
	}

	logger.Info("Establishing MASQUE tunnel to WARP", "endpoint", cfg.WarpEndpoint)

	// Establish Connect-IP tunnel
	udpConn, ipConn, err := client.ConnectIP(ctx)
	if err != nil {
		logger.Error("Failed to establish Connect-IP tunnel", "error", err)
		client.Close()
		return nil, fmt.Errorf("failed to establish Connect-IP tunnel: %w", err)
	}

	logger.Debug("Connect-IP tunnel established, setting up Tunnel struct")
	tunnelCtx, cancel := context.WithCancel(ctx)

	tunnel := &Tunnel{
		client:     client,
		udpConn:    udpConn,
		ipConn:     ipConn,
		localAddr:  netip.AddrPort{},
		remoteAddr: cfg.WarpEndpoint,
		logger:     logger,
		ctx:        tunnelCtx,
		cancel:     cancel,
	}

	logger.Info("MASQUE tunnel established successfully")
	return tunnel, nil
}

// Read reads IP packets from the tunnel
func (t *Tunnel) Read(p []byte) (n int, err error) {
	return t.ipConn.Read(p)
}

// Write writes IP packets to the tunnel
func (t *Tunnel) Write(p []byte) (n int, err error) {
	return t.ipConn.Write(p)
}

// Close closes the tunnel and all associated resources
func (t *Tunnel) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.logger.Debug("Closing MASQUE tunnel resources")
		t.cancel()
		if t.ipConn != nil {
			t.logger.Debug("Closing Connect-IP connection")
			err = t.ipConn.Close()
		}
		if t.udpConn != nil {
			t.logger.Debug("Closing UDP connection")
			if cerr := t.udpConn.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		if t.client != nil {
			t.logger.Debug("Closing MASQUE client")
			if cerr := t.client.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		t.logger.Info("MASQUE tunnel closed")
	})
	return err
}

// GetIPConn returns the underlying Connect-IP connection
func (t *Tunnel) GetIPConn() io.ReadWriteCloser {
	return t.ipConn
}

// LocalAddr returns the local address (not applicable for Connect-IP)
func (t *Tunnel) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   t.localAddr.Addr().AsSlice(),
		Port: int(t.localAddr.Port()),
	}
}

// RemoteAddr returns the remote WARP endpoint address
func (t *Tunnel) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   t.remoteAddr.Addr().AsSlice(),
		Port: int(t.remoteAddr.Port()),
	}
}
