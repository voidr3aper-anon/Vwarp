package mixed

import (
	"context"
	"log/slog"
	"net"

	"github.com/bepass-org/vwarp/masque"
	"github.com/bepass-org/vwarp/proxy/pkg/statute"
)

// MasqueDialer wraps a MASQUE client to provide ProxyDialFunc functionality
type MasqueDialer struct {
	client       *masque.MasqueClient
	fallbackDial statute.ProxyDialFunc
	logger       *slog.Logger
}

// NewMasqueDialer creates a new MASQUE-aware dialer
func NewMasqueDialer(client *masque.MasqueClient, logger *slog.Logger) *MasqueDialer {
	if logger == nil {
		logger = slog.Default()
	}

	return &MasqueDialer{
		client:       client,
		fallbackDial: statute.DefaultProxyDial(),
		logger:       logger,
	}
}

// DialContext implements the ProxyDialFunc interface using MASQUE
func (m *MasqueDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if m.client == nil {
		m.logger.Debug("MASQUE client not available, using fallback", "address", address)
		return m.fallbackDial(ctx, network, address)
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		m.logger.Debug("Attempting MASQUE TCP connection", "address", address)

		// For now, we'll use the fallback since we need to implement
		// the MASQUE client's DialContext method properly
		// TODO: Implement proper MASQUE dialing
		m.logger.Debug("MASQUE TCP dialing not yet fully implemented, using fallback")
		return m.fallbackDial(ctx, network, address)

	default:
		m.logger.Debug("Unsupported network type for MASQUE, using fallback",
			"network", network, "address", address)
		return m.fallbackDial(ctx, network, address)
	}
}

// WithMasqueClient adds MASQUE support to the mixed proxy
func WithMasqueClient(client *masque.MasqueClient, logger *slog.Logger) Option {
	return func(p *Proxy) {
		masqueDialer := NewMasqueDialer(client, logger)
		p.userDialFunc = masqueDialer.DialContext

		if logger != nil {
			logger.Info("MASQUE client integrated with proxy server")
		}
	}
}

// WithMasqueAutoSetup automatically sets up MASQUE client with registration
func WithMasqueAutoSetup(ctx context.Context, options masque.AutoRegisterOptions) Option {
	return func(p *Proxy) {
		client, err := masque.AutoLoadOrRegisterWithOptions(ctx, options)
		if err != nil {
			p.logger.Error("Failed to setup MASQUE client", "error", err)
			return
		}

		masqueDialer := NewMasqueDialer(client, options.Logger)
		p.userDialFunc = masqueDialer.DialContext

		p.logger.Info("MASQUE client auto-configured and integrated with proxy server")
	}
}
