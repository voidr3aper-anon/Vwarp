package masque

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strings"

	connectip "github.com/Diniboy1123/connect-ip-go"

	"github.com/bepass-org/vwarp/masque/usque/api"
	"github.com/bepass-org/vwarp/masque/usque/config"
)

// MasqueClient represents a high-level MASQUE client for vwarp
type MasqueClient struct {
	config       *MasqueConfig  // New config format
	legacyConfig *config.Config // Legacy config format (fallback)
	conn         interface{}    // Can be *net.UDPConn (HTTP/3) or *tls.Conn (HTTP/2)
	ipConn       *connectip.Conn
	logger       *slog.Logger
	endpoint     string
	sni          string
	useIPv6      bool
	isHTTP2      bool
}

// MasqueClientConfig holds configuration for creating a MASQUE client
type MasqueClientConfig struct {
	// ConfigPath is the path to the usque config file (optional if using ConfigData)
	ConfigPath string
	// ConfigData is the direct config data (optional if using ConfigPath)
	ConfigData *config.Config
	// Endpoint override (optional, uses config endpoint if not set)
	Endpoint string
	// SNI override (optional, uses default if not set)
	SNI string
	// UseIPv6 determines whether to use IPv6 endpoint
	UseIPv6 bool
	// Logger for debug/info logging
	Logger *slog.Logger
	// ConnectPort is the port to connect to (default 443)
	ConnectPort int
	// NoizeConfig is the obfuscation configuration (optional)
	NoizeConfig interface{} // accepts *noize.NoizeConfig
	// EnableNoize enables packet obfuscation
	EnableNoize bool
}

// NewMasqueClient creates a new MASQUE client
func NewMasqueClient(ctx context.Context, cfg MasqueClientConfig) (*MasqueClient, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Load or use provided config
	var masqueConfig *MasqueConfig
	var legacyConfig *config.Config
	var err error

	cfg.Logger.Debug("[DEBUG] Starting MASQUE client creation")

	if cfg.ConfigData != nil {
		cfg.Logger.Debug("[DEBUG] Using provided config data")
		legacyConfig = cfg.ConfigData
	} else if cfg.ConfigPath != "" {
		cfg.Logger.Debug("[DEBUG] Loading config from file", "path", cfg.ConfigPath)
		// Try new format first, fall back to legacy
		masqueConfig, err = LoadMasqueConfig(cfg.ConfigPath)
		if err != nil {
			// Try legacy format
			legacyConfig, err = config.LoadConfig(cfg.ConfigPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load config (tried both new and legacy formats): %w", err)
			}
		}
		cfg.Logger.Debug("[DEBUG] Config loaded successfully")
	} else {
		return nil, fmt.Errorf("either ConfigPath or ConfigData must be provided")
	}

	// Extract keys based on config format
	var privKey *ecdsa.PrivateKey
	var peerPubKey *ecdsa.PublicKey
	var endpointAddr string

	if masqueConfig != nil {
		// New format
		cfg.Logger.Debug("[DEBUG] Using new MasqueConfig format")

		privKey, err = masqueConfig.GetPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get private key: %w", err)
		}
		cfg.Logger.Debug("[DEBUG] Private key extracted successfully")

		// Try to parse peer public key from config
		peerPubKey, err = masqueConfig.GetServerPublicKey()
		if err != nil {
			// If parsing fails, disable certificate pinning (set to nil)
			cfg.Logger.Warn("Failed to parse server public key, certificate pinning disabled", "error", err)
			peerPubKey = nil
		} else {
			cfg.Logger.Debug("[DEBUG] Peer public key extracted successfully")
		}

		// Determine endpoint
		if cfg.Endpoint != "" {
			endpointAddr = cfg.Endpoint
		} else if cfg.UseIPv6 {
			endpointAddr = masqueConfig.EndpointV6
		} else {
			endpointAddr = masqueConfig.EndpointV4
		}
	} else {
		// Legacy format
		cfg.Logger.Debug("[DEBUG] Using legacy config format")

		privKey, err = legacyConfig.GetEcPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get private key: %w", err)
		}
		cfg.Logger.Debug("[DEBUG] Private key extracted successfully")

		peerPubKey, err = legacyConfig.GetEcEndpointPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get peer public key: %w", err)
		}
		cfg.Logger.Debug("[DEBUG] Peer public key extracted successfully")

		// Determine endpoint
		if cfg.Endpoint != "" {
			endpointAddr = cfg.Endpoint
		} else if cfg.UseIPv6 {
			endpointAddr = legacyConfig.EndpointV6
		} else {
			endpointAddr = legacyConfig.EndpointV4
		}
	}

	// Add port if not specified
	connectPort := 443
	if cfg.ConnectPort > 0 {
		connectPort = cfg.ConnectPort
	}
	if !strings.Contains(endpointAddr, ":") {
		endpointAddr = fmt.Sprintf("%s:%d", endpointAddr, connectPort)
	}

	// Determine SNI
	sni := cfg.SNI
	if sni == "" {
		sni = DefaultMasqueSNI
	}

	cfg.Logger.Info("Establishing MASQUE connection", "endpoint", endpointAddr, "sni", sni)
	cfg.Logger.Debug("[DEBUG] Client assigned IPs", "ipv4", masqueConfig.IPv4, "ipv6", masqueConfig.IPv6)
	cfg.Logger.Debug("[DEBUG] Connection config", "useIPv6", cfg.UseIPv6, "connectPort", connectPort, "enableNoize", cfg.EnableNoize)

	// Create MASQUE connection with HTTP/3 -> HTTP/2 fallback
	// For now, we'll pass the client IPs via a different mechanism since the API doesn't support it yet
	conn, ipConn, err := api.CreateMasqueClientWithFallback(ctx, privKey, peerPubKey, endpointAddr, sni, cfg.EnableNoize, cfg.NoizeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create MASQUE client: %w", err)
	}

	cfg.Logger.Info("MASQUE connection established successfully")

	// Determine connection type
	isHTTP2 := false
	if _, ok := conn.(*net.UDPConn); !ok {
		isHTTP2 = true
	}

	return &MasqueClient{
		config:       masqueConfig,
		legacyConfig: legacyConfig,
		conn:         conn,
		ipConn:       ipConn,
		logger:       cfg.Logger,
		endpoint:     endpointAddr,
		sni:          sni,
		useIPv6:      cfg.UseIPv6,
		isHTTP2:      isHTTP2,
	}, nil
}

// Read reads IP packets from the MASQUE tunnel
func (m *MasqueClient) Read(p []byte) (n int, err error) {
	return m.ipConn.ReadPacket(p, true)
}

// Write writes IP packets to the MASQUE tunnel
func (m *MasqueClient) Write(p []byte) (n int, err error) {
	icmp, err := m.ipConn.WritePacket(p)
	if err != nil {
		return 0, err
	}
	// Ignore ICMP for simple Write
	_ = icmp
	return len(p), nil
}

// WriteWithICMP writes IP packets to the MASQUE tunnel and returns any ICMP response
func (m *MasqueClient) WriteWithICMP(p []byte) ([]byte, error) {
	return m.ipConn.WritePacket(p)
}

// Close closes the MASQUE connection
func (m *MasqueClient) Close() error {
	var errs []error

	if m.ipConn != nil {
		if err := m.ipConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close IP connection: %w", err))
		}
	}

	// Close the underlying connection (UDP or TLS)
	if m.conn != nil {
		if udpConn, ok := m.conn.(*net.UDPConn); ok {
			if err := udpConn.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close UDP connection: %w", err))
			}
		} else if tlsConn, ok := m.conn.(*net.Conn); ok {
			if err := (*tlsConn).Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close TLS connection: %w", err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing MASQUE client: %v", errs)
	}

	return nil
}

// GetLocalAddresses returns the assigned IPv4 and IPv6 addresses
func (m *MasqueClient) GetLocalAddresses() (ipv4, ipv6 string) {
	if m.config != nil {
		return m.config.IPv4, m.config.IPv6
	}
	if m.legacyConfig != nil {
		return m.legacyConfig.IPv4, m.legacyConfig.IPv6
	}
	return "", ""
}

// GetConfig returns the underlying legacy config (for compatibility)
func (m *MasqueClient) GetConfig() *config.Config {
	return m.legacyConfig
}

// GetMasqueConfig returns the new MASQUE config
func (m *MasqueClient) GetMasqueConfig() *MasqueConfig {
	return m.config
}

// RegisterAndEnroll registers a new device and enrolls a MASQUE key
func RegisterAndEnroll(model, locale, jwt, deviceName string, acceptTos bool) (*config.Config, error) {
	// Register new account
	accountData, err := api.Register(model, locale, jwt, acceptTos)
	if err != nil {
		return nil, fmt.Errorf("failed to register: %w", err)
	}

	// Generate EC key pair for MASQUE using the api package
	privKey, pubKey, err := api.GenerateEcKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Enroll the key
	updatedAccountData, apiErr, err := api.EnrollKey(accountData, pubKey, deviceName)
	if err != nil {
		if apiErr != nil {
			return nil, fmt.Errorf("failed to enroll key: %w (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return nil, fmt.Errorf("failed to enroll key: %w", err)
	}

	// Create config
	cfg := &config.Config{
		PrivateKey: base64.StdEncoding.EncodeToString(privKey),
		// Strip port suffix from endpoints
		EndpointV4:     updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
		EndpointV6:     updatedAccountData.Config.Peers[0].Endpoint.V6[1 : len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
		EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
		License:        updatedAccountData.Account.License,
		ID:             updatedAccountData.ID,
		AccessToken:    accountData.Token,
		IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
		IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
	}

	return cfg, nil
}

// SaveConfig is a convenience function to save a config to a file
func SaveConfig(cfg *config.Config, configPath string) error {
	return cfg.SaveConfig(configPath)
}
