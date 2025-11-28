package masque

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

// MasqueConfig holds the configuration for connecting to Cloudflare WARP via MASQUE
type MasqueConfig struct {
	// Cloudflare WARP MASQUE configuration (compatible with usque)
	PrivateKey     string `json:"private_key"`      // Base64 encoded ECDSA private key
	EndpointV4     string `json:"endpoint_v4"`      // IPv4 endpoint
	EndpointV6     string `json:"endpoint_v6"`      // IPv6 endpoint
	EndpointPubKey string `json:"endpoint_pub_key"` // PEM encoded server public key
	License        string `json:"license"`          // Cloudflare license
	ID             string `json:"id"`               // Device ID
	AccessToken    string `json:"access_token"`     // API access token
	IPv4           string `json:"ipv4"`             // Assigned IPv4 address
	IPv6           string `json:"ipv6"`             // Assigned IPv6 address

	// Legacy fields for compatibility
	ServerURL    string         `json:"server_url,omitempty"`
	WarpEndpoint netip.AddrPort `json:"warp_endpoint,omitempty"`
	TLSConfig    *tls.Config    `json:"-"` // Not serialized
	Identity     *WarpIdentity  `json:"-"` // Not serialized
	SNI          string         `json:"sni,omitempty"`
}

// WarpIdentity represents a WARP account identity for use with MASQUE (legacy)
type WarpIdentity struct {
	PrivateKey string
	PublicKey  string
	IPv4       netip.Addr
	IPv6       netip.Addr
	ClientID   string
	Token      string
	AccountID  string
	LicenseKey string
}

// SaveToFile saves the MASQUE configuration to a JSON file
func (c *MasqueConfig) SaveToFile(path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to JSON with proper formatting
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// LoadMasqueConfig loads a MASQUE configuration from a JSON file
func LoadMasqueConfig(path string) (*MasqueConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config MasqueConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// GetPrivateKey decodes and returns the ECDSA private key
func (c *MasqueConfig) GetPrivateKey() (*ecdsa.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Parse ASN.1 DER encoded private key (standard format)
	privKey, err := x509.ParseECPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ASN.1 private key: %w", err)
	}

	return privKey, nil
}

// GetServerPublicKey decodes and returns the server's ECDSA public key
func (c *MasqueConfig) GetServerPublicKey() (*ecdsa.PublicKey, error) {
	if c.EndpointPubKey == "" {
		return nil, fmt.Errorf("endpoint public key is empty")
	}

	// Parse PEM-encoded public key
	return ParseECPublicKey([]byte(c.EndpointPubKey))
}

// Validate checks if the MASQUE configuration is valid
func (c *MasqueConfig) Validate() error {
	if c.PrivateKey == "" {
		return fmt.Errorf("private key is required")
	}

	if c.EndpointV4 == "" && c.EndpointV6 == "" {
		return fmt.Errorf("at least one endpoint (IPv4 or IPv6) is required")
	}

	if c.ID == "" {
		return fmt.Errorf("device ID is required")
	}

	if c.AccessToken == "" {
		return fmt.Errorf("access token is required")
	}

	if c.Identity.PrivateKey == "" {
		return fmt.Errorf("private key is required")
	}

	if c.Identity.PublicKey == "" {
		return fmt.Errorf("public key is required")
	}

	return nil
}

// DefaultTLSConfig returns a default TLS configuration for MASQUE
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Skip verification for testing
		NextProtos:         []string{"h3"},
		ServerName:         ConnectSNI,
	}
}

// DefaultSNI returns the default SNI for Cloudflare WARP MASQUE
func DefaultSNI() string {
	return ConnectSNI
}
