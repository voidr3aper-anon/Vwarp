package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/voidr3aper-anon/Vwarp/config/noize"
)

// UnifiedConfig represents the complete application configuration
type UnifiedConfig struct {
	Version   string           `json:"version,omitempty"`
	Bind      string           `json:"bind,omitempty"`
	Endpoint  string           `json:"endpoint,omitempty"`
	Key       string           `json:"key,omitempty"`
	DNS       string           `json:"dns,omitempty"`
	TestURL   string           `json:"test_url,omitempty"`
	Proxy     string           `json:"proxy,omitempty"`
	WireGuard *WireGuardConfig `json:"wireguard,omitempty"`
	MASQUE    *MASQUEConfig    `json:"masque,omitempty"`
	Psiphon   *PsiphonConfig   `json:"psiphon,omitempty"`
	Metadata  *ConfigMetadata  `json:"metadata,omitempty"`
}

// WireGuardConfig contains WireGuard-specific settings
type WireGuardConfig struct {
	Enabled     bool             `json:"enabled"`
	Config      string           `json:"config,omitempty"` // Path to WireGuard config file
	Reserved    string           `json:"reserved,omitempty"`
	FwMark      uint32           `json:"fwmark,omitempty"`
	AtomicNoize *json.RawMessage `json:"atomicnoize,omitempty"` // AtomicNoize config
}

// MASQUEConfig contains MASQUE-specific settings
type MASQUEConfig struct {
	Enabled   bool             `json:"enabled"`
	Preferred bool             `json:"preferred,omitempty"` // Prefer MASQUE over WireGuard
	Config    *json.RawMessage `json:"config,omitempty"`    // MASQUE noize config
}

// PsiphonConfig contains Psiphon-specific settings
type PsiphonConfig struct {
	Enabled bool   `json:"enabled"`
	Country string `json:"country,omitempty"`
}

// ConfigMetadata contains additional information about the configuration
type ConfigMetadata struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Author      string `json:"author,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// LoadFromFile loads a unified configuration from a JSON file
func LoadFromFile(filepath string) (*UnifiedConfig, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filepath, err)
	}

	var config UnifiedConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", filepath, err)
	}

	return &config, nil
}

// GetNoizeConfig extracts the noize configuration from the unified config
func (uc *UnifiedConfig) GetNoizeConfig() (*noize.UnifiedNoizeConfig, error) {
	noizeConfig := &noize.UnifiedNoizeConfig{
		Version:  uc.Version,
		Metadata: (*noize.ConfigMetadata)(uc.Metadata),
	}

	// Extract WireGuard AtomicNoize config
	if uc.WireGuard != nil && uc.WireGuard.Enabled && uc.WireGuard.AtomicNoize != nil {
		noizeConfig.WireGuard = &noize.WireGuardNoize{
			Enabled: true,
		}

		// Parse AtomicNoize config from raw JSON
		if err := json.Unmarshal(*uc.WireGuard.AtomicNoize, &noizeConfig.WireGuard.AtomicNoize); err != nil {
			return nil, fmt.Errorf("failed to parse AtomicNoize config: %w", err)
		}
	}

	// Extract MASQUE noize config
	if uc.MASQUE != nil && uc.MASQUE.Enabled && uc.MASQUE.Config != nil {
		noizeConfig.MASQUE = &noize.MASQUENoize{
			Enabled: true,
		}

		// Parse MASQUE noize config from raw JSON
		if err := json.Unmarshal(*uc.MASQUE.Config, &noizeConfig.MASQUE.Config); err != nil {
			return nil, fmt.Errorf("failed to parse MASQUE noize config: %w", err)
		}
	}

	return noizeConfig, nil
}

// Validate validates the unified configuration
func (uc *UnifiedConfig) Validate() error {
	// Basic validation
	if uc.WireGuard == nil && uc.MASQUE == nil {
		return fmt.Errorf("at least one of 'wireguard' or 'masque' must be configured")
	}

	if uc.WireGuard != nil && uc.WireGuard.Enabled && uc.WireGuard.Config == "" && uc.Endpoint == "" {
		return fmt.Errorf("wireguard requires either 'config' file path or 'endpoint'")
	}

	return nil
}
