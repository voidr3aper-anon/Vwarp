package noize

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/voidr3aper-anon/Vwarp/masque/noize"
	"github.com/voidr3aper-anon/Vwarp/wireguard/preflightbind"
)

// UnifiedNoizeConfig represents the complete configuration for both WireGuard and MASQUE obfuscation
type UnifiedNoizeConfig struct {
	Version   string          `json:"version,omitempty"`
	WireGuard *WireGuardNoize `json:"wireguard,omitempty"`
	MASQUE    *MASQUENoize    `json:"masque,omitempty"`
	Metadata  *ConfigMetadata `json:"metadata,omitempty"`
}

// ConfigMetadata contains additional information about the configuration
type ConfigMetadata struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Author      string `json:"author,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// WireGuardNoize contains AtomicNoize configuration for WireGuard obfuscation
type WireGuardNoize struct {
	Enabled     bool                             `json:"enabled"`
	Preset      string                           `json:"preset,omitempty"`
	AtomicNoize *preflightbind.AtomicNoizeConfig `json:"atomicnoize,omitempty"`
}

// MASQUENoize contains configuration for MASQUE QUIC obfuscation
type MASQUENoize struct {
	Enabled bool               `json:"enabled"`
	Preset  string             `json:"preset,omitempty"`
	Config  *noize.NoizeConfig `json:"config,omitempty"`
}

// JunkPacketConfig represents junk packet configuration that's common between both systems
type JunkPacketConfig struct {
	Count           int           `json:"count,omitempty"`
	MinSize         int           `json:"min_size,omitempty"`
	MaxSize         int           `json:"max_size,omitempty"`
	BeforeHandshake int           `json:"before_handshake,omitempty"`
	AfterI1         int           `json:"after_i1,omitempty"`         // WireGuard specific
	DuringHandshake int           `json:"during_handshake,omitempty"` // MASQUE specific
	AfterHandshake  int           `json:"after_handshake,omitempty"`
	Interval        time.Duration `json:"interval,omitempty"`
	AllowZeroSize   bool          `json:"allow_zero_size,omitempty"`
}

// TimingConfig represents timing-related obfuscation settings
type TimingConfig struct {
	HandshakeDelay time.Duration `json:"handshake_delay,omitempty"`
	PacketDelay    time.Duration `json:"packet_delay,omitempty"`
	RandomDelay    bool          `json:"random_delay,omitempty"`
	DelayMin       time.Duration `json:"delay_min,omitempty"`
	DelayMax       time.Duration `json:"delay_max,omitempty"`
}

// SignaturePacketConfig represents signature packets for protocol imitation
type SignaturePacketConfig struct {
	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`
}

// FragmentationConfig represents packet fragmentation settings
type FragmentationConfig struct {
	Enabled bool          `json:"enabled,omitempty"`
	Size    int           `json:"size,omitempty"`
	Delay   time.Duration `json:"delay,omitempty"`
	Initial bool          `json:"initial_only,omitempty"` // Fragment only initial packets
}

// ProtocolMimicryConfig represents protocol mimicry settings
type ProtocolMimicryConfig struct {
	Protocol      string   `json:"protocol,omitempty"` // "dns", "https", "h3", "dtls", "stun"
	CustomWrapper bool     `json:"custom_wrapper,omitempty"`
	FakeALPN      []string `json:"fake_alpn,omitempty"`
	SNIFragment   int      `json:"sni_fragment,omitempty"`
}

// NewUnifiedConfig creates a new empty unified configuration
func NewUnifiedConfig() *UnifiedNoizeConfig {
	return &UnifiedNoizeConfig{
		Version: "1.0",
		Metadata: &ConfigMetadata{
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}
}

// EnableWireGuard enables WireGuard obfuscation with optional preset
func (c *UnifiedNoizeConfig) EnableWireGuard(preset string) *UnifiedNoizeConfig {
	if c.WireGuard == nil {
		c.WireGuard = &WireGuardNoize{}
	}
	c.WireGuard.Enabled = true
	if preset != "" {
		c.WireGuard.Preset = preset
	}
	return c
}

// EnableMASQUE enables MASQUE obfuscation with optional preset
func (c *UnifiedNoizeConfig) EnableMASQUE(preset string) *UnifiedNoizeConfig {
	if c.MASQUE == nil {
		c.MASQUE = &MASQUENoize{}
	}
	c.MASQUE.Enabled = true
	if preset != "" {
		c.MASQUE.Preset = preset
	}
	return c
}

// ToJSON converts the configuration to JSON
func (c *UnifiedNoizeConfig) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// FromJSON creates a configuration from JSON
func FromJSON(data []byte) (*UnifiedNoizeConfig, error) {
	var config UnifiedNoizeConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}
	return &config, nil
}

// Validate validates the configuration
func (c *UnifiedNoizeConfig) Validate() error {
	if c.Version == "" {
		c.Version = "1.0"
	}

	if c.WireGuard != nil && c.WireGuard.Enabled {
		if c.WireGuard.Preset != "" && c.WireGuard.AtomicNoize != nil {
			return fmt.Errorf("cannot specify both preset and custom AtomicNoize config")
		}
		if c.WireGuard.AtomicNoize != nil {
			if err := c.validateAtomicNoizeConfig(c.WireGuard.AtomicNoize); err != nil {
				return fmt.Errorf("invalid AtomicNoize config: %w", err)
			}
		}
	}

	if c.MASQUE != nil && c.MASQUE.Enabled {
		if c.MASQUE.Preset != "" && c.MASQUE.Config != nil {
			return fmt.Errorf("cannot specify both preset and custom MASQUE config")
		}
		if c.MASQUE.Config != nil {
			if err := c.validateMASQUEConfig(c.MASQUE.Config); err != nil {
				return fmt.Errorf("invalid MASQUE config: %w", err)
			}
		}
	}

	return nil
}

// validateAtomicNoizeConfig validates AtomicNoize configuration
func (c *UnifiedNoizeConfig) validateAtomicNoizeConfig(config *preflightbind.AtomicNoizeConfig) error {
	if config.Jc < 0 || config.Jc > 128 {
		return fmt.Errorf("junk packet count must be between 0 and 128")
	}
	if config.Jmin < 0 || config.Jmax < config.Jmin {
		return fmt.Errorf("invalid junk packet size range")
	}
	if config.JcAfterI1 < 0 || config.JcBeforeHS < 0 || config.JcAfterHS < 0 {
		return fmt.Errorf("junk packet counts cannot be negative")
	}
	if config.JcAfterI1+config.JcBeforeHS+config.JcAfterHS > config.Jc {
		return fmt.Errorf("sum of specific junk packet counts exceeds total count")
	}
	return nil
}

// validateMASQUEConfig validates MASQUE configuration
func (c *UnifiedNoizeConfig) validateMASQUEConfig(config *noize.NoizeConfig) error {
	if config.Jc < 0 || config.Jc > 20 {
		return fmt.Errorf("MASQUE junk packet count must be between 0 and 20")
	}
	if config.Jmin < 0 || config.Jmax < config.Jmin {
		return fmt.Errorf("invalid MASQUE junk packet size range")
	}
	if config.FragmentSize < 0 {
		return fmt.Errorf("fragment size cannot be negative")
	}
	return nil
}

// IsWireGuardEnabled returns true if WireGuard obfuscation is enabled
func (c *UnifiedNoizeConfig) IsWireGuardEnabled() bool {
	return c.WireGuard != nil && c.WireGuard.Enabled
}

// IsMASQUEEnabled returns true if MASQUE obfuscation is enabled
func (c *UnifiedNoizeConfig) IsMASQUEEnabled() bool {
	return c.MASQUE != nil && c.MASQUE.Enabled
}

// GetWireGuardPreset returns the WireGuard preset name
func (c *UnifiedNoizeConfig) GetWireGuardPreset() string {
	if c.WireGuard == nil {
		return ""
	}
	return c.WireGuard.Preset
}

// GetMASQUEPreset returns the MASQUE preset name
func (c *UnifiedNoizeConfig) GetMASQUEPreset() string {
	if c.MASQUE == nil {
		return ""
	}
	return c.MASQUE.Preset
}
