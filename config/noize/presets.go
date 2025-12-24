package noize

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/voidr3aper-anon/Vwarp/masque/noize"
	"github.com/voidr3aper-anon/Vwarp/wireguard/preflightbind"
)

// PresetType represents the type of preset configuration
type PresetType string

const (
	PresetMinimal  PresetType = "minimal"
	PresetLight    PresetType = "light"
	PresetMedium   PresetType = "medium"
	PresetHeavy    PresetType = "heavy"
	PresetStealth  PresetType = "stealth"
	PresetGFW      PresetType = "gfw"
	PresetFirewall PresetType = "firewall"
)

// PresetManager manages built-in and custom presets
type PresetManager struct {
	builtinPresets map[string]*UnifiedNoizeConfig
}

// NewPresetManager creates a new preset manager with built-in presets
func NewPresetManager() *PresetManager {
	pm := &PresetManager{
		builtinPresets: make(map[string]*UnifiedNoizeConfig),
	}
	pm.loadBuiltinPresets()
	return pm
}

// loadBuiltinPresets initializes all built-in preset configurations
func (pm *PresetManager) loadBuiltinPresets() {
	presets := map[string]*UnifiedNoizeConfig{
		string(PresetMinimal):  pm.createMinimalPreset(),
		string(PresetLight):    pm.createLightPreset(),
		string(PresetMedium):   pm.createMediumPreset(),
		string(PresetHeavy):    pm.createHeavyPreset(),
		string(PresetStealth):  pm.createStealthPreset(),
		string(PresetGFW):      pm.createGFWPreset(),
		string(PresetFirewall): pm.createFirewallPreset(),
	}

	for name, config := range presets {
		pm.builtinPresets[name] = config
	}
}

// GetPreset returns a preset configuration by name
func (pm *PresetManager) GetPreset(name string) (*UnifiedNoizeConfig, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if preset, exists := pm.builtinPresets[name]; exists {
		// Return a deep copy to prevent modification of built-in presets
		return pm.deepCopyConfig(preset), nil
	}
	return nil, fmt.Errorf("unknown preset: %s", name)
}

// GetAvailablePresets returns a list of all available preset names
func (pm *PresetManager) GetAvailablePresets() []string {
	presets := make([]string, 0, len(pm.builtinPresets))
	for name := range pm.builtinPresets {
		presets = append(presets, name)
	}
	return presets
}

// createMinimalPreset creates minimal obfuscation configuration
func (pm *PresetManager) createMinimalPreset() *UnifiedNoizeConfig {
	config := NewUnifiedConfig()
	config.Metadata.Name = "Minimal"
	config.Metadata.Description = "Minimal obfuscation, maximum performance"

	// WireGuard minimal
	config.WireGuard = &WireGuardNoize{
		Enabled: true,
		Preset:  "minimal",
		AtomicNoize: &preflightbind.AtomicNoizeConfig{
			I1:             "", // No signature packets
			Jc:             0,  // No junk packets
			Jmin:           0,
			Jmax:           0,
			JcAfterI1:      0,
			JcBeforeHS:     0,
			JcAfterHS:      0,
			JunkInterval:   0,
			AllowZeroSize:  false,
			HandshakeDelay: 0,
		},
	}

	// MASQUE minimal
	config.MASQUE = &MASQUENoize{
		Enabled: true,
		Preset:  "minimal",
		Config: &noize.NoizeConfig{
			Jc:              0,
			Jmin:            0,
			Jmax:            0,
			JcBeforeHS:      0,
			JcAfterI1:       0,
			JcDuringHS:      0,
			JcAfterHS:       0,
			JunkInterval:    0,
			FragmentInitial: false,
			FragmentSize:    0,
			PaddingMin:      0,
			PaddingMax:      0,
			HandshakeDelay:  0,
		},
	}

	return config
}

// createLightPreset creates light obfuscation configuration
func (pm *PresetManager) createLightPreset() *UnifiedNoizeConfig {
	config := NewUnifiedConfig()
	config.Metadata.Name = "Light"
	config.Metadata.Description = "Light obfuscation, good performance, basic DPI evasion"

	// WireGuard light
	config.WireGuard = &WireGuardNoize{
		Enabled: true,
		Preset:  "light",
		AtomicNoize: &preflightbind.AtomicNoizeConfig{
			I1:             "<b 0c0d0e0f>", // Simple signature
			Jc:             2,
			Jmin:           20,
			Jmax:           50,
			JcAfterI1:      1,
			JcBeforeHS:     1,
			JcAfterHS:      0,
			JunkInterval:   10 * time.Millisecond,
			AllowZeroSize:  false,
			HandshakeDelay: 5 * time.Millisecond,
		},
	}

	// MASQUE light
	config.MASQUE = &MASQUENoize{
		Enabled: true,
		Preset:  "light",
		Config: &noize.NoizeConfig{
			I1:              "<b 0d0a0d0a>",
			Jc:              2,
			Jmin:            20,
			Jmax:            50,
			JcBeforeHS:      2,
			JcAfterI1:       0,
			JcDuringHS:      0,
			JcAfterHS:       0,
			JunkInterval:    5 * time.Millisecond,
			FragmentInitial: false,
			FragmentSize:    0,
			PaddingMin:      0,
			PaddingMax:      0,
			HandshakeDelay:  10 * time.Millisecond,
			MimicProtocol:   "quic",
		},
	}

	return config
}

// createMediumPreset creates medium obfuscation configuration
func (pm *PresetManager) createMediumPreset() *UnifiedNoizeConfig {
	config := NewUnifiedConfig()
	config.Metadata.Name = "Medium"
	config.Metadata.Description = "Balanced obfuscation and performance"

	// WireGuard medium
	config.WireGuard = &WireGuardNoize{
		Enabled: true,
		Preset:  "medium",
		AtomicNoize: &preflightbind.AtomicNoizeConfig{
			I1:             "<b 0xc200><t><r 16>",
			Jc:             4,
			Jmin:           40,
			Jmax:           70,
			JcAfterI1:      1,
			JcBeforeHS:     2,
			JcAfterHS:      1,
			JunkInterval:   10 * time.Millisecond,
			AllowZeroSize:  false,
			HandshakeDelay: 10 * time.Millisecond,
		},
	}

	// MASQUE medium
	config.MASQUE = &MASQUENoize{
		Enabled: true,
		Preset:  "medium",
		Config: &noize.NoizeConfig{
			I1:              "<b 0d0a0d0a><t><r 16>",
			Jc:              3,
			Jmin:            40,
			Jmax:            80,
			JcBeforeHS:      2,
			JcAfterI1:       1,
			JcDuringHS:      0,
			JcAfterHS:       0,
			JunkInterval:    10 * time.Millisecond,
			FragmentInitial: true,
			FragmentSize:    512,
			FragmentDelay:   2 * time.Millisecond,
			PaddingMin:      16,
			PaddingMax:      32,
			RandomPadding:   true,
			HandshakeDelay:  15 * time.Millisecond,
			MimicProtocol:   "h3",
		},
	}

	return config
}

// createHeavyPreset creates heavy obfuscation configuration
func (pm *PresetManager) createHeavyPreset() *UnifiedNoizeConfig {
	config := NewUnifiedConfig()
	config.Metadata.Name = "Heavy"
	config.Metadata.Description = "Heavy obfuscation, higher latency, strong DPI evasion"

	// WireGuard heavy
	config.WireGuard = &WireGuardNoize{
		Enabled: true,
		Preset:  "heavy",
		AtomicNoize: &preflightbind.AtomicNoizeConfig{
			I1:             "<b 0xc200><t><r 32><p 64>",
			I2:             "<r 16>",
			I3:             "<r 24>",
			Jc:             8,
			Jmin:           60,
			Jmax:           120,
			JcAfterI1:      2,
			JcBeforeHS:     3,
			JcAfterHS:      3,
			JunkInterval:   15 * time.Millisecond,
			AllowZeroSize:  false,
			HandshakeDelay: 25 * time.Millisecond,
		},
	}

	// MASQUE heavy
	config.MASQUE = &MASQUENoize{
		Enabled: true,
		Preset:  "heavy",
		Config: &noize.NoizeConfig{
			I1:              "<b 0d0a0d0a><t><r 32><p 64>",
			I2:              "<r 16>",
			I3:              "<r 24>",
			Jc:              6,
			Jmin:            64,
			Jmax:            128,
			JcBeforeHS:      3,
			JcAfterI1:       1,
			JcDuringHS:      1,
			JcAfterHS:       1,
			JunkInterval:    20 * time.Millisecond,
			JunkRandom:      true,
			FragmentInitial: true,
			FragmentSize:    256,
			FragmentDelay:   5 * time.Millisecond,
			PaddingMin:      32,
			PaddingMax:      128,
			RandomPadding:   true,
			HandshakeDelay:  50 * time.Millisecond,
			RandomDelay:     true,
			DelayMin:        5 * time.Millisecond,
			DelayMax:        25 * time.Millisecond,
			MimicProtocol:   "https",
		},
	}

	return config
}

// createStealthPreset creates stealth obfuscation configuration
func (pm *PresetManager) createStealthPreset() *UnifiedNoizeConfig {
	config := NewUnifiedConfig()
	config.Metadata.Name = "Stealth"
	config.Metadata.Description = "Maximum stealth, advanced protocol mimicry"

	// WireGuard stealth
	config.WireGuard = &WireGuardNoize{
		Enabled: true,
		Preset:  "stealth",
		AtomicNoize: &preflightbind.AtomicNoizeConfig{
			I1:             "<b 0xc200><t><r 48><p 128>",
			I2:             "<r 32><t>",
			I3:             "<r 16><p 32>",
			I4:             "<r 24>",
			Jc:             12,
			Jmin:           80,
			Jmax:           200,
			JcAfterI1:      3,
			JcBeforeHS:     4,
			JcAfterHS:      5,
			JunkInterval:   25 * time.Millisecond,
			AllowZeroSize:  false,
			HandshakeDelay: 50 * time.Millisecond,
		},
	}

	// MASQUE stealth
	config.MASQUE = &MASQUENoize{
		Enabled: true,
		Preset:  "stealth",
		Config: &noize.NoizeConfig{
			I1:               "<b 0d0a0d0a><t><r 48><p 128>",
			I2:               "<r 32><t>",
			I3:               "<r 16><p 32>",
			I4:               "<r 24>",
			Jc:               8,
			Jmin:             100,
			Jmax:             256,
			JcBeforeHS:       4,
			JcAfterI1:        1,
			JcDuringHS:       2,
			JcAfterHS:        1,
			JunkInterval:     30 * time.Millisecond,
			JunkRandom:       true,
			FragmentInitial:  true,
			FragmentSize:     200,
			FragmentDelay:    10 * time.Millisecond,
			PaddingMin:       64,
			PaddingMax:       200,
			RandomPadding:    true,
			HandshakeDelay:   100 * time.Millisecond,
			RandomDelay:      true,
			DelayMin:         10 * time.Millisecond,
			DelayMax:         50 * time.Millisecond,
			MimicProtocol:    "dtls",
			SNIFragmentation: true,
			SNIFragment:      32,
			UseTimestamp:     true,
			UseNonce:         true,
		},
	}

	return config
}

// createGFWPreset creates Great Firewall bypass configuration
func (pm *PresetManager) createGFWPreset() *UnifiedNoizeConfig {
	config := NewUnifiedConfig()
	config.Metadata.Name = "GFW"
	config.Metadata.Description = "Optimized for Great Firewall bypass"

	// WireGuard GFW
	config.WireGuard = &WireGuardNoize{
		Enabled: true,
		Preset:  "gfw",
		AtomicNoize: &preflightbind.AtomicNoizeConfig{
			I1:             "<b 0x16030100><r 32><t>", // TLS-like signature
			I2:             "<r 16><b 0x140303>",
			Jc:             6,
			Jmin:           50,
			Jmax:           100,
			JcAfterI1:      1,
			JcBeforeHS:     3,
			JcAfterHS:      2,
			JunkInterval:   20 * time.Millisecond,
			AllowZeroSize:  false,
			HandshakeDelay: 30 * time.Millisecond,
		},
	}

	// MASQUE GFW
	config.MASQUE = &MASQUENoize{
		Enabled: true,
		Preset:  "gfw",
		Config: &noize.NoizeConfig{
			I1:               "<b 16030100><r 32><t>", // TLS ClientHello mimicry
			I2:               "<r 16><b 140303>",
			Jc:               5,
			Jmin:             64,
			Jmax:             120,
			JcBeforeHS:       3,
			JcAfterI1:        1,
			JcDuringHS:       1,
			JcAfterHS:        0,
			JunkInterval:     25 * time.Millisecond,
			JunkRandom:       true,
			FragmentInitial:  true,
			FragmentSize:     300,
			FragmentDelay:    8 * time.Millisecond,
			PaddingMin:       32,
			PaddingMax:       80,
			RandomPadding:    true,
			HandshakeDelay:   40 * time.Millisecond,
			RandomDelay:      true,
			DelayMin:         5 * time.Millisecond,
			DelayMax:         20 * time.Millisecond,
			MimicProtocol:    "https",
			SNIFragmentation: true,
			SNIFragment:      16,
			UseTimestamp:     false, // Avoid fingerprinting
			UseNonce:         true,
			RandomizeInitial: true,
		},
	}

	return config
}

// createFirewallPreset creates corporate firewall bypass configuration
func (pm *PresetManager) createFirewallPreset() *UnifiedNoizeConfig {
	config := NewUnifiedConfig()
	config.Metadata.Name = "Firewall"
	config.Metadata.Description = "Corporate firewall circumvention"

	// WireGuard firewall
	config.WireGuard = &WireGuardNoize{
		Enabled: true,
		Preset:  "firewall",
		AtomicNoize: &preflightbind.AtomicNoizeConfig{
			I1:             "<b 0x45000028><r 20>", // IP header mimicry
			Jc:             3,
			Jmin:           30,
			Jmax:           60,
			JcAfterI1:      1,
			JcBeforeHS:     1,
			JcAfterHS:      1,
			JunkInterval:   15 * time.Millisecond,
			AllowZeroSize:  false,
			HandshakeDelay: 20 * time.Millisecond,
		},
	}

	// MASQUE firewall
	config.MASQUE = &MASQUENoize{
		Enabled: true,
		Preset:  "firewall",
		Config: &noize.NoizeConfig{
			I1:              "<b 45000028><r 20>", // IP header mimicry
			Jc:              4,
			Jmin:            32,
			Jmax:            64,
			JcBeforeHS:      2,
			JcAfterI1:       1,
			JcDuringHS:      1,
			JcAfterHS:       0,
			JunkInterval:    12 * time.Millisecond,
			FragmentInitial: false, // Avoid fragmentation detection
			PaddingMin:      16,
			PaddingMax:      48,
			HandshakeDelay:  25 * time.Millisecond,
			MimicProtocol:   "stun", // STUN is often allowed
		},
	}

	return config
}

// deepCopyConfig creates a deep copy of a configuration
func (pm *PresetManager) deepCopyConfig(src *UnifiedNoizeConfig) *UnifiedNoizeConfig {
	data, _ := json.Marshal(src)
	var dst UnifiedNoizeConfig
	json.Unmarshal(data, &dst)
	return &dst
}

// GetPresetDescription returns a description of the specified preset
func (pm *PresetManager) GetPresetDescription(name string) string {
	preset, err := pm.GetPreset(name)
	if err != nil {
		return ""
	}
	if preset.Metadata != nil {
		return preset.Metadata.Description
	}
	return ""
}
