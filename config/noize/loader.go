package noize

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/voidr3aper-anon/Vwarp/masque/noize"
	"github.com/voidr3aper-anon/Vwarp/wireguard/preflightbind"
)

// ConfigLoader handles loading and merging configurations from various sources
type ConfigLoader struct {
	presetManager *PresetManager
}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{
		presetManager: NewPresetManager(),
	}
}

// LoadFromFile loads configuration from a JSON file
func (cl *ConfigLoader) LoadFromFile(filepath string) (*UnifiedNoizeConfig, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filepath, err)
	}

	config, err := FromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", filepath, err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config in file %s: %w", filepath, err)
	}

	return config, nil
}

// LoadFromPreset loads configuration from a built-in preset
func (cl *ConfigLoader) LoadFromPreset(presetName string) (*UnifiedNoizeConfig, error) {
	return cl.presetManager.GetPreset(presetName)
}

// LoadMixed loads configuration by merging preset with custom config file
func (cl *ConfigLoader) LoadMixed(presetName string, configPath string) (*UnifiedNoizeConfig, error) {
	// Load base preset
	baseConfig, err := cl.LoadFromPreset(presetName)
	if err != nil {
		return nil, fmt.Errorf("failed to load preset %s: %w", presetName, err)
	}

	// If no custom config provided, return preset
	if configPath == "" {
		return baseConfig, nil
	}

	// Load custom config
	customConfig, err := cl.LoadFromFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load custom config: %w", err)
	}

	// Merge custom over preset
	merged := cl.MergeConfigs(baseConfig, customConfig)
	return merged, nil
}

// MergeConfigs merges two configurations, with override taking precedence
func (cl *ConfigLoader) MergeConfigs(base, override *UnifiedNoizeConfig) *UnifiedNoizeConfig {
	merged := cl.deepCopy(base)

	// Merge metadata
	if override.Metadata != nil {
		if merged.Metadata == nil {
			merged.Metadata = &ConfigMetadata{}
		}
		cl.mergeMetadata(merged.Metadata, override.Metadata)
	}

	// Merge WireGuard config
	if override.WireGuard != nil {
		if merged.WireGuard == nil {
			merged.WireGuard = &WireGuardNoize{}
		}
		cl.mergeWireGuardConfig(merged.WireGuard, override.WireGuard)
	}

	// Merge MASQUE config
	if override.MASQUE != nil {
		if merged.MASQUE == nil {
			merged.MASQUE = &MASQUENoize{}
		}
		cl.mergeMASQUEConfig(merged.MASQUE, override.MASQUE)
	}

	return merged
}

// mergeMetadata merges metadata, with override taking precedence
func (cl *ConfigLoader) mergeMetadata(base, override *ConfigMetadata) {
	if override.Name != "" {
		base.Name = override.Name
	}
	if override.Description != "" {
		base.Description = override.Description
	}
	if override.Author != "" {
		base.Author = override.Author
	}
	if override.CreatedAt != "" {
		base.CreatedAt = override.CreatedAt
	}
}

// mergeWireGuardConfig merges WireGuard configurations
func (cl *ConfigLoader) mergeWireGuardConfig(base, override *WireGuardNoize) {
	// Override enabled flag
	base.Enabled = override.Enabled

	// Override preset if specified
	if override.Preset != "" {
		base.Preset = override.Preset
	}

	// Merge AtomicNoize config
	if override.AtomicNoize != nil {
		if base.AtomicNoize == nil {
			base.AtomicNoize = &preflightbind.AtomicNoizeConfig{}
		}
		cl.mergeAtomicNoizeConfig(base.AtomicNoize, override.AtomicNoize)
	}
}

// mergeMASQUEConfig merges MASQUE configurations
func (cl *ConfigLoader) mergeMASQUEConfig(base, override *MASQUENoize) {
	// Override enabled flag
	base.Enabled = override.Enabled

	// Override preset if specified
	if override.Preset != "" {
		base.Preset = override.Preset
	}

	// Merge Noize config
	if override.Config != nil {
		if base.Config == nil {
			base.Config = &noize.NoizeConfig{}
		}
		cl.mergeNoizeConfig(base.Config, override.Config)
	}
}

// mergeAtomicNoizeConfig merges AtomicNoize configurations
func (cl *ConfigLoader) mergeAtomicNoizeConfig(base, override *preflightbind.AtomicNoizeConfig) {
	if override.I1 != "" {
		base.I1 = override.I1
	}
	if override.I2 != "" {
		base.I2 = override.I2
	}
	if override.I3 != "" {
		base.I3 = override.I3
	}
	if override.I4 != "" {
		base.I4 = override.I4
	}
	if override.I5 != "" {
		base.I5 = override.I5
	}
	if override.S1 != 0 {
		base.S1 = override.S1
	}
	if override.S2 != 0 {
		base.S2 = override.S2
	}
	if override.Jc != 0 {
		base.Jc = override.Jc
	}
	if override.Jmin != 0 {
		base.Jmin = override.Jmin
	}
	if override.Jmax != 0 {
		base.Jmax = override.Jmax
	}
	if override.JcAfterI1 != 0 {
		base.JcAfterI1 = override.JcAfterI1
	}
	if override.JcBeforeHS != 0 {
		base.JcBeforeHS = override.JcBeforeHS
	}
	if override.JcAfterHS != 0 {
		base.JcAfterHS = override.JcAfterHS
	}
	if override.JunkInterval != 0 {
		base.JunkInterval = override.JunkInterval
	}
	base.AllowZeroSize = override.AllowZeroSize
	if override.HandshakeDelay != 0 {
		base.HandshakeDelay = override.HandshakeDelay
	}
}

// mergeNoizeConfig merges MASQUE Noize configurations
func (cl *ConfigLoader) mergeNoizeConfig(base, override *noize.NoizeConfig) {
	if override.I1 != "" {
		base.I1 = override.I1
	}
	if override.I2 != "" {
		base.I2 = override.I2
	}
	if override.I3 != "" {
		base.I3 = override.I3
	}
	if override.I4 != "" {
		base.I4 = override.I4
	}
	if override.I5 != "" {
		base.I5 = override.I5
	}
	if override.FragmentSize != 0 {
		base.FragmentSize = override.FragmentSize
	}
	base.FragmentInitial = override.FragmentInitial
	if override.FragmentDelay != 0 {
		base.FragmentDelay = override.FragmentDelay
	}
	if override.PaddingMin != 0 {
		base.PaddingMin = override.PaddingMin
	}
	if override.PaddingMax != 0 {
		base.PaddingMax = override.PaddingMax
	}
	base.RandomPadding = override.RandomPadding
	if override.Jc != 0 {
		base.Jc = override.Jc
	}
	if override.Jmin != 0 {
		base.Jmin = override.Jmin
	}
	if override.Jmax != 0 {
		base.Jmax = override.Jmax
	}
	if override.JcBeforeHS != 0 {
		base.JcBeforeHS = override.JcBeforeHS
	}
	if override.JcAfterI1 != 0 {
		base.JcAfterI1 = override.JcAfterI1
	}
	if override.JcDuringHS != 0 {
		base.JcDuringHS = override.JcDuringHS
	}
	if override.JcAfterHS != 0 {
		base.JcAfterHS = override.JcAfterHS
	}
	if override.JunkInterval != 0 {
		base.JunkInterval = override.JunkInterval
	}
	base.JunkRandom = override.JunkRandom
	if override.MimicProtocol != "" {
		base.MimicProtocol = override.MimicProtocol
	}
	base.CustomWrapper = override.CustomWrapper
	if override.HandshakeDelay != 0 {
		base.HandshakeDelay = override.HandshakeDelay
	}
	if override.PacketDelay != 0 {
		base.PacketDelay = override.PacketDelay
	}
	base.RandomDelay = override.RandomDelay
	if override.DelayMin != 0 {
		base.DelayMin = override.DelayMin
	}
	if override.DelayMax != 0 {
		base.DelayMax = override.DelayMax
	}
	base.SNIFragmentation = override.SNIFragmentation
	if override.SNIFragment != 0 {
		base.SNIFragment = override.SNIFragment
	}
	if len(override.FakeALPN) > 0 {
		base.FakeALPN = override.FakeALPN
	}
	base.ReversedOrder = override.ReversedOrder
	base.DuplicatePackets = override.DuplicatePackets
	base.AllowZeroSize = override.AllowZeroSize
	base.UseTimestamp = override.UseTimestamp
	base.UseNonce = override.UseNonce
	base.RandomizeInitial = override.RandomizeInitial
	if override.FakeLoss != 0 {
		base.FakeLoss = override.FakeLoss
	}
}

// deepCopy creates a deep copy of a configuration using JSON marshaling
func (cl *ConfigLoader) deepCopy(src *UnifiedNoizeConfig) *UnifiedNoizeConfig {
	data, _ := json.Marshal(src)
	var dst UnifiedNoizeConfig
	json.Unmarshal(data, &dst)
	return &dst
}

// SaveToFile saves a configuration to a JSON file
func (cl *ConfigLoader) SaveToFile(config *UnifiedNoizeConfig, filepath string) error {
	// Ensure directory exists
	dir := filepath
	if !strings.HasSuffix(filepath, "/") && !strings.HasSuffix(filepath, "\\") {
		dir = filepath[:strings.LastIndexAny(filepath, "/\\")]
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	data, err := config.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", filepath, err)
	}

	return nil
}

// ExportPresetToFile exports a preset configuration to a JSON file for customization
func (cl *ConfigLoader) ExportPresetToFile(presetName, filepath string) error {
	config, err := cl.LoadFromPreset(presetName)
	if err != nil {
		return err
	}

	// Add export metadata
	if config.Metadata == nil {
		config.Metadata = &ConfigMetadata{}
	}
	config.Metadata.Description = fmt.Sprintf("Exported %s preset for customization", presetName)

	return cl.SaveToFile(config, filepath)
}

// GetAvailablePresets returns list of available presets
func (cl *ConfigLoader) GetAvailablePresets() []string {
	return cl.presetManager.GetAvailablePresets()
}

// GetPresetDescription returns description of a preset
func (cl *ConfigLoader) GetPresetDescription(presetName string) string {
	return cl.presetManager.GetPresetDescription(presetName)
}

// AutoDetectConfigPath attempts to find a configuration file in common locations
func (cl *ConfigLoader) AutoDetectConfigPath() string {
	commonPaths := []string{
		"vwarp.json",
		"config.json",
		"noize.json",
		"config/vwarp.json",
		"config/noize.json",
		".vwarp/config.json",
		filepath.Join(os.Getenv("HOME"), ".vwarp", "config.json"),
		filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "vwarp", "config.json"),
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}
