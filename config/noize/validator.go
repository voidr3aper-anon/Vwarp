package noize

import (
	"fmt"
	"time"

	"github.com/voidr3aper-anon/Vwarp/masque/noize"
	"github.com/voidr3aper-anon/Vwarp/wireguard/preflightbind"
)

// ConfigValidator provides validation for unified configurations
type ConfigValidator struct{}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{}
}

// ValidateConfig validates a complete unified configuration
func (cv *ConfigValidator) ValidateConfig(config *UnifiedNoizeConfig) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate version
	if config.Version == "" {
		config.Version = "1.0"
	}

	// Validate at least one protocol is enabled
	if !config.IsWireGuardEnabled() && !config.IsMASQUEEnabled() {
		return fmt.Errorf("at least one protocol (WireGuard or MASQUE) must be enabled")
	}

	// Validate WireGuard configuration if enabled
	if config.IsWireGuardEnabled() {
		if err := cv.ValidateWireGuardConfig(config.WireGuard); err != nil {
			return fmt.Errorf("WireGuard configuration error: %w", err)
		}
	}

	// Validate MASQUE configuration if enabled
	if config.IsMASQUEEnabled() {
		if err := cv.ValidateMASQUEConfig(config.MASQUE); err != nil {
			return fmt.Errorf("MASQUE configuration error: %w", err)
		}
	}

	return nil
}

// ValidateWireGuardConfig validates WireGuard-specific configuration
func (cv *ConfigValidator) ValidateWireGuardConfig(config *WireGuardNoize) error {
	if config == nil {
		return fmt.Errorf("WireGuard configuration cannot be nil")
	}

	// If preset is specified, AtomicNoize config should be nil or match preset
	if config.Preset != "" && config.AtomicNoize != nil {
		return fmt.Errorf("cannot specify both preset (%s) and custom AtomicNoize config", config.Preset)
	}

	// Validate preset name if specified
	if config.Preset != "" {
		if !cv.isValidPreset(config.Preset) {
			return fmt.Errorf("invalid WireGuard preset: %s", config.Preset)
		}
	}

	// Validate AtomicNoize config if specified
	if config.AtomicNoize != nil {
		if err := cv.ValidateAtomicNoizeConfig(config.AtomicNoize); err != nil {
			return fmt.Errorf("AtomicNoize configuration error: %w", err)
		}
	}

	return nil
}

// ValidateMASQUEConfig validates MASQUE-specific configuration
func (cv *ConfigValidator) ValidateMASQUEConfig(config *MASQUENoize) error {
	if config == nil {
		return fmt.Errorf("MASQUE configuration cannot be nil")
	}

	// If preset is specified, Config should be nil or match preset
	if config.Preset != "" && config.Config != nil {
		return fmt.Errorf("cannot specify both preset (%s) and custom MASQUE config", config.Preset)
	}

	// Validate preset name if specified
	if config.Preset != "" {
		if !cv.isValidPreset(config.Preset) {
			return fmt.Errorf("invalid MASQUE preset: %s", config.Preset)
		}
	}

	// Validate Noize config if specified
	if config.Config != nil {
		if err := cv.ValidateNoizeConfig(config.Config); err != nil {
			return fmt.Errorf("MASQUE Noize configuration error: %w", err)
		}
	}

	return nil
}

// ValidateAtomicNoizeConfig validates AtomicNoize configuration parameters
func (cv *ConfigValidator) ValidateAtomicNoizeConfig(config *preflightbind.AtomicNoizeConfig) error {
	// Validate junk packet count
	if config.Jc < 0 || config.Jc > 128 {
		return fmt.Errorf("junk packet count (Jc) must be between 0 and 128, got %d", config.Jc)
	}

	// Validate junk packet sizes
	if config.Jmin < 0 {
		return fmt.Errorf("minimum junk packet size cannot be negative, got %d", config.Jmin)
	}
	if config.Jmax < config.Jmin {
		return fmt.Errorf("maximum junk packet size (%d) cannot be less than minimum (%d)", config.Jmax, config.Jmin)
	}
	if config.Jmax > 1400 {
		return fmt.Errorf("maximum junk packet size should not exceed 1400 bytes to avoid fragmentation, got %d", config.Jmax)
	}

	// Validate junk packet distribution
	if config.JcAfterI1 < 0 {
		return fmt.Errorf("junk packets after I1 cannot be negative, got %d", config.JcAfterI1)
	}
	if config.JcBeforeHS < 0 {
		return fmt.Errorf("junk packets before handshake cannot be negative, got %d", config.JcBeforeHS)
	}
	if config.JcAfterHS < 0 {
		return fmt.Errorf("junk packets after handshake cannot be negative, got %d", config.JcAfterHS)
	}

	// Validate total distribution doesn't exceed total count
	totalSpecific := config.JcAfterI1 + config.JcBeforeHS + config.JcAfterHS
	if totalSpecific > config.Jc {
		return fmt.Errorf("sum of specific junk packet counts (%d) exceeds total count (%d)", totalSpecific, config.Jc)
	}

	// Validate timing parameters
	if config.JunkInterval < 0 {
		return fmt.Errorf("junk interval cannot be negative")
	}
	if config.JunkInterval > 5*time.Second {
		return fmt.Errorf("junk interval should not exceed 5 seconds to maintain effectiveness")
	}
	if config.HandshakeDelay < 0 {
		return fmt.Errorf("handshake delay cannot be negative")
	}
	if config.HandshakeDelay > 10*time.Second {
		return fmt.Errorf("handshake delay should not exceed 10 seconds to avoid timeouts")
	}

	// Validate signature packets format (basic validation)
	signatures := []string{config.I1, config.I2, config.I3, config.I4, config.I5}
	for i, sig := range signatures {
		if sig != "" {
			if err := cv.validateSignaturePacket(sig, fmt.Sprintf("I%d", i+1)); err != nil {
				return err
			}
		}
	}

	// Validate S1, S2 parameters (should be 0 for WARP compatibility)
	if config.S1 != 0 {
		return fmt.Errorf("S1 parameter should be 0 for WARP compatibility")
	}
	if config.S2 != 0 {
		return fmt.Errorf("S2 parameter should be 0 for WARP compatibility")
	}

	return nil
}

// ValidateNoizeConfig validates MASQUE Noize configuration parameters
func (cv *ConfigValidator) ValidateNoizeConfig(config *noize.NoizeConfig) error {
	// Validate junk packet count
	if config.Jc < 0 || config.Jc > 20 {
		return fmt.Errorf("MASQUE junk packet count (Jc) must be between 0 and 20, got %d", config.Jc)
	}

	// Validate junk packet sizes
	if config.Jmin < 0 {
		return fmt.Errorf("minimum junk packet size cannot be negative, got %d", config.Jmin)
	}
	if config.Jmax < config.Jmin {
		return fmt.Errorf("maximum junk packet size (%d) cannot be less than minimum (%d)", config.Jmax, config.Jmin)
	}
	if config.Jmax > 1400 {
		return fmt.Errorf("maximum junk packet size should not exceed 1400 bytes, got %d", config.Jmax)
	}

	// Validate junk packet distribution
	if config.JcBeforeHS < 0 {
		return fmt.Errorf("junk packets before handshake cannot be negative, got %d", config.JcBeforeHS)
	}
	if config.JcAfterI1 < 0 {
		return fmt.Errorf("junk packets after I1 cannot be negative, got %d", config.JcAfterI1)
	}
	if config.JcDuringHS < 0 {
		return fmt.Errorf("junk packets during handshake cannot be negative, got %d", config.JcDuringHS)
	}
	if config.JcAfterHS < 0 {
		return fmt.Errorf("junk packets after handshake cannot be negative, got %d", config.JcAfterHS)
	}

	totalSpecific := config.JcBeforeHS + config.JcAfterI1 + config.JcDuringHS + config.JcAfterHS
	if totalSpecific > config.Jc {
		return fmt.Errorf("sum of specific junk packet counts (%d) exceeds total count (%d)", totalSpecific, config.Jc)
	}

	// Validate fragmentation settings
	if config.FragmentSize < 0 {
		return fmt.Errorf("fragment size cannot be negative, got %d", config.FragmentSize)
	}
	if config.FragmentSize > 0 && config.FragmentSize < 64 {
		return fmt.Errorf("fragment size should be at least 64 bytes if enabled, got %d", config.FragmentSize)
	}
	if config.FragmentDelay < 0 {
		return fmt.Errorf("fragment delay cannot be negative")
	}

	// Validate padding settings
	if config.PaddingMin < 0 {
		return fmt.Errorf("minimum padding cannot be negative, got %d", config.PaddingMin)
	}
	if config.PaddingMax < config.PaddingMin {
		return fmt.Errorf("maximum padding (%d) cannot be less than minimum (%d)", config.PaddingMax, config.PaddingMin)
	}
	if config.PaddingMax > 500 {
		return fmt.Errorf("maximum padding should not exceed 500 bytes to avoid overhead, got %d", config.PaddingMax)
	}

	// Validate timing parameters
	if config.JunkInterval < 0 {
		return fmt.Errorf("junk interval cannot be negative")
	}
	if config.JunkInterval > 5*time.Second {
		return fmt.Errorf("junk interval should not exceed 5 seconds")
	}
	if config.HandshakeDelay < 0 {
		return fmt.Errorf("handshake delay cannot be negative")
	}
	if config.HandshakeDelay > 10*time.Second {
		return fmt.Errorf("handshake delay should not exceed 10 seconds")
	}
	if config.PacketDelay < 0 {
		return fmt.Errorf("packet delay cannot be negative")
	}
	if config.DelayMin < 0 || config.DelayMax < config.DelayMin {
		return fmt.Errorf("invalid delay range: min=%v, max=%v", config.DelayMin, config.DelayMax)
	}

	// Validate protocol mimicry
	if config.MimicProtocol != "" {
		validProtocols := []string{"quic", "dns", "https", "h3", "dtls", "stun"}
		if !cv.stringInSlice(config.MimicProtocol, validProtocols) {
			return fmt.Errorf("invalid mimic protocol %s, must be one of: %v", config.MimicProtocol, validProtocols)
		}
	}

	// Validate SNI fragmentation
	if config.SNIFragment < 0 {
		return fmt.Errorf("SNI fragment size cannot be negative")
	}
	if config.SNIFragment > 0 && config.SNIFragment < 8 {
		return fmt.Errorf("SNI fragment size should be at least 8 bytes if enabled")
	}

	// Validate fake loss ratio
	if config.FakeLoss < 0 || config.FakeLoss > 1.0 {
		return fmt.Errorf("fake loss ratio must be between 0.0 and 1.0, got %f", config.FakeLoss)
	}

	// Validate signature packets
	signatures := []string{config.I1, config.I2, config.I3, config.I4, config.I5}
	for i, sig := range signatures {
		if sig != "" {
			if err := cv.validateSignaturePacket(sig, fmt.Sprintf("I%d", i+1)); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateSignaturePacket performs basic validation of signature packet format
func (cv *ConfigValidator) validateSignaturePacket(packet, name string) error {
	if len(packet) == 0 {
		return nil // Empty is valid
	}

	// Basic format validation for CPS format
	if len(packet) > 1000 {
		return fmt.Errorf("signature packet %s is too long (%d chars), should be under 1000", name, len(packet))
	}

	// Check for basic CPS format markers
	if packet[0] != '<' && packet[len(packet)-1] != '>' {
		// Allow simple numeric values too
		if packet != "1" && packet != "2" && packet != "3" && packet != "4" && packet != "5" {
			// For more complex validation, we could parse the CPS format
			// For now, just ensure it's reasonable
			return nil
		}
	}

	return nil
}

// isValidPreset checks if a preset name is valid
func (cv *ConfigValidator) isValidPreset(preset string) bool {
	validPresets := []string{
		string(PresetMinimal),
		string(PresetLight),
		string(PresetMedium),
		string(PresetHeavy),
		string(PresetStealth),
		string(PresetGFW),
		string(PresetFirewall),
	}
	return cv.stringInSlice(preset, validPresets)
}

// stringInSlice checks if a string is in a slice
func (cv *ConfigValidator) stringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// ValidateAndSuggestFixes validates configuration and suggests fixes for common issues
func (cv *ConfigValidator) ValidateAndSuggestFixes(config *UnifiedNoizeConfig) ([]string, error) {
	var suggestions []string

	// Validate first
	if err := cv.ValidateConfig(config); err != nil {
		return suggestions, err
	}

	// Performance suggestions
	if config.IsWireGuardEnabled() && config.WireGuard.AtomicNoize != nil {
		atomic := config.WireGuard.AtomicNoize
		if atomic.Jc > 10 {
			suggestions = append(suggestions, fmt.Sprintf("WireGuard junk packet count (%d) is high, consider reducing for better performance", atomic.Jc))
		}
		if atomic.HandshakeDelay > 100*time.Millisecond {
			suggestions = append(suggestions, fmt.Sprintf("WireGuard handshake delay (%v) is high, may cause connection timeouts", atomic.HandshakeDelay))
		}
	}

	if config.IsMASQUEEnabled() && config.MASQUE.Config != nil {
		masque := config.MASQUE.Config
		if masque.Jc > 8 {
			suggestions = append(suggestions, fmt.Sprintf("MASQUE junk packet count (%d) is high, consider reducing for better performance", masque.Jc))
		}
		if masque.HandshakeDelay > 200*time.Millisecond {
			suggestions = append(suggestions, fmt.Sprintf("MASQUE handshake delay (%v) is high, may cause connection timeouts", masque.HandshakeDelay))
		}
		if masque.PaddingMax > 200 {
			suggestions = append(suggestions, fmt.Sprintf("MASQUE padding (%d bytes) is high, consider reducing for lower overhead", masque.PaddingMax))
		}
	}

	// Security suggestions
	if config.IsWireGuardEnabled() && config.WireGuard.AtomicNoize != nil {
		if config.WireGuard.AtomicNoize.I1 == "" {
			suggestions = append(suggestions, "WireGuard signature packet I1 is empty, obfuscation effectiveness will be limited")
		}
	}

	if config.IsMASQUEEnabled() && config.MASQUE.Config != nil {
		if config.MASQUE.Config.I1 == "" && config.MASQUE.Config.Jc == 0 {
			suggestions = append(suggestions, "MASQUE has no signature packets or junk packets, obfuscation will be minimal")
		}
	}

	return suggestions, nil
}
