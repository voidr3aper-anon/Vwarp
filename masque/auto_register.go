package masque

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/bepass-org/vwarp/masque/usque/config"
)

// AutoLoadOrRegister automatically loads an existing MASQUE config or registers a new device
// This mimics the behavior of masque-plus and wgcf for seamless user experience
func AutoLoadOrRegister(ctx context.Context, configPath, deviceName string, logger *slog.Logger) (*MasqueClient, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Info("No MASQUE config found, registering new device", "path", configPath)

		// Create directory if needed
		dir := filepath.Dir(configPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create config directory: %w", err)
		}

		// Auto-register
		cfg, err := RegisterAndEnroll(
			DefaultModel,
			DefaultLocale,
			"", // No team token
			deviceName,
			true, // Auto-accept TOS
		)
		if err != nil {
			return nil, fmt.Errorf("auto-registration failed: %w", err)
		}

		// Save config
		if err := SaveConfig(cfg, configPath); err != nil {
			return nil, fmt.Errorf("failed to save config: %w", err)
		}

		logger.Info("MASQUE device registered successfully",
			"path", configPath,
			"ipv4", cfg.IPv4,
			"ipv6", cfg.IPv6,
		)
	} else {
		logger.Info("Using existing MASQUE config", "path", configPath)
	}

	// Create and return client
	return NewMasqueClientFromConfig(ctx, MasqueClientConfig{
		ConfigPath: configPath,
		Logger:     logger,
	})
}

// AutoLoadOrRegisterWithOptions provides more control over auto-registration
func AutoLoadOrRegisterWithOptions(ctx context.Context, opts AutoRegisterOptions) (*MasqueClient, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = GetDefaultConfigPath()
	}

	// Check if config exists and force renew if requested
	needsRegistration := opts.ForceRenew
	if !needsRegistration {
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			needsRegistration = true
		}
	}

	if needsRegistration {
		if opts.ForceRenew {
			logger.Info("Force renewal requested, re-registering device")
		} else {
			logger.Info("No config found, registering new device")
		}

		// Create directory if needed
		dir := filepath.Dir(configPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create config directory: %w", err)
		}

		deviceName := opts.DeviceName
		if deviceName == "" {
			deviceName = "vwarp"
		}

		model := opts.Model
		if model == "" {
			model = DefaultModel
		}

		locale := opts.Locale
		if locale == "" {
			locale = DefaultLocale
		}

		// Auto-register using new Cloudflare registration system
		cr := NewCloudflareRegistration()
		cfg, err := cr.RegisterAndEnroll(ctx, model, locale, deviceName)
		if err != nil {
			return nil, fmt.Errorf("auto-registration failed: %w", err)
		}

		// Save config
		if err := cfg.SaveToFile(configPath); err != nil {
			return nil, fmt.Errorf("failed to save config: %w", err)
		}

		logger.Info("MASQUE device registered successfully",
			"path", configPath,
			"ipv4", cfg.IPv4,
			"ipv6", cfg.IPv6,
			"license", cfg.License,
		)
	}

	// Load config and create client
	clientConfig := MasqueClientConfig{
		ConfigPath:  configPath,
		Endpoint:    opts.Endpoint,
		SNI:         opts.SNI,
		UseIPv6:     opts.UseIPv6,
		Logger:      logger,
		ConnectPort: opts.ConnectPort,
		EnableNoize: opts.EnableNoize,
		NoizeConfig: opts.NoizeConfig,
	}

	return NewMasqueClientFromConfig(ctx, clientConfig)
}

// Use MasqueClientConfig from usque_client.go to avoid duplication

// NewMasqueClientFromConfig creates a MASQUE client from a config file (wrapper for NewMasqueClient)
func NewMasqueClientFromConfig(ctx context.Context, cfg MasqueClientConfig) (*MasqueClient, error) {
	// Use the existing NewMasqueClient function
	return NewMasqueClient(ctx, cfg)
}

// AutoRegisterOptions provides options for automatic registration
type AutoRegisterOptions struct {
	// ConfigPath is the path to the config file (default: platform-specific via GetDefaultConfigPath())
	ConfigPath string

	// DeviceName is the name to register the device with (default: "vwarp")
	DeviceName string

	// Model is the device model (default: "PC")
	Model string

	// Locale is the locale to use (default: "en_US")
	Locale string

	// TeamToken is the optional Cloudflare team token
	TeamToken string

	// ForceRenew forces re-registration even if config exists
	ForceRenew bool

	// Endpoint override (optional)
	Endpoint string

	// SNI override (optional)
	SNI string

	// UseIPv6 determines whether to use IPv6 endpoint
	UseIPv6 bool

	// ConnectPort is the port to connect to (default 443)
	ConnectPort int

	// Logger for debug/info logging
	Logger *slog.Logger

	// EnableNoize enables packet obfuscation
	EnableNoize bool

	// NoizeConfig is the obfuscation configuration (optional)
	NoizeConfig interface{} // accepts *noize.NoizeConfig
}

// UpdateLicenseIfNeeded updates the license key if it differs from the config
// This mimics wgcf's license update behavior
func UpdateLicenseIfNeeded(configPath, newLicense string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	if newLicense == "" {
		return nil // Nothing to update
	}

	// Load existing config
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check if license needs updating
	if cfg.License == newLicense {
		logger.Info("License already up to date")
		return nil
	}

	logger.Info("Updating license key")

	// TODO: Implement API call to update license
	// This would require adding an UpdateAccount method to the API
	// For now, just update the config file
	cfg.License = newLicense

	if err := cfg.SaveConfig(configPath); err != nil {
		return fmt.Errorf("failed to save updated config: %w", err)
	}

	logger.Info("License updated successfully")
	return nil
}

// ValidateConfig checks if a config file exists and is valid
func ValidateConfig(configPath string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", configPath)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("invalid config file: %w", err)
	}

	// Basic validation
	if cfg.PrivateKey == "" {
		return fmt.Errorf("config missing private key")
	}
	if cfg.EndpointPubKey == "" {
		return fmt.Errorf("config missing endpoint public key")
	}
	if cfg.EndpointV4 == "" && cfg.EndpointV6 == "" {
		return fmt.Errorf("config missing endpoints")
	}

	return nil
}

// DeleteConfig removes the config file (useful for reset)
func DeleteConfig(configPath string) error {
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	return nil
}
