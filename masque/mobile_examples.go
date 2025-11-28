package masque

// Mobile platform integration examples showing how to use MASQUE on iOS and Android
// These examples show the proper way to set config paths for mobile apps

import (
	"context"
	"fmt"
	"log/slog"
)

// AndroidMasqueSetup shows how to initialize MASQUE on Android
// appDataDir should come from context.getFilesDir().getAbsolutePath() in Java/Kotlin
func AndroidMasqueSetup(appDataDir string) (*MasqueClient, error) {
	ctx := context.Background()
	logger := slog.Default()

	// Get mobile-specific config path
	configPath := GetMobileConfigPath(appDataDir)

	logger.Info("Android MASQUE setup", "configPath", configPath)

	// Auto-load or register with Android-specific settings
	client, err := AutoLoadOrRegisterWithOptions(ctx, AutoRegisterOptions{
		ConfigPath: configPath,
		DeviceName: "Android-vwarp",
		Model:      "Android",
		Logger:     logger,
	})

	if err != nil {
		return nil, fmt.Errorf("Android MASQUE setup failed: %w", err)
	}

	return client, nil
}

// IOSMasqueSetup shows how to initialize MASQUE on iOS
// appSupportDir should come from FileManager.default.urls(for: .applicationSupportDirectory) in Swift
func IOSMasqueSetup(appSupportDir string) (*MasqueClient, error) {
	ctx := context.Background()
	logger := slog.Default()

	// Get mobile-specific config path
	configPath := GetMobileConfigPath(appSupportDir)

	logger.Info("iOS MASQUE setup", "configPath", configPath)

	// Auto-load or register with iOS-specific settings
	client, err := AutoLoadOrRegisterWithOptions(ctx, AutoRegisterOptions{
		ConfigPath: configPath,
		DeviceName: "iOS-vwarp",
		Model:      "iOS",
		Logger:     logger,
	})

	if err != nil {
		return nil, fmt.Errorf("iOS MASQUE setup failed: %w", err)
	}

	return client, nil
}

// DesktopMasqueSetup shows how to initialize MASQUE on desktop (Windows/macOS/Linux)
// Uses platform-specific default paths automatically
func DesktopMasqueSetup() (*MasqueClient, error) {
	ctx := context.Background()
	logger := slog.Default()

	// Get platform-specific default config path
	// Windows: %APPDATA%\vwarp\masque_config.json
	// macOS: ~/Library/Application Support/vwarp/masque_config.json
	// Linux: ~/.config/vwarp/masque_config.json
	configPath := GetDefaultConfigPath()

	logger.Info("Desktop MASQUE setup", "configPath", configPath)

	// Auto-load or register
	client, err := AutoLoadOrRegisterWithOptions(ctx, AutoRegisterOptions{
		ConfigPath: configPath,
		DeviceName: "Desktop-vwarp",
		Logger:     logger,
	})

	if err != nil {
		return nil, fmt.Errorf("Desktop MASQUE setup failed: %w", err)
	}

	return client, nil
}

// CustomPathMasqueSetup shows how to use a custom config path (for testing or custom scenarios)
func CustomPathMasqueSetup(customConfigPath string) (*MasqueClient, error) {
	ctx := context.Background()
	logger := slog.Default()

	client, err := AutoLoadOrRegisterWithOptions(ctx, AutoRegisterOptions{
		ConfigPath: customConfigPath,
		DeviceName: "Custom-vwarp",
		Logger:     logger,
	})

	if err != nil {
		return nil, fmt.Errorf("Custom MASQUE setup failed: %w", err)
	}

	return client, nil
}
