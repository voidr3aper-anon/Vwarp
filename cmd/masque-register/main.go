package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/bepass-org/vwarp/masque"
)

func main() {
	var (
		configPath = flag.String("config", "", "Path to save the configuration file (default: platform-specific)")
		deviceName = flag.String("device", "vwarp-masque", "Device name for registration")
		forceRenew = flag.Bool("renew", false, "Force re-registration even if config exists")
		timeout    = flag.Duration("timeout", 30*time.Second, "Registration timeout")
		verbose    = flag.Bool("v", false, "Verbose logging")
		model      = flag.String("model", "PC", "Device model (PC, Android, iOS, etc.)")
		locale     = flag.String("locale", "en_US", "Device locale")
	)
	flag.Parse()

	// Setup logger
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Determine config path
	if *configPath == "" {
		*configPath = getDefaultConfigPath()
	}

	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║         vwarp MASQUE Registration Tool                    ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Device Name:  %s\n", *deviceName)
	fmt.Printf("Model:        %s\n", *model)
	fmt.Printf("Locale:       %s\n", *locale)
	fmt.Printf("Config Path:  %s\n", *configPath)
	fmt.Printf("Force Renew:  %v\n", *forceRenew)
	fmt.Println()

	// Check if config already exists
	if !*forceRenew {
		if _, err := os.Stat(*configPath); err == nil {
			fmt.Println("⚠️  Config file already exists!")
			fmt.Println("Use --renew to force re-registration")
			fmt.Println()

			// Load and display existing config
			config, err := masque.LoadMasqueConfig(*configPath)
			if err != nil {
				logger.Error("Failed to load existing config", "error", err)
				os.Exit(1)
			}

			displayConfig(config, *configPath)
			fmt.Println("\n✅ Using existing configuration")
			return
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(*configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Error("Failed to create config directory", "error", err)
		os.Exit(1)
	}

	fmt.Println("📝 Registering with Cloudflare WARP...")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Method 1: Using AutoLoadOrRegisterWithOptions (recommended)
	client, err := masque.AutoLoadOrRegisterWithOptions(ctx, masque.AutoRegisterOptions{
		ConfigPath: *configPath,
		DeviceName: *deviceName,
		Model:      *model,
		Locale:     *locale,
		ForceRenew: *forceRenew,
		Logger:     logger,
	})
	if err != nil {
		logger.Error("Registration failed", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	// Get the config to display details
	config := client.GetMasqueConfig()

	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              ✅ Registration Successful!                   ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()

	displayConfig(config, *configPath)

	// Verify the config can be loaded
	fmt.Println("\n🔍 Verifying saved configuration...")
	if err := masque.ValidateConfig(*configPath); err != nil {
		logger.Error("Config validation failed", "error", err)
		os.Exit(1)
	}

	fmt.Println("✅ Configuration validated successfully!")
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Next steps:")
	fmt.Println("  1. Use this config with masque-test:")
	fmt.Printf("     masque-test.exe -config \"%s\" -endpoint %s:443\n", *configPath, config.EndpointV4)
	fmt.Println()
	fmt.Println("  2. Or create a MASQUE client programmatically:")
	fmt.Println("     client, _ := masque.NewMasqueClient(ctx, masque.MasqueClientConfig{")
	fmt.Printf("         ConfigPath: \"%s\",\n", *configPath)
	fmt.Println("     })")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func displayConfig(config *masque.MasqueConfig, path string) {
	fmt.Println("📋 Configuration Details:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Device ID:      %s\n", config.ID)
	fmt.Printf("  License:        %s\n", config.License)
	fmt.Printf("  IPv4 Address:   %s\n", config.IPv4)
	fmt.Printf("  IPv6 Address:   %s\n", config.IPv6)
	fmt.Printf("  Endpoint IPv4:  %s\n", config.EndpointV4)
	fmt.Printf("  Endpoint IPv6:  %s\n", config.EndpointV6)
	fmt.Printf("  Config File:    %s\n", path)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func getDefaultConfigPath() string {
	var configDir string

	switch runtime.GOOS {
	case "windows":
		configDir = filepath.Join(os.Getenv("APPDATA"), "vwarp")
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		configDir = filepath.Join(homeDir, "Library", "Application Support", "vwarp")
	case "linux":
		configDir = os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			homeDir, _ := os.UserHomeDir()
			configDir = filepath.Join(homeDir, ".config", "vwarp")
		}
	default:
		homeDir, _ := os.UserHomeDir()
		configDir = filepath.Join(homeDir, ".vwarp")
	}

	return filepath.Join(configDir, "masque_config.json")
}
