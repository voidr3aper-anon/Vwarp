package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/bepass-org/vwarp/masque"
	"github.com/bepass-org/vwarp/masque/noize"
	"github.com/bepass-org/vwarp/masque/usque/config"
)

func main() {
	// Command flags
	register := flag.Bool("register", false, "Force re-register device (otherwise auto-register if needed)")
	configPath := flag.String("config", "", "Path to config file (default: platform-specific)")
	endpoint := flag.String("endpoint", "", "MASQUE endpoint (optional)")
	useIPv6 := flag.Bool("ipv6", false, "Use IPv6 endpoint")
	deviceName := flag.String("name", "vwarp", "Device name for registration")
	verbose := flag.Bool("v", false, "Verbose logging")
	testMode := flag.Bool("test", false, "Test mode: connect and print stats")

	// Noize/Obfuscation flags
	enableNoize := flag.Bool("noize", false, "Enable packet obfuscation")
	noizePreset := flag.String("noize-preset", "medium", "Obfuscation preset: light, medium, heavy, stealth, gfw, none")
	noizeFragment := flag.Int("noize-fragment", 0, "Fragment packet size (0=disabled)")
	noizeJunk := flag.Int("noize-junk", 0, "Number of junk packets (0=use preset)")
	noizeMimic := flag.String("noize-mimic", "", "Protocol to mimic: dns, https, h3, dtls, stun")

	// Scanner flags
	scanMode := flag.Bool("scan", false, "Scan mode: find best endpoint")
	scanWorkers := flag.Int("scan-workers", 10, "Number of concurrent scanner workers")
	scanMax := flag.Int("scan-max", 30, "Maximum number of endpoints to scan")
	scanTimeout := flag.Duration("scan-timeout", 5*time.Second, "Timeout per endpoint scan")
	scanPing := flag.Bool("scan-ping", true, "Enable ping before connection test")
	scanOrdered := flag.Bool("scan-ordered", false, "Scan in order (no shuffle)")
	scanVerbose := flag.Bool("scan-verbose", false, "Show all scan attempts")
	range4 := flag.String("range4", "", "Comma-separated IPv4 CIDR ranges to scan")
	range6 := flag.String("range6", "", "Comma-separated IPv6 CIDR ranges to scan")
	ports := flag.String("ports", "443,500,1701,4500,4443,8443,8095", "Comma-separated ports to scan")

	flag.Parse()

	// Use platform-specific default config path if not specified
	if *configPath == "" {
		*configPath = masque.GetDefaultConfigPath()
	}

	// Setup logger
	logLevel := slog.LevelInfo
	if *verbose || *scanVerbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Scanner mode
	if *scanMode {
		fmt.Println("Starting MASQUE endpoint scanner...")
		runScanner(logger, *configPath, *range4, *range6, *ports, *useIPv6, *scanWorkers, *scanMax, *scanTimeout, *scanPing, *scanOrdered, *scanVerbose)
		return
	}

	// Connection mode with auto-registration
	fmt.Println("Initializing MASQUE connection...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build noize config if enabled
	var noizeConfig interface{}
	if *enableNoize {
		noizeConfig = buildNoizeConfig(*noizePreset, *noizeFragment, *noizeJunk, *noizeMimic)
		if noizeConfig != nil {
			fmt.Printf("[NOIZE] Obfuscation enabled (preset: %s)\n", *noizePreset)
		}
	}

	// Use auto-registration which handles everything automatically
	client, err := masque.AutoLoadOrRegisterWithOptions(ctx, masque.AutoRegisterOptions{
		ConfigPath:  *configPath,
		DeviceName:  *deviceName,
		ForceRenew:  *register,
		Endpoint:    *endpoint,
		UseIPv6:     *useIPv6,
		Logger:      logger,
		EnableNoize: *enableNoize,
		NoizeConfig: noizeConfig,
	})
	if err != nil {
		log.Fatalf("Failed to create MASQUE client: %v", err)
	}
	defer client.Close()

	fmt.Println("✓ Connected successfully!")

	ipv4, ipv6 := client.GetLocalAddresses()
	fmt.Printf("  Assigned IPv4: %s\n", ipv4)
	fmt.Printf("  Assigned IPv6: %s\n", ipv6)

	if *testMode {
		fmt.Println("\nTest mode: Reading packets for 10 seconds...")
		testCtx, testCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer testCancel()

		buf := make([]byte, 1500)
		packetCount := 0
		totalBytes := 0

		go func() {
			<-testCtx.Done()
			fmt.Printf("\n✓ Test completed: %d packets, %d bytes\n", packetCount, totalBytes)
			os.Exit(0)
		}()

		for {
			n, err := client.Read(buf)
			if err != nil {
				log.Printf("Read error: %v", err)
				break
			}
			packetCount++
			totalBytes += n
			if packetCount%10 == 0 {
				fmt.Printf("  Packets: %d, Bytes: %d\n", packetCount, totalBytes)
			}
		}
	} else {
		fmt.Println("\nMASQUE tunnel is ready. Press Ctrl+C to exit.")
		// Keep running
		select {}
	}
}

func runScanner(logger *slog.Logger, configPath, range4, range6, portsStr string, useIPv6 bool, workers, maxEndpoints int, timeout time.Duration, pingEnabled, ordered, verboseChild bool) {
	ctx := context.Background()

	// Load config if exists, or register without connecting
	logger.Info("Loading/creating MASQUE config for scanner...")

	var cfg *config.Config
	var err error

	// Check if config exists
	if _, err := os.Stat(configPath); err == nil {
		// Load existing config
		cfg, err = config.LoadConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load existing config: %v", err)
		}
		logger.Info("Loaded existing config")
	} else {
		// Create new config via registration
		logger.Info("No config found, registering new device...")
		cfg, err = masque.RegisterAndEnroll(
			masque.DefaultModel,
			masque.DefaultLocale,
			"", // no JWT
			"vwarp-scanner",
			true, // accept TOS
		)
		if err != nil {
			log.Fatalf("Failed to register: %v", err)
		}

		// Create directory if needed before saving
		if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
			log.Fatalf("Failed to create config directory: %v", err)
		}

		// Save config
		if err := masque.SaveConfig(cfg, configPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
		logger.Info("Created and saved new config")
	}

	// Get keys from config
	privKey, err := cfg.GetEcPrivateKey()
	if err != nil {
		log.Fatalf("Failed to get private key: %v", err)
	}
	peerPubKey, err := cfg.GetEcEndpointPublicKey()
	if err != nil {
		log.Fatalf("Failed to get peer public key: %v", err)
	}

	// Parse CIDR ranges
	var ipv4Ranges, ipv6Ranges []string
	if range4 != "" {
		ipv4Ranges = parseCIDRList(range4)
	}
	if range6 != "" {
		ipv6Ranges = parseCIDRList(range6)
	}

	// Parse ports
	var scanPorts []int
	if portsStr != "" {
		for _, portStr := range splitComma(portsStr) {
			var port int
			if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil && port > 0 && port < 65536 {
				scanPorts = append(scanPorts, port)
			}
		}
	}

	// Create scanner
	scanner := masque.NewScanner(masque.ScannerConfig{
		IPv4Ranges:   ipv4Ranges,
		IPv6Ranges:   ipv6Ranges,
		Ports:        scanPorts,
		MaxEndpoints: maxEndpoints,
		ScanTimeout:  timeout,
		Workers:      workers,
		PingEnabled:  pingEnabled,
		Ordered:      ordered,
		UseIPv6:      useIPv6,
		PrivKey:      privKey,
		PeerPubKey:   peerPubKey,
		SNI:          masque.DefaultMasqueSNI,
		EarlyExit:    true,
		VerboseChild: verboseChild,
		Logger:       logger,
	})

	// Run scan
	result, err := scanner.Scan(ctx)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	sep := "============================================================"
	fmt.Println("\n" + sep)
	fmt.Println("SCAN RESULTS")
	fmt.Println(sep)
	fmt.Printf("✓ Best endpoint: %s\n", result.Endpoint)
	fmt.Printf("  Latency: %v\n", result.Latency)
	if result.PingTime > 0 {
		fmt.Printf("  Ping time: %v\n", result.PingTime)
	}

	// Show top 5 results
	successful := scanner.GetSuccessfulResults()
	if len(successful) > 1 {
		fmt.Println("\nTop endpoints:")
		for i, r := range successful {
			if i >= 5 {
				break
			}
			fmt.Printf("  %d. %s (latency: %v", i+1, r.Endpoint, r.Latency)
			if r.PingTime > 0 {
				fmt.Printf(", ping: %v", r.PingTime)
			}
			fmt.Println(")")
		}
	}

	fmt.Println(sep)
	fmt.Printf("\nTo use this endpoint:\n")
	fmt.Printf("  masque-test.exe -endpoint %s\n", result.Endpoint)
}

func parseCIDRList(s string) []string {
	var ranges []string
	for _, cidr := range splitComma(s) {
		if cidr != "" {
			ranges = append(ranges, cidr)
		}
	}
	return ranges
}

func splitComma(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else if c != ' ' && c != '\t' {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// buildNoizeConfig creates a noize configuration based on flags
func buildNoizeConfig(preset string, fragmentSize, junkCount int, mimicProtocol string) interface{} {
	var cfg *noize.NoizeConfig

	// Start with preset
	switch preset {
	case "light":
		cfg = noize.LightObfuscationConfig()
	case "medium":
		cfg = noize.MediumObfuscationConfig()
	case "heavy":
		cfg = noize.HeavyObfuscationConfig()
	case "stealth":
		cfg = noize.StealthObfuscationConfig()
	case "gfw":
		cfg = noize.GFWBypassConfig()
	case "none":
		return noize.NoObfuscationConfig()
	default:
		cfg = noize.MediumObfuscationConfig()
	}

	// Apply custom overrides
	if fragmentSize > 0 {
		cfg.FragmentSize = fragmentSize
		cfg.FragmentInitial = true
	}

	if junkCount > 0 {
		cfg.Jc = junkCount
	}

	if mimicProtocol != "" {
		cfg.MimicProtocol = mimicProtocol
	}

	return cfg
}
