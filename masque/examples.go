package masque

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/bepass-org/vwarp/masque/usque/config"
)

// Example: Register a new MASQUE account
func ExampleRegisterNewAccount() {
	// Register and enroll a new device
	cfg, err := RegisterAndEnroll(
		DefaultModel,  // model: "PC"
		DefaultLocale, // locale: "en_US"
		"",            // jwt (team token, optional)
		"MyDevice",    // device name
		true,          // accept TOS
	)
	if err != nil {
		log.Fatalf("Failed to register: %v", err)
	}

	// Save config to file
	if err := SaveConfig(cfg, "masque_config.json"); err != nil {
		log.Fatalf("Failed to save config: %v", err)
	}

	fmt.Println("Registration successful!")
	fmt.Printf("IPv4: %s\n", cfg.IPv4)
	fmt.Printf("IPv6: %s\n", cfg.IPv6)
}

// Example: Connect using existing config
func ExampleConnectWithConfig() {
	ctx := context.Background()

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Connect using config file
	client, err := NewMasqueClient(ctx, MasqueClientConfig{
		ConfigPath: "masque_config.json",
		UseIPv6:    false, // Use IPv4 endpoint
		Logger:     logger,
	})
	if err != nil {
		log.Fatalf("Failed to create MASQUE client: %v", err)
	}
	defer client.Close()

	fmt.Println("Connected to MASQUE!")

	// Get assigned addresses
	ipv4, ipv6 := client.GetLocalAddresses()
	fmt.Printf("Assigned IPv4: %s\n", ipv4)
	fmt.Printf("Assigned IPv6: %s\n", ipv6)

	// Now you can use client.Read() and client.Write() for IP packet tunneling
	// Example: Read loop
	buf := make([]byte, 1500)
	for {
		n, err := client.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			break
		}
		fmt.Printf("Received %d bytes\n", n)
		// Process packet...
	}
}

// Example: Connect with specific endpoint
func ExampleConnectWithEndpoint() {
	ctx := context.Background()

	// Load existing config
	cfg, err := config.LoadConfig("masque_config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect with custom endpoint
	client, err := NewMasqueClient(ctx, MasqueClientConfig{
		ConfigData: cfg,
		Endpoint:   "162.159.198.1:443", // Override endpoint
		SNI:        DefaultMasqueSNI,
		UseIPv6:    false,
		Logger:     slog.Default(),
	})
	if err != nil {
		log.Fatalf("Failed to create MASQUE client: %v", err)
	}
	defer client.Close()

	fmt.Println("Connected with custom endpoint!")
}

// Example: Integration with WireGuard
// This shows how to use the MASQUE client as a transport for WireGuard
func ExampleWireGuardIntegration() {
	// This is a conceptual example showing how to integrate with WireGuard
	// You would use the MASQUE client as the underlying transport

	ctx := context.Background()

	client, err := NewMasqueClient(ctx, MasqueClientConfig{
		ConfigPath: "masque_config.json",
		UseIPv6:    false,
	})
	if err != nil {
		log.Fatalf("Failed to create MASQUE client: %v", err)
	}
	defer client.Close()

	// The client implements Read/Write interface
	// You can wrap it with your WireGuard stack or use it directly
	// For example, with lwip or other TUN implementations:

	// wgConfig := wireguard.Config{
	//     PrivateKey: ...,
	//     Peers: ...,
	// }
	//
	// Use client as transport:
	// wgDevice := wireguard.NewDevice(wgConfig, client)

	fmt.Println("MASQUE client ready for WireGuard integration")
}
