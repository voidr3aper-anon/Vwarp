package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bepass-org/vwarp/masque"
	"github.com/bepass-org/vwarp/proxy/pkg/mixed"
)

func main() {
	// Set up logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create context with cancellation
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println("🔐 MASQUE-Enhanced Mixed Proxy Server")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("🔧 Supports HTTP, SOCKS4, SOCKS5 with MASQUE backend")
	fmt.Println("📋 Configures applications to use proxy at: 127.0.0.1:1080")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Create MASQUE-enabled mixed proxy
	proxy := mixed.NewProxy(
		mixed.WithBindAddress("127.0.0.1:1080"),
		mixed.WithLogger(logger),
		mixed.WithContext(ctx),
		// Auto-setup MASQUE with registration
		mixed.WithMasqueAutoSetup(ctx, masque.AutoRegisterOptions{
			DeviceName: "masque-mixed-proxy",
			Logger:     logger,
		}),
	)

	logger.Info("🚀 Starting MASQUE-enhanced mixed proxy server on 127.0.0.1:1080")

	// Start the proxy server
	go func() {
		if err := proxy.ListenAndServe(); err != nil {
			logger.Error("Proxy server error", "error", err)
			cancel()
		}
	}()

	fmt.Println("📊 Server Status: ✅ Ready")
	fmt.Println("🔐 Backend: MASQUE tunnel with automated registration")
	fmt.Println("🌐 Protocols: HTTP, SOCKS4, SOCKS5")
	fmt.Println("📋 Press Ctrl+C to stop the server")

	// Wait for cancellation
	<-ctx.Done()
	logger.Info("👋 Shutting down mixed proxy server...")
}
