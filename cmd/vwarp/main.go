package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const appName = "vwarp"

// customLogWriter intercepts standard log output and reformats it as structured logs
type customLogWriter struct {
	logger *slog.Logger
}

func (w *customLogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Remove trailing newline
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}

	// Check for common QUIC/HTTP3 messages and categorize them
	switch {
	case contains(msg, "handling stream failed"):
		if contains(msg, "H3_NO_ERROR") {
			w.logger.Debug("QUIC stream closed gracefully", "details", msg)
		} else {
			w.logger.Warn("QUIC stream failed", "details", msg)
		}
	case contains(msg, "writing to stream failed"):
		w.logger.Debug("Stream write failed during connection cleanup", "details", msg)
	case contains(msg, "failed to increase receive buffer size"):
		w.logger.Debug("UDP buffer size notice", "details", msg)
	default:
		// For any other QUIC library messages
		w.logger.Debug("QUIC library message", "details", msg)
	}

	return len(p), nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func main() {
	// Set up structured logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Intercept standard log output (used by QUIC library) and format it nicely
	log.SetOutput(&customLogWriter{logger: logger})

	args := os.Args[1:]
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	rootCmd := newRootCmd()
	versionCmd(rootCmd)
	err := rootCmd.command.Parse(args)

	switch {
	case errors.Is(err, ff.ErrHelp):
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Command(rootCmd.command))
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := rootCmd.command.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func fatal(l *slog.Logger, err error) {
	l.Error(err.Error())
	os.Exit(1)
}
