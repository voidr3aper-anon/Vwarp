//go:build !linux

package masque

import (
	"log/slog"
	"net"
)

// configureUDPBufferPlatform is a no-op on non-Linux platforms
// where QUIC UDP buffer warnings are typically not an issue
func configureUDPBufferPlatform(conn *net.UDPConn, logger *slog.Logger) error {
	logger.Debug("UDP buffer configuration not required on this platform")
	return nil
}
