package masque

import (
	"log/slog"
	"net"
	"runtime"
)

// udpBufferSize is the optimal UDP buffer size for QUIC connections (7MB)
// This matches the buffer size used by WireGuard for optimal performance
const udpBufferSize = 7 << 20 // 7MB

// configureUDPBuffer applies optimal UDP socket buffer settings for QUIC
// This function is a no-op on platforms other than Linux/Unix where the
// QUIC buffer warnings are not an issue
func configureUDPBuffer(conn *net.UDPConn, logger *slog.Logger) error {
	if conn == nil {
		return nil
	}

	// Only apply buffer configuration on Linux where QUIC buffer warnings occur
	if runtime.GOOS != "linux" {
		return nil
	}

	logger.Debug("Configuring UDP socket buffers for optimal QUIC performance", "bufferSize", udpBufferSize)

	// Apply platform-specific buffer configuration
	return configureUDPBufferPlatform(conn, logger)
}
