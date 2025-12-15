//go:build linux

package masque

import (
	"log/slog"
	"net"

	"golang.org/x/sys/unix"
)

// configureUDPBufferPlatform applies Linux-specific UDP socket buffer optimizations
// This implements the same approach as WireGuard to maximize QUIC performance
func configureUDPBufferPlatform(conn *net.UDPConn, logger *slog.Logger) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		logger.Warn("Failed to get raw connection for UDP buffer configuration", "error", err)
		return err
	}

	var syscallErr error
	controlErr := rawConn.Control(func(fd uintptr) {
		logger.Debug("Applying UDP socket buffer settings", "fd", fd, "bufferSize", udpBufferSize)

		// Set up to *mem_max (this should always work)
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, udpBufferSize); err != nil {
			logger.Debug("Failed to set SO_RCVBUF", "error", err)
			syscallErr = err
		} else {
			logger.Debug("Successfully set SO_RCVBUF", "size", udpBufferSize)
		}

		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, udpBufferSize); err != nil {
			logger.Debug("Failed to set SO_SNDBUF", "error", err)
			if syscallErr == nil {
				syscallErr = err
			}
		} else {
			logger.Debug("Successfully set SO_SNDBUF", "size", udpBufferSize)
		}

		// Try to set beyond *mem_max if CAP_NET_ADMIN is available
		// These may fail silently, which is acceptable
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, udpBufferSize); err != nil {
			logger.Debug("SO_RCVBUFFORCE not available (requires CAP_NET_ADMIN)", "error", err)
		} else {
			logger.Debug("Successfully set SO_RCVBUFFORCE", "size", udpBufferSize)
		}

		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, udpBufferSize); err != nil {
			logger.Debug("SO_SNDBUFFORCE not available (requires CAP_NET_ADMIN)", "error", err)
		} else {
			logger.Debug("Successfully set SO_SNDBUFFORCE", "size", udpBufferSize)
		}

		// Verify the actual buffer sizes set
		if actualRcvBuf, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
			logger.Debug("Actual receive buffer size", "size", actualRcvBuf, "requested", udpBufferSize)
			if actualRcvBuf < (udpBufferSize / 2) { // Allow some system overhead
				logger.Warn("UDP receive buffer size is significantly smaller than requested",
					"actual", actualRcvBuf, "requested", udpBufferSize,
					"suggestion", "Consider increasing net.core.rmem_max system limit")
			}
		}

		if actualSndBuf, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF); err == nil {
			logger.Debug("Actual send buffer size", "size", actualSndBuf, "requested", udpBufferSize)
			if actualSndBuf < (udpBufferSize / 2) { // Allow some system overhead
				logger.Warn("UDP send buffer size is significantly smaller than requested",
					"actual", actualSndBuf, "requested", udpBufferSize,
					"suggestion", "Consider increasing net.core.wmem_max system limit")
			}
		}
	})

	if controlErr != nil {
		logger.Error("Failed to control raw socket for buffer configuration", "error", controlErr)
		return controlErr
	}

	if syscallErr != nil {
		logger.Warn("Some UDP buffer settings failed to apply", "error", syscallErr)
		// Don't return error - partial success is still beneficial
	}

	logger.Info("UDP socket buffer configuration completed")
	return nil
}
