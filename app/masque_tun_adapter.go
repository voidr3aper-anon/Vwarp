package app

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/voidr3aper-anon/Vwarp/masque"
	"github.com/voidr3aper-anon/Vwarp/wireguard/tun"
	"github.com/voidr3aper-anon/Vwarp/wireguard/tun/netstack"
)

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// netstackTunAdapter wraps a tun.Device to provide packet forwarding interface
type netstackTunAdapter struct {
	dev             tun.Device
	tunnelBufPool   *sync.Pool
	tunnelSizesPool *sync.Pool
}

func (n *netstackTunAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *netstackTunAdapter) WritePacket(pkt []byte) error {
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// isConnectionError checks if the error indicates a closed or broken connection

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())

	// Standard network connection errors
	connectionErrors := []string{
		"use of closed network connection",
		"connection reset by peer",
		"broken pipe",
		"network is unreachable",
		"no route to host",
		"connection refused",
		"connection timed out",
		"i/o timeout",
		"context deadline exceeded",
		"context canceled",
		"connection aborted",
		"transport endpoint is not connected",
		"socket is not connected",
		"network interface is down",
		"connection reset by peer",
		"EOF",
		"broken pipe",
	}

	// Mobile and platform-specific errors
	androidErrors := []string{
		"permission denied",
		"operation not permitted",
		"protocol not available",
		"address family not supported",
		"network protocol is not available",
	}

	// Check all error patterns
	allErrors := append(connectionErrors, androidErrors...)
	for _, pattern := range allErrors {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// isPacketForwardingActive checks if packet forwarding is currently working
func isPacketForwardingActive(lastRead, lastWrite *atomic.Int64) bool {
	now := time.Now().Unix()
	lastReadTime := lastRead.Load()
	lastWriteTime := lastWrite.Load()

	// Consider active if we've had successful reads/writes within the last 30 seconds
	readRecent := now-lastReadTime < 30
	writeRecent := now-lastWriteTime < 30

	return readRecent || writeRecent
}

// AdapterFactory is a function that creates a new MASQUE adapter
type AdapterFactory func() (*masque.MasqueAdapter, error)

// Connection monitoring constants
const (
	HealthCheckInterval      = 45 * time.Second
	StaleConnectionThreshold = 120 * time.Second
	RecoveryCooldownPeriod   = 60 * time.Second
	MaxRecoveryAttempts      = 5
	MaxReconnectionAttempts  = 5
	ConnectivityTestTimeout  = 8 * time.Second
)

// Global connection failure tracking for firewall detection
var globalConnectionFailures atomic.Int64
var globalLastFailureReset atomic.Int64

func init() {
	globalLastFailureReset.Store(time.Now().Unix())
}

// TrackConnectionFailure increments the global connection failure counter
// This helps detect firewall interference patterns
func TrackConnectionFailure() {
	globalConnectionFailures.Add(1)
}

// maintainMasqueTunnel continuously forwards packets between the TUN device and MASQUE
// with automatic reconnection on connection failures
func maintainMasqueTunnel(ctx context.Context, l *slog.Logger, adapter *masque.MasqueAdapter, factory AdapterFactory, device *netstackTunAdapter, mtu int, tnet *netstack.Net, testURL string) {
	l.Info("Starting MASQUE tunnel packet forwarding with auto-reconnect")

	// Connection state management - buffered channel to prevent blocking
	connectionDown := make(chan bool, 1)

	// Track connection state
	var connectionBroken atomic.Bool
	var lastSuccessfulRead atomic.Int64
	var lastSuccessfulWrite atomic.Int64
	var lastRecoveryTime atomic.Int64
	var connectionFailures atomic.Int64 // Track connection failures for firewall detection
	var lastFailureReset atomic.Int64   // Time when failure counter was last reset
	var adapterMutex sync.RWMutex       // Protect adapter access during replacement

	// Initialize timestamps
	now := time.Now().Unix()
	lastSuccessfulRead.Store(now)
	lastSuccessfulWrite.Store(now)
	lastFailureReset.Store(now)

	// Forward packets from netstack to MASQUE
	go func() {
		buf := make([]byte, mtu)
		packetCount := 0
		writeErrors := 0

		for ctx.Err() == nil {
			// Wait if connection is broken
			if connectionBroken.Load() {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			n, err := device.ReadPacket(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				l.Error("error reading from TUN device", "error", err)
				// Brief pause to avoid tight loop on TUN errors
				time.Sleep(50 * time.Millisecond)
				continue
			}

			packetCount++

			// Protected adapter access
			adapterMutex.RLock()
			currentAdapter := adapter
			adapterMutex.RUnlock()

			// Write packet to MASQUE and handle ICMP response
			icmp, err := currentAdapter.WriteWithICMP(buf[:n])
			if err != nil {
				if isConnectionError(err) {
					writeErrors++
					connectionFailures.Add(1) // Track local failure
					TrackConnectionFailure()  // Track global failure

					// Be more tolerant - require multiple consecutive errors before marking as broken
					if writeErrors >= 3 && !connectionBroken.Load() {
						l.Warn("MASQUE connection error detected on write", "error", err, "consecutive_errors", writeErrors)
						connectionBroken.Store(true)
						// Signal connection down (non-blocking)
						select {
						case connectionDown <- true:
						default:
						}
					}
					// Drop this packet and continue - don't queue failed writes
					continue
				} else {
					l.Error("error writing to MASQUE", "error", err, "packet_size", n)
					writeErrors++
					time.Sleep(20 * time.Millisecond) // Slightly longer pause for non-connection errors
				}
				continue
			}

			// Reset error counter on successful write
			if writeErrors > 0 {
				writeErrors = 0
			}
			lastSuccessfulWrite.Store(time.Now().Unix())

			// Handle ICMP response if present
			if len(icmp) > 0 {
				if err := device.WritePacket(icmp); err != nil {
					l.Error("error writing ICMP to TUN device", "error", err)
				}
			}
		}
	}()

	// Forward packets from MASQUE to netstack
	go func() {
		buf := make([]byte, mtu)
		packetCount := 0
		consecutiveErrors := 0
		readTimeouts := 0
		for ctx.Err() == nil {
			// Wait if connection is broken
			if connectionBroken.Load() {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Protected adapter access
			adapterMutex.RLock()
			currentAdapter := adapter
			adapterMutex.RUnlock()

			n, err := currentAdapter.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				if isConnectionError(err) {
					consecutiveErrors++
					connectionFailures.Add(1) // Track local failure
					TrackConnectionFailure()  // Track global failure

					// Categorize error types for better handling
					errStr := err.Error()
					isTimeout := strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline")

					if isTimeout {
						readTimeouts++
					}

					// Only trigger connection down after multiple consecutive errors or critical errors
					if consecutiveErrors >= 3 && !connectionBroken.Load() {
						l.Warn("MASQUE connection error detected on read", "error", err, "is_timeout", isTimeout, "consecutive_errors", consecutiveErrors)
						connectionBroken.Store(true)
						// Signal connection down (non-blocking)
						select {
						case connectionDown <- true:
						default:
						}
					}

					// Adaptive backoff based on error type
					if isTimeout && readTimeouts < 3 {
						// Short backoff for timeouts - may be temporary
						time.Sleep(200 * time.Millisecond)
					} else {
						// Longer backoff for connection errors or repeated timeouts
						backoffTime := time.Duration(min(consecutiveErrors, 20)) * 250 * time.Millisecond
						time.Sleep(backoffTime)
					}
				} else {
					l.Error("error reading from MASQUE", "error", err)
					consecutiveErrors++
					if consecutiveErrors > 10 {
						time.Sleep(500 * time.Millisecond)
					}
				}
				continue
			}

			// Reset error counters on successful read
			if consecutiveErrors > 0 || readTimeouts > 0 {
				consecutiveErrors = 0
				readTimeouts = 0
			}
			lastSuccessfulRead.Store(time.Now().Unix())

			packetCount++

			if err := device.WritePacket(buf[:n]); err != nil {
				l.Error("error writing to TUN device", "error", err, "packet_size", n)
				// Brief pause to avoid flooding TUN device with failed writes
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// Connection health monitoring goroutine
	go func() {
		healthTicker := time.NewTicker(HealthCheckInterval)
		defer healthTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-healthTicker.C:
				// Check if we haven't had successful reads/writes recently
				now := time.Now().Unix()
				lastRead := lastSuccessfulRead.Load()
				lastWrite := lastSuccessfulWrite.Load()

				// If no activity for too long and not already broken, trigger health check
				// But skip if we just completed recovery recently (30 second cooldown)
				lastRecovery := lastRecoveryTime.Load()
				recoveryCooldown := now-lastRecovery < int64(RecoveryCooldownPeriod.Seconds())

				// More aggressive monitoring - trigger on read OR write issues, or high failure rate
				readStale := now-lastRead > int64(StaleConnectionThreshold.Seconds())
				writeStale := now-lastWrite > int64(StaleConnectionThreshold.Seconds())
				failures := connectionFailures.Load()

				// Trigger if either read/write is stale OR we have connection failures
				connectionIssues := (readStale || writeStale) || failures >= 3

				if !connectionBroken.Load() && !recoveryCooldown && connectionIssues {
					l.Warn("Connection appears stale, triggering health check",
						"seconds_since_read", now-lastRead,
						"seconds_since_write", now-lastWrite)

					// Signal connection down for investigation
					select {
					case connectionDown <- true:
					default:
					}
				}
			}
		}
	}()

	// Connection failure monitoring goroutine - detect firewall interference
	go func() {
		failureCheckTicker := time.NewTicker(30 * time.Second) // Check every 30 seconds
		defer failureCheckTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-failureCheckTicker.C:
				now := time.Now().Unix()
				lastReset := lastFailureReset.Load()
				failures := connectionFailures.Load()
				globalFailures := globalConnectionFailures.Load()
				globalLastReset := globalLastFailureReset.Load()

				// If we have many failures in a short period, likely firewall interference
				timeSinceReset := now - lastReset
				globalTimeSinceReset := now - globalLastReset

				// Check both local and global failure rates
				localHighFailures := failures >= 5 && timeSinceReset < 120              // 5+ failures in 2 minutes
				globalHighFailures := globalFailures >= 8 && globalTimeSinceReset < 180 // 8+ global failures in 3 minutes

				if localHighFailures || globalHighFailures {
					if !connectionBroken.Load() {
						l.Warn("High connection failure rate detected, likely firewall interference",
							"failures", failures,
							"time_window_seconds", timeSinceReset)

						// Trigger reconnection
						connectionBroken.Store(true)
						select {
						case connectionDown <- true:
						default:
						}
					}
				}

				// Reset failure counter every 5 minutes if no reconnection needed
				if timeSinceReset > 300 && failures > 0 {
					connectionFailures.Store(0)
					lastFailureReset.Store(now)
					l.Debug("Connection failure counter reset", "previous_failures", failures)
				}
			}
		}
	}()

	// Connection monitoring and recovery goroutine
	go func() {
		recoveryAttempts := 0

		for {
			select {
			case <-ctx.Done():
				return
			case <-connectionDown:
				l.Warn("MASQUE connection lost, starting recovery process...")

				// Give time for error messages to settle and avoid rapid reconnection
				settleTime := time.Duration(min(recoveryAttempts+1, 5)) * time.Second
				time.Sleep(settleTime)

				// Try to reconnect with exponential backoff
				successfulRecovery := false
				for attempt := 1; attempt <= MaxReconnectionAttempts && ctx.Err() == nil; attempt++ {
					// Progressive backoff with jitter
					baseBackoff := time.Duration(attempt) * 2 * time.Second
					jitter := time.Duration(time.Now().UnixNano()%1000) * time.Millisecond
					backoff := baseBackoff + jitter

					l.Info("Reconnection attempt", "attempt", attempt, "backoff", backoff, "recovery_cycle", recoveryAttempts+1)

					time.Sleep(backoff)

					if ctx.Err() != nil {
						return
					}

					// Acquire write lock for adapter replacement
					adapterMutex.Lock()

					// Close the old broken adapter
					l.Info("Closing broken MASQUE adapter")
					oldAdapter := adapter
					if oldAdapter != nil {
						oldAdapter.Close()
					}

					// Create a new MASQUE adapter from scratch
					l.Info("Creating new MASQUE adapter with fresh handshake")
					newAdapter, err := factory()
					if err != nil {
						l.Warn("Failed to create new MASQUE adapter", "attempt", attempt, "error", err)
						adapterMutex.Unlock()
						continue
					}

					// Replace the adapter safely first
					adapter = newAdapter

					// Reset timestamps
					now := time.Now().Unix()
					lastSuccessfulRead.Store(now)
					lastSuccessfulWrite.Store(now)

					adapterMutex.Unlock()

					// Brief pause to allow packet forwarding goroutines to detect the new adapter
					time.Sleep(1 * time.Second)

					// Mark connection as restored AFTER adapter is replaced and goroutines can see it
					l.Info("Marking connection as restored - packet forwarding should resume")
					connectionBroken.Store(false)

					// Perform connectivity test to validate the new MASQUE connection
					l.Info("Testing connectivity on restored MASQUE connection", "attempt", attempt)

					// Create a timeout context for the connectivity test
					testCtx, cancel := context.WithTimeout(ctx, ConnectivityTestTimeout)

					// Test connectivity with fallback approach during recovery
					var connectivityOK bool

					// Try DNS-independent test first (most reliable)
					if err := dnsIndependentConnectivityTest(testCtx, l, tnet); err != nil {
						l.Debug("DNS-independent test failed, trying HTTP test", "error", err)

						// Fallback to basic HTTP connectivity test
						if err := usermodeTunTest(testCtx, l, tnet, testURL); err != nil {
							l.Warn("HTTP connectivity test failed during recovery", "error", err)
							// Accept established tunnel even if HTTP tests fail
							l.Info("Accepting established MASQUE tunnel")
							connectivityOK = true
						} else {
							l.Info("HTTP connectivity test passed")
							connectivityOK = true
						}
					} else {
						l.Info("DNS-independent connectivity test passed")
						connectivityOK = true
					}
					cancel()

					if connectivityOK {
						l.Info("MASQUE adapter validated successfully", "attempt", attempt)
					} else {
						l.Warn("MASQUE adapter failed connectivity validation but accepting tunnel", "attempt", attempt)
					}

					// Accept recovery if tunnel established successfully
					successfulRecovery = true
					lastRecoveryTime.Store(time.Now().Unix())
					l.Info("Connection recovery completed successfully", "attempt", attempt)
					break
				}

				// Handle recovery outcome
				if successfulRecovery {
					recoveryAttempts = 0 // Reset counter on success
					// Reset failure counters after successful recovery
					connectionFailures.Store(0)
					lastFailureReset.Store(time.Now().Unix())
					globalConnectionFailures.Store(0)
					globalLastFailureReset.Store(time.Now().Unix())

					l.Info("MASQUE connection recovery successful")

					// Drain any queued connectionDown signals that occurred during recovery
					drained := 0
					for {
						select {
						case <-connectionDown:
							drained++
						default:
							// No more signals to drain
							goto drainComplete
						}
					}
				drainComplete:
					if drained > 0 {
						l.Info("Cleared stale recovery signals", "count", drained)
					}
					// Recovery successful, don't trigger reconnection
				} else {
					recoveryAttempts++
					l.Error("All reconnection attempts failed", "recovery_cycle", recoveryAttempts, "max_cycles", MaxRecoveryAttempts)

					// If we've exceeded max recovery attempts, wait longer before trying again
					if recoveryAttempts >= MaxRecoveryAttempts {
						l.Error("Maximum recovery attempts exceeded, waiting longer before retry")
						time.Sleep(60 * time.Second) // Wait 1 minute before trying again
						recoveryAttempts = 0         // Reset for next cycle
					} else {
						// Progressive delay between recovery cycles
						delayTime := time.Duration(recoveryAttempts*5) * time.Second
						l.Info("Waiting before next recovery cycle", "delay", delayTime)
						time.Sleep(delayTime)
					}

					// Only trigger reconnection if recovery failed and context not cancelled
					if ctx.Err() == nil {
						select {
						case connectionDown <- true:
						default:
						}
					}
				}
			}
		}
	}()
}
