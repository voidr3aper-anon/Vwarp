package masque

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
)

// Connect-IP implementation based on draft-ietf-masque-connect-ip

// ConnectIPConn represents a Connect-IP connection
type ConnectIPConn struct {
	stream     io.ReadWriteCloser
	datagramCh chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
}

// Dial establishes a Connect-IP connection
func DialConnectIP(
	ctx context.Context,
	httpConn http.RoundTripper,
	uriTemplate *uritemplate.Template,
	protocol string,
	headers http.Header,
	useCapsules bool,
	target string,
	logger *slog.Logger,
) (*ConnectIPConn, *http.Response, error) {

	// Parse target into host and port
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse target: %w", err)
	}

	// For IPv6, bracket the host so that the template contains a bracketed IPv6 literal
	targetHost := host
	if net.ParseIP(host) != nil && net.ParseIP(host).To4() == nil {
		targetHost = "[" + host + "]"
	}

	// Expand URI template for Connect-IP
	uri, err := uriTemplate.Expand(uritemplate.Values{
		"target_host": uritemplate.String(targetHost),
		"target_port": uritemplate.String(port),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to expand URI template: %w", err)
	}

	// Debug log the URI
	if logger != nil {
		logger.Debug("Expanded Connect-IP URI", "uri", uri)
	}

	// Create CONNECT request (use standard CONNECT method - Connect-IP will use Connect semantics)
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, uri, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Debug log the request URL
	if logger != nil {
		logger.Debug("Connect-IP request", "url", req.URL.String(), "method", req.Method)
	}

	// Set required headers
	req.Header.Set("Capsule-Protocol", "?1")
	if protocol != "" {
		// For HTTP/2, the transport checks req.Header.Get(":protocol") and will
		// treat it as a pseudo-header for CONNECT extended usage.
		// We'll also set X-Connect-Protocol for servers that expect a non-standard header.
		req.Header.Set(":protocol", protocol)
		req.Header.Set("X-Connect-Protocol", protocol)
	}

	// Add custom headers
	for k, v := range headers {
		for _, val := range v {
			req.Header.Add(k, val)
		}
	}

	// Send request
	resp, err := httpConn.RoundTrip(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, resp, fmt.Errorf("CONNECT-IP failed with status %d", resp.StatusCode)
	}

	// Check for Capsule-Protocol support
	capsuleHeader := resp.Header.Get("Capsule-Protocol")
	if capsuleHeader != "" {
		dict, err := httpsfv.UnmarshalDictionary([]string{capsuleHeader})
		if err == nil {
			if val, ok := dict.Get("?1"); ok {
				// Check if value indicates capsule support
				if item, ok := val.(httpsfv.Item); ok {
					if boolVal, ok := item.Value.(bool); ok && boolVal {
						useCapsules = true
					}
				}
			}
		}
	}

	connCtx, cancel := context.WithCancel(ctx)

	conn := &ConnectIPConn{
		stream:     nil, // Will be set if we have access to the underlying stream
		datagramCh: make(chan []byte, 100),
		ctx:        connCtx,
		cancel:     cancel,
	}

	// If the body implements io.ReadWriteCloser, we can use it directly
	if rwc, ok := resp.Body.(io.ReadWriteCloser); ok {
		// Wrap the body for capsule handling if needed
		if useCapsules {
			go conn.readCapsules(rwc)
		}
	}

	return conn, resp, nil
}

// Read reads an IP packet from the connection
func (c *ConnectIPConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()

	if closed {
		return 0, io.EOF
	}

	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case data := <-c.datagramCh:
		n = copy(p, data)
		return n, nil
	}
}

// Write writes an IP packet to the connection
func (c *ConnectIPConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()

	if closed {
		return 0, io.ErrClosedPipe
	}

	// For now, we write directly to the stream
	// In a full implementation, we'd wrap in capsules
	if c.stream != nil {
		// Write as DATAGRAM capsule
		capsule := make([]byte, 0, len(p)+16)
		capsule = quicvarint.Append(capsule, CapsuleTypeDatagram)
		capsule = quicvarint.Append(capsule, uint64(len(p)))
		capsule = append(capsule, p...)

		return c.stream.Write(capsule)
	}

	return len(p), nil
}

// Close closes the connection
func (c *ConnectIPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	c.cancel()

	if c.stream != nil {
		return c.stream.Close()
	}

	return nil
}

// readCapsules reads capsules from the stream
func (c *ConnectIPConn) readCapsules(r io.Reader) {
	br := bufio.NewReader(r)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Read capsule type
		capsuleType, err := binary.ReadUvarint(br)
		if err != nil {
			return
		}

		// Read capsule length
		capsuleLen, err := binary.ReadUvarint(br)
		if err != nil {
			return
		}

		// Read capsule data
		data := make([]byte, capsuleLen)
		if _, err := io.ReadFull(br, data); err != nil {
			return
		}

		// Handle capsule based on type
		switch capsuleType {
		case CapsuleTypeDatagram:
			select {
			case c.datagramCh <- data:
			case <-c.ctx.Done():
				return
			default:
				// Drop if channel is full
			}
		case CapsuleTypeAddressAssign, CapsuleTypeAddressRequest, CapsuleTypeRouteAdvertise:
			// These would be handled for full IP tunnel setup
			// For now, we ignore them
		}
	}
}

// Helper function to parse endpoint
func ParseEndpoint(endpoint string) (host string, port int, err error) {
	// Try to split host:port
	if idx := lastIndexByte(endpoint, ':'); idx != -1 {
		host = endpoint[:idx]
		portStr := endpoint[idx+1:]
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %w", err)
		}
		return host, port, nil
	}

	return endpoint, 443, nil // default port
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
