package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	// Test UDP connectivity to MASQUE endpoint
	endpoint := "162.159.198.1:443"

	fmt.Printf("Testing UDP connectivity to %s\n", endpoint)

	// Create UDP connection
	conn, err := net.DialTimeout("udp", endpoint, 5*time.Second)
	if err != nil {
		fmt.Printf("Failed to dial UDP: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Println("UDP dial successful, attempting to send test packet...")

	// Send test data
	testData := []byte("HELLO")
	n, err := conn.Write(testData)
	if err != nil {
		fmt.Printf("Failed to write: %v\n", err)
		return
	}
	fmt.Printf("Sent %d bytes\n", n)

	// Try to read with timeout (will likely timeout, but that's OK)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Read timeout (expected for raw UDP test)")
		} else {
			fmt.Printf("Read error: %v\n", err)
		}
	} else {
		fmt.Printf("Received %d bytes: %v\n", n, buf[:n])
	}

	fmt.Println("UDP test complete")
}
