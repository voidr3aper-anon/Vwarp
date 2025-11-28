package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

// GenerateRandomAndroidSerial generates a random 8-byte Android-like device identifier
// and returns it as a hexadecimal string.
func GenerateRandomAndroidSerial() (string, error) {
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return "", err
	}
	return hex.EncodeToString(serial), nil
}

// GenerateRandomWgPubkey generates a random 32-byte WireGuard like public key
// and returns it as a base64-encoded string.
func GenerateRandomWgPubkey() (string, error) {
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

// TimeAsCfString formats a given time.Time into a Cloudflare-compatible string format.
func TimeAsCfString(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-07:00")
}

// GenerateEcKeyPair generates a new ECDSA key pair using the P-256 curve.
func GenerateEcKeyPair() ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	marshalledPrivKey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	marshalledPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return marshalledPrivKey, marshalledPubKey, nil
}

// GenerateCert creates a self-signed certificate using the provided ECDSA private and public keys.
// The certificate is valid for 24 hours.
func GenerateCert(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([][]byte, error) {
	// Debug: validate private key
	if privKey == nil {
		fmt.Printf("[DEBUG] GenerateCert: private key is nil\n")
		return nil, fmt.Errorf("private key is nil")
	}
	if privKey.D == nil || privKey.D.Sign() <= 0 {
		fmt.Printf("[DEBUG] GenerateCert: invalid D value\n")
		return nil, fmt.Errorf("invalid private key: D value is nil or non-positive")
	}

	fmt.Printf("[DEBUG] GenerateCert: privKey.D bit length: %d\n", privKey.D.BitLen())
	fmt.Printf("[DEBUG] GenerateCert: curve params P bit length: %d\n", privKey.Curve.Params().P.BitLen())

	// Check if D is within the curve's valid range
	if privKey.D.Cmp(privKey.Curve.Params().N) >= 0 {
		fmt.Printf("[DEBUG] GenerateCert: D value exceeds curve order N\n")
		return nil, fmt.Errorf("private key D value exceeds curve order")
	}

	// Use minimal certificate template like usque - Cloudflare doesn't care about these fields
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 24 * time.Hour),
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		fmt.Printf("[DEBUG] GenerateCert: x509.CreateCertificate failed: %v\n", err)
		return nil, err
	}

	fmt.Printf("[DEBUG] GenerateCert: certificate created successfully, size: %d bytes\n", len(cert))
	return [][]byte{cert}, nil
}

// DefaultQuicConfig returns a MASQUE compatible default QUIC configuration with specified keep-alive period and initial packet size.
func DefaultQuicConfig(keepalivePeriod time.Duration, initialPacketSize uint16) *quic.Config {
	return &quic.Config{
		EnableDatagrams:      true,
		InitialPacketSize:    initialPacketSize,
		KeepAlivePeriod:      keepalivePeriod,
		HandshakeIdleTimeout: 10 * time.Second, // Explicit handshake timeout
		MaxIdleTimeout:       60 * time.Second, // Connection idle timeout
	}
}

// LoginToBase64 encodes a username and password into a base64-encoded string in "username:password" format.
func LoginToBase64(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// ParseECPrivateKey parses a base64-encoded ECDSA private key
func ParseECPrivateKey(privKeyB64 string) (*ecdsa.PrivateKey, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	fmt.Printf("[DEBUG] ParseECPrivateKey: decoded %d bytes\n", len(privKeyBytes))
	fmt.Printf("[DEBUG] ParseECPrivateKey: first 32 bytes: %x\n", privKeyBytes[:min(32, len(privKeyBytes))])

	privKey, err := x509.ParseECPrivateKey(privKeyBytes)
	if err != nil {
		fmt.Printf("[DEBUG] ParseECPrivateKey: x509.ParseECPrivateKey failed: %v\n", err)
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	fmt.Printf("[DEBUG] ParseECPrivateKey: parsed successfully\n")
	fmt.Printf("[DEBUG] ParseECPrivateKey: D bit length: %d\n", privKey.D.BitLen())
	fmt.Printf("[DEBUG] ParseECPrivateKey: D hex: %x\n", privKey.D.Bytes())
	fmt.Printf("[DEBUG] ParseECPrivateKey: Curve: %s\n", privKey.Curve.Params().Name)

	return privKey, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ParseECPublicKeyPEM parses a PEM-encoded ECDSA public key
func ParseECPublicKeyPEM(pemData string) (*ecdsa.PublicKey, error) {
	// Find PEM block in the data
	block := []byte(pemData)

	// Try to parse as PKIX
	pubKey, err := x509.ParsePKIXPublicKey(block)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	return ecPubKey, nil
}
