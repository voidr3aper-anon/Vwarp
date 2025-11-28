package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// Cloudflare API constants
	APIUrl     = "https://api.cloudflareclient.com"
	APIVersion = "v0a4471"
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	ConnectURI = "https://cloudflareaccess.com"
)

// GenerateECKeyPair generates a new ECDSA key pair using P-256 curve
func GenerateECKeyPair() ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	marshalledPrivKey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	marshalledPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return marshalledPrivKey, marshalledPubKey, nil
}

// GenerateSelfSignedCert creates a self-signed certificate
func GenerateSelfSignedCert(privKey *ecdsa.PrivateKey) ([][]byte, error) {
	// Debug: validate private key before certificate generation
	if privKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if privKey.D == nil || privKey.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key: D value is nil or non-positive")
	}
	if privKey.PublicKey.X == nil || privKey.PublicKey.Y == nil {
		return nil, fmt.Errorf("invalid public key: X or Y is nil")
	}

	fmt.Printf("[DEBUG] GenerateCert: privKey.D bit length: %d\n", privKey.D.BitLen())
	fmt.Printf("[DEBUG] GenerateCert: curve params P bit length: %d\n", privKey.Curve.Params().P.BitLen())

	// Use minimal certificate template like usque - Cloudflare doesn't validate these fields
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 24 * time.Hour),
	}

	// Use exact same certificate generation as usque for compatibility
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		fmt.Printf("[DEBUG] Certificate generation failed: %v\n", err)
		return nil, err
	}

	fmt.Printf("[DEBUG] GenerateCert: certificate created successfully, size: %d bytes\n", len(cert))
	return [][]byte{cert}, nil
}

// GenerateRandomSerial generates a random device serial number
func GenerateRandomSerial() (string, error) {
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return "", err
	}
	return hex.EncodeToString(serial), nil
}

// GenerateRandomWgPubkey generates a random WireGuard-like public key
func GenerateRandomWgPubkey() (string, error) {
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

// DefaultQUICConfig returns a MASQUE-compatible QUIC configuration
func DefaultQUICConfig(keepalivePeriod time.Duration, initialPacketSize uint16) *quic.Config {
	// Match usque's exact QUIC configuration
	return &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: initialPacketSize,
		KeepAlivePeriod:   keepalivePeriod,
	}
}

// TimeFormatCloudflare formats time for Cloudflare API
func TimeFormatCloudflare(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-07:00")
}

// ParseECPrivateKey parses a base64-encoded or PEM-encoded EC private key
func ParseECPrivateKey(data string) (*ecdsa.PrivateKey, error) {
	// Try to parse as PEM first
	block, _ := pem.Decode([]byte(data))
	if block != nil && block.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	}

	// Try as base64-encoded DER
	derData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	privKey, err := x509.ParseECPrivateKey(derData)
	if err != nil {
		// Debug: log key format info
		fmt.Printf("[DEBUG] Private key parsing failed: %v\n", err)
		fmt.Printf("[DEBUG] Key data length: %d bytes\n", len(derData))
		fmt.Printf("[DEBUG] Key data (first 32 bytes): %x\n", derData[:min(32, len(derData))])
		return nil, err
	}

	// Validate parsed key
	if privKey.D == nil || privKey.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key: D value is nil or non-positive")
	}

	fmt.Printf("[DEBUG] Private key parsed successfully, D byte length: %d\n", len(privKey.D.Bytes()))
	return privKey, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ParseECPublicKey parses a PEM-encoded EC public key
func ParseECPublicKey(pemData []byte) (*ecdsa.PublicKey, error) {
	// Decode PEM
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecPubKey, nil
}
