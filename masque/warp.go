package masque

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/netip"

	"github.com/bepass-org/vwarp/warp"
)

// ConvertWarpIdentityToMasque converts a WARP identity to MASQUE-compatible format
func ConvertWarpIdentityToMasque(identity *warp.Identity) (*WarpIdentity, error) {
	if identity == nil {
		return nil, fmt.Errorf("identity is nil")
	}

	ipv4, err := netip.ParseAddr(identity.Config.Interface.Addresses.V4)
	if err != nil {
		return nil, fmt.Errorf("invalid IPv4 address: %w", err)
	}

	ipv6, err := netip.ParseAddr(identity.Config.Interface.Addresses.V6)
	if err != nil {
		return nil, fmt.Errorf("invalid IPv6 address: %w", err)
	}

	return &WarpIdentity{
		PrivateKey: identity.PrivateKey,
		PublicKey:  identity.Config.Peers[0].PublicKey,
		IPv4:       ipv4,
		IPv6:       ipv6,
		ClientID:   identity.Config.ClientID,
		Token:      identity.Token,
		AccountID:  "", // Not available in current warp.Identity
		LicenseKey: "", // Not available in current warp.Identity
	}, nil
}

// GenerateTLSConfigForWarp creates a TLS configuration for connecting to Cloudflare WARP via MASQUE
func GenerateTLSConfigForWarp(privKeyB64 string, peerPubKeyB64 string, sni string) (*tls.Config, error) {
	// Decode private key
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key (base64): %w", err)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyBytes)
	if err != nil {
		// Try alternative parsing methods if the first fails
		if privKeyInterface, err2 := x509.ParsePKCS8PrivateKey(privKeyBytes); err2 == nil {
			if ecKey, ok := privKeyInterface.(*ecdsa.PrivateKey); ok {
				privKey = ecKey
			} else {
				return nil, fmt.Errorf("parsed PKCS8 key is not ECDSA: %T", privKeyInterface)
			}
		} else {
			return nil, fmt.Errorf("failed to parse private key (tried EC and PKCS8): EC=%w, PKCS8=%w", err, err2)
		}
	}

	// Decode peer public key (assuming PEM format)
	block, _ := pem.Decode([]byte(peerPubKeyB64))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block for peer public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}

	peerPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("peer public key is not ECDSA: %T", pubKey)
	}

	// Skip client certificate generation - use usque approach without client certs
	fmt.Printf("[DEBUG] Skipping client certificate generation (using usque approach)\n")

	// Create TLS config without client certificate (like usque)
	return PrepareTLSConfig(privKey, peerPubKey, nil, sni, nil)
}
