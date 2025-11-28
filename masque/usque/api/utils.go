package api

import (
	"github.com/bepass-org/vwarp/masque/usque/internal"
)

// Re-export internal utilities that need to be accessible from the masque package

// GenerateEcKeyPair generates a new ECDSA key pair using the P-256 curve
func GenerateEcKeyPair() ([]byte, []byte, error) {
	return internal.GenerateEcKeyPair()
}
