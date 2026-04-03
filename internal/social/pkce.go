package social

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/palauth/palauth/internal/crypto"
)

// GeneratePKCE generates a PKCE code verifier and S256 code challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	verifier, err = crypto.GenerateToken(32)
	if err != nil {
		return "", "", err
	}
	challenge = computeS256Challenge(verifier)
	return verifier, challenge, nil
}

// computeS256Challenge computes the S256 code challenge from a verifier.
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
