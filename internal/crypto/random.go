package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

// GenerateToken generates a cryptographically secure random token.
// length is the byte count; the returned hex string is 2x length.
func GenerateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateOTP generates a numeric OTP with the specified number of digits using crypto/rand.
func GenerateOTP(digits int) (string, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}

	return fmt.Sprintf("%0*d", digits, n), nil
}
