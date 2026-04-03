package mfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMFATokenConstants(t *testing.T) {
	// MFA token TTL is 5 minutes (PSD2 RTS max 5dk auth code lifetime).
	assert.Equal(t, 5*time.Minute, MFATokenTTL)

	// Token is 256-bit (32 bytes).
	assert.Equal(t, 32, MFATokenBytes)
}

func TestMFATokenKeyFormat(t *testing.T) {
	key := mfaTokenKey("abc123")
	assert.Equal(t, "palauth:mfa_token:abc123", key)
}
