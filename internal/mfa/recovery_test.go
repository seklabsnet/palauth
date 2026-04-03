package mfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecoveryCodeConstants(t *testing.T) {
	assert.Equal(t, 10, RecoveryCodeCount)
	assert.Equal(t, 5, RecoveryCodeLength) // 5 bytes = 8 base32 chars
}

func TestPadRecoveryCode(t *testing.T) {
	// Recovery codes are 8 chars but Argon2id needs 15+ chars.
	code := "abcdefgh"
	padded := padRecoveryCode(code)
	assert.Equal(t, "palauth-rc:abcdefgh", padded)
	assert.GreaterOrEqual(t, len(padded), 15)
}

func TestPadRecoveryCodeMinLength(t *testing.T) {
	// Padding prefix is "palauth-rc:" (11 chars), so even a 4-char code gives 15+ chars.
	fourCharCode := "abcd"
	padded := padRecoveryCode(fourCharCode)
	assert.GreaterOrEqual(t, len(padded), 15)

	// Actual recovery codes are 8 chars, so 11+8=19 chars.
	eightCharCode := "abcdefgh"
	padded = padRecoveryCode(eightCharCode)
	assert.Equal(t, 19, len(padded))
}
