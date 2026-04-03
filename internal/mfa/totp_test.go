package mfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTOTPConstants(t *testing.T) {
	assert.Equal(t, "PalAuth", TOTPIssuer)
	assert.Equal(t, 30, int(TOTPPeriod))
	assert.Equal(t, 6, TOTPDigits)
	// Skew of 2 allows ±60s clock drift (2 periods of 30s each direction).
	assert.Equal(t, 2, int(TOTPSkew))
	// Replay window covers the full skew window.
	assert.Equal(t, 90, replayWindowSec)
}
