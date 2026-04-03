package mfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMFALockoutConstants(t *testing.T) {
	// MFA lockout threshold is 5 (PSD2 RTS), different from password lockout (10).
	assert.Equal(t, 5, MFALockoutThreshold)
	assert.Equal(t, 30*60, int(MFALockoutDuration.Seconds()))
}

func TestMFALockoutKeyFormat(t *testing.T) {
	countKey := mfaCountKey("prj_123", "usr_456")
	assert.Equal(t, "palauth:mfa_lockout:prj_123:usr_456:count", countKey)

	lockedKey := mfaLockedKey("prj_123", "usr_456")
	assert.Equal(t, "palauth:mfa_lockout:prj_123:usr_456:locked", lockedKey)
}
