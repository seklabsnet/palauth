package mfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEmailOTPConstants(t *testing.T) {
	assert.Equal(t, 6, EmailOTPDigits)
	assert.Equal(t, 5*time.Minute, EmailOTPTTL)
	assert.Equal(t, 3, EmailOTPMaxAttempts)
}

func TestEmailOTPKeyFormat(t *testing.T) {
	otpKey := emailOTPKey("prj_123", "usr_456")
	assert.Equal(t, "palauth:email_otp:prj_123:usr_456:code", otpKey)

	attemptsKey := emailOTPAttemptsKey("prj_123", "usr_456")
	assert.Equal(t, "palauth:email_otp:prj_123:usr_456:attempts", attemptsKey)
}
