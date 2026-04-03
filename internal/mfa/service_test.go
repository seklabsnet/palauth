package mfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMFAErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"not enrolled", ErrMFANotEnrolled, "MFA is not enrolled"},
		{"already verified", ErrMFAAlreadyVerified, "MFA enrollment is already verified"},
		{"invalid code", ErrInvalidCode, "invalid code"},
		{"lockout", ErrMFALockout, "MFA is locked due to too many failed attempts"},
		{"token expired", ErrMFATokenExpired, "MFA token has expired"},
		{"token invalid", ErrMFATokenInvalid, "MFA token is invalid"},
		{"replay", ErrReplayDetected, "code has already been used"},
		{"max attempts", ErrMaxOTPAttempts, "maximum OTP attempts exceeded, request a new code"},
		{"no recovery codes", ErrNoRecoveryCodesLeft, "no recovery codes remaining"},
		{"reauth required", ErrReauthRequired, "re-authentication is required"},
		{"email not verified", ErrEmailNotVerified, "email must be verified before enrolling email OTP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}
