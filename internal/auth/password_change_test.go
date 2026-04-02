package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/palauth/palauth/internal/crypto"
)

func TestChangePassword_EmptyCurrentPassword(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, testLogger)
	err := svc.ChangePassword(t.Context(), "prj_test", "usr_test", "", "new-password-1234!")
	assert.ErrorIs(t, err, ErrCurrentPasswordRequired)
}

func TestChangePassword_EmptyNewPassword(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, testLogger)
	err := svc.ChangePassword(t.Context(), "prj_test", "usr_test", "current-pass-1234!", "")
	assert.ErrorIs(t, err, ErrNewPasswordRequired)
}

func TestChangePassword_ErrorTypes_Defined(t *testing.T) {
	// Verify all error types used in password change are properly defined.
	errors := []error{
		ErrCurrentPasswordRequired,
		ErrNewPasswordRequired,
		ErrInvalidCredentials,
		ErrUserNotFound,
		crypto.ErrPasswordTooShort,
		crypto.ErrPasswordTooLong,
		crypto.ErrPasswordBreached,
		crypto.ErrPasswordReused,
		ErrHIBPUnavailable,
	}
	for _, e := range errors {
		assert.NotNil(t, e)
		assert.NotEmpty(t, e.Error())
	}
}

func TestChangePassword_BothEmpty(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, testLogger)
	// Current password is checked first.
	err := svc.ChangePassword(t.Context(), "prj_test", "usr_test", "", "")
	assert.ErrorIs(t, err, ErrCurrentPasswordRequired)
}

func TestPasswordHistory_CheckReuse(t *testing.T) {
	// Unit test for crypto.CheckPasswordHistory.
	hash1, err := crypto.Hash("first-password-12345!", testPepper)
	assert.NoError(t, err)

	hash2, err := crypto.Hash("second-password-6789!", testPepper)
	assert.NoError(t, err)

	history := []string{hash1, hash2}

	// Reusing first password should fail.
	err = crypto.CheckPasswordHistory("first-password-12345!", history, testPepper)
	assert.ErrorIs(t, err, crypto.ErrPasswordReused)

	// Reusing second password should fail.
	err = crypto.CheckPasswordHistory("second-password-6789!", history, testPepper)
	assert.ErrorIs(t, err, crypto.ErrPasswordReused)

	// New password should succeed.
	err = crypto.CheckPasswordHistory("completely-new-password!", history, testPepper)
	assert.NoError(t, err)
}

func TestPasswordHistory_EmptyHistory(t *testing.T) {
	// Empty history should always pass.
	err := crypto.CheckPasswordHistory("any-password-1234567!", nil, testPepper)
	assert.NoError(t, err)

	err = crypto.CheckPasswordHistory("any-password-1234567!", []string{}, testPepper)
	assert.NoError(t, err)
}
