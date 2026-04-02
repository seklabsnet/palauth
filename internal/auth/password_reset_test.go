package auth

import (
	"crypto/sha1" //nolint:gosec // SHA1 required for HIBP k-Anonymity mock
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/palauth/palauth/internal/crypto"
)

func TestRequestReset_EmptyEmail_ReturnsNil(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, testLogger)

	// Should return nil even with empty email (enumeration prevention).
	err := svc.RequestReset(t.Context(), "prj_test", "")
	assert.NoError(t, err)
}

func TestConfirmReset_EmptyToken_Error(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, testLogger)
	err := svc.ConfirmReset(t.Context(), "prj_test", "", "new-password-1234!")
	assert.ErrorIs(t, err, ErrTokenRequired)
}

func TestConfirmReset_ErrorTypes_Defined(t *testing.T) {
	// Verify all error types used in password reset are properly defined and distinct.
	errors := []error{
		ErrTokenRequired,
		ErrTokenUsed,
		ErrTokenExpired,
		ErrTokenNotFound,
		ErrHIBPUnavailable,
		crypto.ErrPasswordTooShort,
		crypto.ErrPasswordTooLong,
		crypto.ErrPasswordBreached,
		crypto.ErrPasswordReused,
	}
	for i, e := range errors {
		assert.NotNil(t, e)
		assert.NotEmpty(t, e.Error())
		// Verify each error is distinct from others.
		for j, other := range errors {
			if i != j {
				assert.NotEqual(t, e.Error(), other.Error(), "errors at index %d and %d should be distinct", i, j)
			}
		}
	}
}

func TestBreachChecker_DetectsBreachedPassword(t *testing.T) {
	password := "breached-password-1234!"
	h := sha1.New() //nolint:gosec // SHA1 required for HIBP k-Anonymity
	h.Write([]byte(password))
	fullHash := fmt.Sprintf("%X", h.Sum(nil))
	suffix := fullHash[5:]

	hibpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(suffix + ":999\r\n"))
	}))
	defer hibpServer.Close()

	bc := crypto.NewBreachCheckerWithURL(hibpServer.URL + "/range/")
	breached, err := bc.Check(t.Context(), password)
	assert.NoError(t, err)
	assert.True(t, breached, "password should be detected as breached")
}

func TestBreachChecker_NotBreached(t *testing.T) {
	hibpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:0\r\n"))
	}))
	defer hibpServer.Close()

	bc := crypto.NewBreachCheckerWithURL(hibpServer.URL + "/range/")
	breached, err := bc.Check(t.Context(), "not-a-breached-password-xyz!")
	assert.NoError(t, err)
	assert.False(t, breached, "password should not be detected as breached")
}

func TestPasswordValidation_TooShort(t *testing.T) {
	err := crypto.ValidatePassword("14charpasswrd!")
	assert.ErrorIs(t, err, crypto.ErrPasswordTooShort)
}

func TestPasswordValidation_TooLong(t *testing.T) {
	longPw := make([]byte, 65)
	for i := range longPw {
		longPw[i] = 'a'
	}
	err := crypto.ValidatePassword(string(longPw))
	assert.ErrorIs(t, err, crypto.ErrPasswordTooLong)
}

func TestPasswordValidation_Valid(t *testing.T) {
	err := crypto.ValidatePassword("this-is-a-valid-password!")
	assert.NoError(t, err)
}

func TestPasswordValidation_Exactly15Chars(t *testing.T) {
	err := crypto.ValidatePassword("exactly15chars!")
	assert.NoError(t, err, "15 chars should be valid (minimum)")
}

func TestPasswordValidation_Exactly64Chars(t *testing.T) {
	pw := make([]byte, 64)
	for i := range pw {
		pw[i] = 'a'
	}
	err := crypto.ValidatePassword(string(pw))
	assert.NoError(t, err, "64 chars should be valid (maximum)")
}
