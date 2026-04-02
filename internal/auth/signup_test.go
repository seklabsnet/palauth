package auth

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA1 required for HIBP k-Anonymity mock
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/palauth/palauth/internal/crypto"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

const testPepper = "this-is-a-test-pepper-at-least-32-bytes-long-ok"

func TestSignup_EmailRequired(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	_, err := svc.Signup(context.Background(), "", "validpassword1234", "prj_test")
	assert.ErrorIs(t, err, ErrEmailRequired)
}

func TestSignup_PasswordRequired(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	_, err := svc.Signup(context.Background(), "test@example.com", "", "prj_test")
	assert.ErrorIs(t, err, ErrPasswordRequired)
}

func TestSignup_InvalidEmail(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	_, err := svc.Signup(context.Background(), "not-an-email", "validpassword1234", "prj_test")
	assert.ErrorIs(t, err, ErrEmailRequired)
}

func TestSignup_WeakPassword_TooShort(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	_, err := svc.Signup(context.Background(), "test@example.com", "short14chars!!", "prj_test")
	assert.ErrorIs(t, err, crypto.ErrPasswordTooShort)
}

func TestSignup_WeakPassword_TooLong(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	longPw := make([]byte, 65)
	for i := range longPw {
		longPw[i] = 'a'
	}
	_, err := svc.Signup(context.Background(), "test@example.com", string(longPw), "prj_test")
	assert.ErrorIs(t, err, crypto.ErrPasswordTooLong)
}

func TestSignup_BreachedPassword(t *testing.T) {
	// Compute SHA1 of our test password to return matching HIBP suffix.
	password := "password123456789"
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
	svc := NewService(nil, nil, nil, nil, nil, bc, nil, testPepper, nil, testLogger)
	_, err := svc.Signup(context.Background(), "test@example.com", password, "prj_test")
	assert.ErrorIs(t, err, crypto.ErrPasswordBreached)
}

func TestSignup_HIBPUnavailable_FailClosed(t *testing.T) {
	// HIBP server returns 500 — signup must fail closed.
	hibpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer hibpServer.Close()

	bc := crypto.NewBreachCheckerWithURL(hibpServer.URL + "/range/")
	svc := NewService(nil, nil, nil, nil, nil, bc, nil, testPepper, nil, testLogger)
	_, err := svc.Signup(context.Background(), "test@example.com", "validpassword1234", "prj_test")
	assert.ErrorIs(t, err, ErrHIBPUnavailable)
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "Alice@Example.COM", "alice@example.com"},
		{"trim spaces", "  test@example.com  ", "test@example.com"},
		{"mixed case with spaces", "  User@DOMAIN.com ", "user@domain.com"},
		{"already normalized", "test@example.com", "test@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, normalizeEmail(tc.input))
		})
	}
}

func TestSha256Hash(t *testing.T) {
	hash := sha256Hash("test")
	require.Len(t, hash, 32, "SHA-256 produces 32 bytes")

	// Same input produces same output.
	hash2 := sha256Hash("test")
	assert.Equal(t, hash, hash2)

	// Different input produces different output.
	hash3 := sha256Hash("other")
	assert.NotEqual(t, hash, hash3)
}

func TestConstantTimeTokenCompare(t *testing.T) {
	a := sha256Hash("token1")
	b := sha256Hash("token1")
	c := sha256Hash("token2")

	assert.True(t, constantTimeTokenCompare(a, b), "same tokens should match")
	assert.False(t, constantTimeTokenCompare(a, c), "different tokens should not match")
}

func TestEmailHashBytes(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)

	hash1, err := svc.emailHashBytes("test@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, hash1)

	// Same email produces same hash.
	hash2, err := svc.emailHashBytes("test@example.com")
	require.NoError(t, err)
	assert.Equal(t, hash1, hash2)

	// Different email produces different hash.
	hash3, err := svc.emailHashBytes("other@example.com")
	require.NoError(t, err)
	assert.NotEqual(t, hash1, hash3)
}
