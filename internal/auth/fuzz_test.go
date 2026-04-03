package auth

import (
	"testing"

	"github.com/palauth/palauth/internal/crypto"
)

func FuzzSignupValidation(f *testing.F) {
	f.Add("test@example.com", "a-secure-password-here")
	f.Add("", "")
	f.Add("notanemail", "short")
	f.Add("valid@email.com", "this-is-exactly-15!")
	f.Add("a@b.c", "12345678901234567890123456789012345678901234567890123456789012345") // 65 chars

	f.Fuzz(func(t *testing.T, email, password string) {
		// Should never panic — only return errors.
		_ = crypto.ValidatePassword(password)
		_ = normalizeEmail(email)
	})
}

func FuzzNormalizeEmail(f *testing.F) {
	f.Add("Test@Example.COM")
	f.Add("  alice@example.com  ")
	f.Add("")
	f.Add("UPPER@CASE.ORG")

	f.Fuzz(func(t *testing.T, email string) {
		result := normalizeEmail(email)
		// Result should always be lowercase and trimmed.
		if result != normalizeEmail(result) {
			t.Errorf("normalizeEmail is not idempotent for input %q", email)
		}
	})
}
