package token

import (
	"bytes"
	"log/slog"
	"testing"
)

func FuzzJWTVerify(f *testing.F) {
	f.Add("not-a-jwt")
	f.Add("eyJhbGciOiJQUzI1NiJ9.e30.invalid")
	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake")
	f.Add("eyJhbGciOiJub25lIn0.e30.")

	svc, err := NewJWTService(JWTConfig{
		Algorithm: AlgPS256,
		Logger:    slog.Default(),
	})
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, tokenStr string) {
		// Should never panic, only return errors.
		_, _ = svc.Verify(tokenStr)
	})
}

func FuzzHashToken(f *testing.F) {
	f.Add("test-token-1")
	f.Add("")
	f.Add("a-very-long-token-string-that-goes-on-and-on")

	f.Fuzz(func(t *testing.T, token string) {
		hash := hashToken(token)
		if len(hash) != 32 {
			t.Errorf("hash length should be 32, got %d", len(hash))
		}
		// Determinism check.
		hash2 := hashToken(token)
		if !bytes.Equal(hash, hash2) {
			t.Fatal("hashToken must be deterministic")
		}
	})
}
