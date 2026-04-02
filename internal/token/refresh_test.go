package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestHashToken(t *testing.T) {
	hash1 := hashToken("test-token-1")
	hash2 := hashToken("test-token-2")
	hash3 := hashToken("test-token-1")

	assert.Len(t, hash1, 32) // SHA-256 = 32 bytes
	assert.Len(t, hash2, 32)
	assert.Equal(t, hash1, hash3, "same input should produce same hash")
	assert.NotEqual(t, hash1, hash2, "different input should produce different hash")
}

func TestHashToken_Deterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		token := rapid.String().Draw(t, "token")
		h1 := hashToken(token)
		h2 := hashToken(token)
		if len(h1) != 32 {
			t.Fatalf("hash length should be 32, got %d", len(h1))
		}
		for i := range h1 {
			if h1[i] != h2[i] {
				t.Fatal("hash should be deterministic")
			}
		}
	})
}

func TestRefreshTokenConstants(t *testing.T) {
	assert.Equal(t, 32, RefreshTokenBytes)
	require.Positive(t, GracePeriod.Seconds())
	require.Positive(t, DefaultRefreshTTL.Hours())
}
