package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestDeterministicHash_Deterministic(t *testing.T) {
	key := []byte("test-key-for-hashing-1234567890")

	h1 := DeterministicHash("user@example.com", key)
	h2 := DeterministicHash("user@example.com", key)

	assert.Equal(t, h1, h2, "same input must produce same hash")
}

func TestDeterministicHash_DifferentInputs(t *testing.T) {
	key := []byte("test-key-for-hashing-1234567890")

	h1 := DeterministicHash("user1@example.com", key)
	h2 := DeterministicHash("user2@example.com", key)

	assert.NotEqual(t, h1, h2, "different inputs must produce different hashes")
}

func TestDeterministicHash_DifferentKeys(t *testing.T) {
	key1 := []byte("key-one-for-testing-1234567890")
	key2 := []byte("key-two-for-testing-1234567890")

	h1 := DeterministicHash("user@example.com", key1)
	h2 := DeterministicHash("user@example.com", key2)

	assert.NotEqual(t, h1, h2, "different keys must produce different hashes")
}

func TestDeterministicHash_Length(t *testing.T) {
	key := []byte("test-key")
	h := DeterministicHash("data", key)
	// HMAC-SHA256 = 32 bytes = 64 hex characters
	require.Len(t, h, 64, "HMAC-SHA256 hex-encoded should be 64 characters")
}

func TestDeterministicHash_EmptyData(t *testing.T) {
	key := []byte("test-key")
	h := DeterministicHash("", key)
	require.Len(t, h, 64, "empty data should still produce 64-char hex hash")

	hNonEmpty := DeterministicHash("x", key)
	assert.NotEqual(t, h, hNonEmpty, "empty and non-empty should differ")
}

// Property-based test using rapid

func TestRapid_DeterministicHash_Determinism(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.String().Draw(t, "data")
		key := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(t, "key")

		h1 := DeterministicHash(data, key)
		h2 := DeterministicHash(data, key)
		assert.Equal(t, h1, h2, "same input must always produce same output")
	})
}
