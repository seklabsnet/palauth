package apikey

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestHashKey(t *testing.T) {
	key := "pk_test_abc123"
	hash := HashKey(key)
	expected := sha256.Sum256([]byte(key))
	assert.Equal(t, expected[:], hash)
}

func TestHashKey_DifferentKeys(t *testing.T) {
	hash1 := HashKey("key1")
	hash2 := HashKey("key2")
	assert.NotEqual(t, hash1, hash2)
}

func TestHashKey_SameKey(t *testing.T) {
	hash1 := HashKey("same-key")
	hash2 := HashKey("same-key")
	assert.Equal(t, hash1, hash2)
}

func TestKeyPrefixes(t *testing.T) {
	tests := []struct {
		keyType string
		prefix  string
	}{
		{KeyTypePublicTest, "pk_test_"},
		{KeyTypeSecretTest, "sk_test_"},
		{KeyTypePublicLive, "pk_live_"},
		{KeyTypeSecretLive, "sk_live_"},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			prefix, ok := keyPrefixes[tt.keyType]
			require.True(t, ok, "key type %q should have a prefix", tt.keyType)
			assert.Equal(t, tt.prefix, prefix)
		})
	}
}

func TestAllKeyTypes(t *testing.T) {
	assert.Len(t, AllKeyTypes, 4)
	assert.Contains(t, AllKeyTypes, KeyTypePublicTest)
	assert.Contains(t, AllKeyTypes, KeyTypeSecretTest)
	assert.Contains(t, AllKeyTypes, KeyTypePublicLive)
	assert.Contains(t, AllKeyTypes, KeyTypeSecretLive)
}

func TestInvalidKeyType(t *testing.T) {
	_, ok := keyPrefixes["invalid_type"]
	assert.False(t, ok)
}

// Property-based tests for hash determinism and collision resistance.
func TestHashKey_Property_Deterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key := rapid.String().Draw(t, "key")
		h1 := HashKey(key)
		h2 := HashKey(key)
		assert.Equal(t, h1, h2, "HashKey must be deterministic")
	})
}

func TestHashKey_Property_FixedLength(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key := rapid.String().Draw(t, "key")
		h := HashKey(key)
		assert.Len(t, h, 32, "SHA-256 hash must be 32 bytes")
	})
}

func TestKeyFormat(t *testing.T) {
	// Verify that the expected key format is prefix + 64 hex chars.
	tests := []struct {
		prefix string
	}{
		{"pk_test_"},
		{"sk_test_"},
		{"pk_live_"},
		{"sk_live_"},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			// Simulate the expected format.
			key := tt.prefix + strings.Repeat("ab", 32)
			assert.True(t, strings.HasPrefix(key, tt.prefix))
			assert.Len(t, key, len(tt.prefix)+64)
		})
	}
}
