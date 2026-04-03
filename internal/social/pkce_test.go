package social

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestGeneratePKCE(t *testing.T) {
	t.Run("generates valid verifier and challenge", func(t *testing.T) {
		verifier, challenge, err := GeneratePKCE()
		require.NoError(t, err)

		assert.Len(t, verifier, 64) // 32 bytes hex-encoded
		assert.NotEmpty(t, challenge)

		// Verify S256 relationship.
		h := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(h[:])
		assert.Equal(t, expected, challenge)
	})

	t.Run("generates unique values each time", func(t *testing.T) {
		v1, c1, err := GeneratePKCE()
		require.NoError(t, err)

		v2, c2, err := GeneratePKCE()
		require.NoError(t, err)

		assert.NotEqual(t, v1, v2)
		assert.NotEqual(t, c1, c2)
	})
}

func TestComputeS256Challenge(t *testing.T) {
	// Known test vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	challenge := computeS256Challenge(verifier)
	assert.Equal(t, expected, challenge)
}

func TestGeneratePKCE_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		verifier, challenge, err := GeneratePKCE()
		if err != nil {
			t.Fatal(err)
		}

		// Verifier should always be 64 hex chars.
		if len(verifier) != 64 {
			t.Fatalf("expected verifier length 64, got %d", len(verifier))
		}

		// Challenge should always match S256 of verifier.
		h := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(h[:])
		if challenge != expected {
			t.Fatalf("challenge mismatch: %s != %s", challenge, expected)
		}
	})
}
