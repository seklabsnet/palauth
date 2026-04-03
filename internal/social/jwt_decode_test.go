package social

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeJWTPayload(t *testing.T) {
	t.Run("valid JWT", func(t *testing.T) {
		payload := map[string]any{
			"sub":            "1234567890",
			"email":          "test@example.com",
			"email_verified": true,
			"name":           "Test User",
		}
		payloadJSON, _ := json.Marshal(payload)
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
		body := base64.RawURLEncoding.EncodeToString(payloadJSON)
		sig := base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))
		token := header + "." + body + "." + sig

		claims, err := decodeJWTPayload(token)
		require.NoError(t, err)
		assert.Equal(t, "1234567890", claims["sub"])
		assert.Equal(t, "test@example.com", claims["email"])
		assert.Equal(t, true, claims["email_verified"])
		assert.Equal(t, "Test User", claims["name"])
	})

	t.Run("invalid format - not 3 parts", func(t *testing.T) {
		_, err := decodeJWTPayload("not.a.valid.jwt.token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid JWT format")
	})

	t.Run("invalid format - 2 parts", func(t *testing.T) {
		_, err := decodeJWTPayload("only.two")
		assert.Error(t, err)
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		_, err := decodeJWTPayload("header.!!!invalid!!!.sig")
		assert.Error(t, err)
	})

	t.Run("invalid JSON payload", func(t *testing.T) {
		notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
		_, err := decodeJWTPayload("header." + notJSON + ".sig")
		assert.Error(t, err)
	})
}
