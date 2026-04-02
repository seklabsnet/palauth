package token

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKS_Format(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	jwks := svc.PublicKeys()
	require.Len(t, jwks.Keys, 1)

	// Verify it serializes to valid JSON.
	data, err := json.Marshal(jwks)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	keys, ok := parsed["keys"].([]any)
	require.True(t, ok)
	require.Len(t, keys, 1)

	key := keys[0].(map[string]any)
	assert.Equal(t, "sig", key["use"])
	assert.NotEmpty(t, key["kid"])
	assert.Equal(t, "PS256", key["alg"])
	assert.Equal(t, "RSA", key["kty"])
}

func TestJWKS_MultipleKeys(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)
	err := svc.GenerateKey(AlgES256)
	require.NoError(t, err)

	jwks := svc.PublicKeys()
	require.Len(t, jwks.Keys, 2)

	// First key: PS256/RSA.
	assert.Equal(t, "PS256", jwks.Keys[0].Algorithm)
	// Second key: ES256/EC.
	assert.Equal(t, "ES256", jwks.Keys[1].Algorithm)

	// Both should be public keys.
	for _, k := range jwks.Keys {
		assert.True(t, k.IsPublic())
		assert.NotEmpty(t, k.KeyID)
		assert.Equal(t, "sig", k.Use)
	}
}

func TestJWKS_ES256Format(t *testing.T) {
	svc := newTestJWTService(t, AlgES256)

	jwks := svc.PublicKeys()
	data, err := json.Marshal(jwks)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	keys := parsed["keys"].([]any)
	key := keys[0].(map[string]any)
	assert.Equal(t, "EC", key["kty"])
	assert.Equal(t, "ES256", key["alg"])
	assert.Equal(t, "P-256", key["crv"])
}
