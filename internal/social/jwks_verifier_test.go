package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testJWKSSetup creates a test ECDSA key pair, JWKS endpoint, and signer.
type testJWKSSetup struct {
	key      *ecdsa.PrivateKey
	kid      string
	server   *httptest.Server
	signer   jose.Signer
	clientID string
	issuer   string
}

func newTestJWKSSetup(t *testing.T) *testJWKSSetup {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid := "test-key-1"
	clientID := "test-client-id"
	issuer := "https://test-provider.example.com"

	jwk := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(server.Close)

	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	require.NoError(t, err)

	return &testJWKSSetup{
		key:      key,
		kid:      kid,
		server:   server,
		signer:   signer,
		clientID: clientID,
		issuer:   issuer,
	}
}

func (s *testJWKSSetup) signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	token, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func TestJWKSVerifier_ValidToken(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	token := setup.signToken(t, map[string]any{
		"iss":            setup.issuer,
		"aud":            setup.clientID,
		"sub":            "user-123",
		"email":          "user@example.com",
		"email_verified": true,
		"exp":            float64(time.Now().Add(5 * time.Minute).Unix()),
	})

	claims, err := verifier.verifyIDToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, "user@example.com", claims["email"])
}

func TestJWKSVerifier_InvalidSignature(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	// Sign with a different key.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: otherKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", setup.kid),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(otherSigner).Claims(map[string]any{
		"iss": setup.issuer,
		"aud": setup.clientID,
		"sub": "attacker",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
	}).Serialize()
	require.NoError(t, err)

	_, err = verifier.verifyIDToken(context.Background(), token)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestJWKSVerifier_WrongAudience(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	token := setup.signToken(t, map[string]any{
		"iss": setup.issuer,
		"aud": "wrong-client-id",
		"sub": "user-123",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
	})

	_, err := verifier.verifyIDToken(context.Background(), token)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestJWKSVerifier_WrongIssuer(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	token := setup.signToken(t, map[string]any{
		"iss": "https://evil.example.com",
		"aud": setup.clientID,
		"sub": "user-123",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
	})

	_, err := verifier.verifyIDToken(context.Background(), token)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestJWKSVerifier_ExpiredToken(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	token := setup.signToken(t, map[string]any{
		"iss": setup.issuer,
		"aud": setup.clientID,
		"sub": "user-123",
		"exp": float64(time.Now().Add(-5 * time.Minute).Unix()),
	})

	_, err := verifier.verifyIDToken(context.Background(), token)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestJWKSVerifier_MissingExp(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	token := setup.signToken(t, map[string]any{
		"iss": setup.issuer,
		"aud": setup.clientID,
		"sub": "user-123",
	})

	_, err := verifier.verifyIDToken(context.Background(), token)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestJWKSVerifier_ForgedToken_NoCryptoVerification(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	// Craft a fake JWT with no valid signature — should be rejected.
	_, err := verifier.verifyIDToken(context.Background(), "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.invalid")
	assert.Error(t, err)
}

func TestJWKSVerifier_AudienceArray(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	token := setup.signToken(t, map[string]any{
		"iss": setup.issuer,
		"aud": []string{setup.clientID, "other-client"},
		"sub": "user-123",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
	})

	claims, err := verifier.verifyIDToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims["sub"])
}

func TestJWKSVerifier_EmptyIssuer_SkipsCheck(t *testing.T) {
	setup := newTestJWKSSetup(t)
	// Empty issuer means skip issuer validation (used for Microsoft "common" tenant).
	verifier := newJWKSVerifier(setup.server.URL, "", setup.clientID)

	token := setup.signToken(t, map[string]any{
		"iss": "https://any-issuer.example.com",
		"aud": setup.clientID,
		"sub": "user-123",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
	})

	claims, err := verifier.verifyIDToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims["sub"])
}

func TestJWKSVerifier_CacheTTL(t *testing.T) {
	setup := newTestJWKSSetup(t)
	verifier := newJWKSVerifier(setup.server.URL, setup.issuer, setup.clientID)

	token := setup.signToken(t, map[string]any{
		"iss": setup.issuer,
		"aud": setup.clientID,
		"sub": "user-123",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
	})

	// First call fetches from server.
	_, err := verifier.verifyIDToken(context.Background(), token)
	require.NoError(t, err)

	// Second call should use cache — even if server is down, it should work.
	setup.server.Close()
	token2 := setup.signToken(t, map[string]any{
		"iss": setup.issuer,
		"aud": setup.clientID,
		"sub": "user-456",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
	})
	_, err = verifier.verifyIDToken(context.Background(), token2)
	require.NoError(t, err)
}
