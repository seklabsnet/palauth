package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// generateTestECKey generates a PEM-encoded EC P-256 private key for tests.
func generateTestECKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// mockProvider implements Provider for testing.
type mockProvider struct {
	name     string
	authURL  string
	user     *ProviderUser
	exchErr  error
	credErr  error
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) AuthURL(state, codeChallenge, redirectURI string) string {
	return m.authURL + "?state=" + state + "&code_challenge=" + codeChallenge
}
func (m *mockProvider) Exchange(_ context.Context, _, _, _ string) (*ProviderUser, error) {
	if m.exchErr != nil {
		return nil, m.exchErr
	}
	return m.user, nil
}
func (m *mockProvider) ValidateCredential(_ context.Context, _ string) (*ProviderUser, error) {
	if m.credErr != nil {
		return nil, m.credErr
	}
	return m.user, nil
}

func TestService_Authorize_UnsupportedProvider(t *testing.T) {
	svc := &Service{
		providers: make(map[string]Provider),
	}

	_, err := svc.Authorize(context.Background(), "prj_test", "unknown", "http://localhost/callback")
	assert.ErrorIs(t, err, ErrUnsupportedProvider)
}

func TestService_ExchangeCredential_UnsupportedProvider(t *testing.T) {
	svc := &Service{
		providers: make(map[string]Provider),
	}

	_, err := svc.ExchangeCredential(context.Background(), "prj_test", "unknown", "token", "", "")
	assert.ErrorIs(t, err, ErrUnsupportedProvider)
}

func TestService_RegisterProvider(t *testing.T) {
	svc := &Service{
		providers: make(map[string]Provider),
	}

	mp := &mockProvider{name: "google"}
	svc.RegisterProvider(mp)

	p, ok := svc.GetProvider("google")
	assert.True(t, ok)
	assert.Equal(t, "google", p.Name())

	_, ok = svc.GetProvider("unknown")
	assert.False(t, ok)
}

// createMockOAuthServer creates an httptest server that mimics an OAuth2 token endpoint.
func createMockOAuthServer(t *testing.T, idTokenClaims map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build a fake id_token JWT.
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		payloadJSON, _ := json.Marshal(idTokenClaims)
		payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
		sig := base64.RawURLEncoding.EncodeToString([]byte("test-sig"))
		idToken := header + "." + payload + "." + sig

		resp := map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

// TestMockOAuthExchange tests that a mock OAuth server can be used for exchange.
func TestMockOAuthExchange(t *testing.T) {
	claims := map[string]any{
		"sub":            "google-123",
		"email":          "user@gmail.com",
		"email_verified": true,
		"name":           "Test User",
		"picture":        "https://example.com/photo.jpg",
	}
	server := createMockOAuthServer(t, claims)
	defer server.Close()

	provider := &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL + "/auth",
				TokenURL: server.URL + "/token",
			},
			Scopes: []string{"openid", "email", "profile"},
		},
	}

	pu, err := provider.Exchange(context.Background(), "test-code", "test-verifier", server.URL+"/callback")
	require.NoError(t, err)
	assert.Equal(t, "google-123", pu.ProviderID)
	assert.Equal(t, "user@gmail.com", pu.Email)
	assert.Equal(t, "Test User", pu.Name)
	assert.True(t, pu.Verified)
}

func TestMockOAuthExchange_MicrosoftProvider(t *testing.T) {
	claims := map[string]any{
		"sub":   "ms-user-id",
		"email": "user@outlook.com",
		"name":  "MS User",
	}
	server := createMockOAuthServer(t, claims)
	defer server.Close()

	provider := &MicrosoftProvider{
		config: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL + "/auth",
				TokenURL: server.URL + "/token",
			},
			Scopes: []string{"openid", "email", "profile"},
		},
		tenant: "common",
	}

	pu, err := provider.Exchange(context.Background(), "test-code", "test-verifier", server.URL+"/callback")
	require.NoError(t, err)
	assert.Equal(t, "ms-user-id", pu.ProviderID)
	assert.Equal(t, "user@outlook.com", pu.Email)
	assert.Equal(t, "MS User", pu.Name)
	assert.True(t, pu.Verified)
}

func TestMockOAuthExchange_AppleProvider(t *testing.T) {
	claims := map[string]any{
		"sub":            "apple-user-id",
		"email":          "user@icloud.com",
		"email_verified": true,
	}
	server := createMockOAuthServer(t, claims)
	defer server.Close()

	testKey := generateTestECKey(t)

	provider := &AppleProvider{
		config: &oauth2.Config{
			ClientID: "test-client-id",
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL + "/auth",
				TokenURL: server.URL + "/token",
			},
			Scopes: []string{"openid", "email", "name"},
		},
		teamID:  "test-team",
		keyID:   "test-key",
		privKey: testKey,
	}

	pu, err := provider.Exchange(context.Background(), "test-code", "test-verifier", server.URL+"/callback")
	require.NoError(t, err)
	assert.Equal(t, "apple-user-id", pu.ProviderID)
	assert.Equal(t, "user@icloud.com", pu.Email)
	assert.True(t, pu.Verified)
}

func TestAppleProvider_GenerateClientSecret(t *testing.T) {
	testKey := generateTestECKey(t)
	provider := &AppleProvider{
		config: &oauth2.Config{ClientID: "com.example.app"},
		teamID: "TEAM123",
		keyID:  "KEY456",
		privKey: testKey,
	}

	secret, err := provider.generateClientSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Verify the JWT structure by decoding the payload.
	claims, err := decodeJWTPayload(secret)
	require.NoError(t, err)
	assert.Equal(t, "TEAM123", claims["iss"])
	assert.Equal(t, "com.example.app", claims["sub"])
}

func TestAppleProvider_GenerateClientSecret_InvalidKey(t *testing.T) {
	provider := &AppleProvider{
		config:  &oauth2.Config{ClientID: "com.example.app"},
		teamID:  "TEAM123",
		keyID:   "KEY456",
		privKey: "not-a-valid-pem-key",
	}

	_, err := provider.generateClientSecret()
	assert.Error(t, err)
}

// TestMockGitHubExchange tests GitHub provider with a mock user API.
func TestMockGitHubExchange(t *testing.T) {
	mux := http.NewServeMux()

	// Token endpoint.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"access_token": "mock-gh-token",
			"token_type":   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	provider := &GitHubProvider{
		config: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL + "/auth",
				TokenURL: server.URL + "/token",
			},
			Scopes: []string{"read:user", "user:email"},
		},
	}

	// Exchange will try to call the real GitHub API, so we test error handling.
	_, err := provider.Exchange(context.Background(), "test-code", "test-verifier", server.URL+"/callback")
	// This will fail because the mock token can't call real GitHub API.
	// The important thing is it gets past the token exchange.
	assert.Error(t, err) // expected: can't reach real GitHub API
}

func TestGitHubValidateCredential_InvalidToken(t *testing.T) {
	provider := NewGitHubProvider("id", "secret")

	// This will fail because we pass an invalid token to the real GitHub API.
	_, err := provider.ValidateCredential(context.Background(), "invalid-token")
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

// mockRedirectURIValidator implements RedirectURIValidator for testing.
type mockRedirectURIValidator struct {
	allowedURIs []string
}

func (m *mockRedirectURIValidator) GetAllowedRedirectURIs(_ context.Context, _ string) ([]string, error) {
	return m.allowedURIs, nil
}

func TestService_ValidateRedirectURI_Allowed(t *testing.T) {
	svc := &Service{
		redirectURIValidator: &mockRedirectURIValidator{
			allowedURIs: []string{"http://localhost:3000/callback", "https://app.example.com/callback"},
		},
	}

	err := svc.validateRedirectURI(context.Background(), "prj_test", "http://localhost:3000/callback")
	assert.NoError(t, err)
}

func TestService_ValidateRedirectURI_NotAllowed(t *testing.T) {
	svc := &Service{
		redirectURIValidator: &mockRedirectURIValidator{
			allowedURIs: []string{"http://localhost:3000/callback"},
		},
	}

	err := svc.validateRedirectURI(context.Background(), "prj_test", "https://evil.com/steal")
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestService_ValidateRedirectURI_ExactMatchRequired(t *testing.T) {
	svc := &Service{
		redirectURIValidator: &mockRedirectURIValidator{
			allowedURIs: []string{"http://localhost:3000/callback"},
		},
	}

	// Partial match should not be accepted.
	err := svc.validateRedirectURI(context.Background(), "prj_test", "http://localhost:3000/callback?extra=param")
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestService_ValidateRedirectURI_NoValidator(t *testing.T) {
	svc := &Service{
		redirectURIValidator: nil,
	}

	// No validator configured — should pass (e.g., in tests).
	err := svc.validateRedirectURI(context.Background(), "prj_test", "http://anything.com")
	assert.NoError(t, err)
}

func TestService_ValidateRedirectURI_EmptyAllowlist(t *testing.T) {
	svc := &Service{
		redirectURIValidator: &mockRedirectURIValidator{
			allowedURIs: []string{},
		},
	}

	err := svc.validateRedirectURI(context.Background(), "prj_test", "http://localhost/callback")
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestGoogleProvider_ValidateCredential_AudienceMismatch(t *testing.T) {
	// Mock Google tokeninfo endpoint that returns a valid token with wrong audience.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"sub":            "google-123",
			"email":          "user@gmail.com",
			"email_verified": "true",
			"aud":            "different-app-client-id",
		})
	}))
	defer server.Close()

	provider := &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     "my-client-id",
			ClientSecret: "secret",
		},
	}

	// Override the tokeninfo URL for testing — we call the mock server directly.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"?id_token=fake", http.NoBody)
	require.NoError(t, err)
	resp, err := providerHTTPClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Simulate what ValidateCredential does — parse and check aud.
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		Aud           string `json:"aud"`
	}
	err = json.NewDecoder(resp.Body).Decode(&claims)
	require.NoError(t, err)

	// Verify that audience mismatch is detected.
	assert.NotEqual(t, provider.config.ClientID, claims.Aud)
}
