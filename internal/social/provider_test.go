package social

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidProviders(t *testing.T) {
	assert.True(t, ValidProviders["google"])
	assert.True(t, ValidProviders["apple"])
	assert.True(t, ValidProviders["github"])
	assert.True(t, ValidProviders["microsoft"])
	assert.False(t, ValidProviders["facebook"])
	assert.False(t, ValidProviders[""])
}

func TestGoogleProvider_Name(t *testing.T) {
	p := NewGoogleProvider("id", "secret")
	assert.Equal(t, "google", p.Name())
}

func TestGoogleProvider_AuthURL(t *testing.T) {
	p := NewGoogleProvider("client-id", "client-secret")
	url := p.AuthURL("test-state", "test-challenge", "http://localhost/callback")

	assert.Contains(t, url, "accounts.google.com")
	assert.Contains(t, url, "client_id=client-id")
	assert.Contains(t, url, "state=test-state")
	assert.Contains(t, url, "code_challenge=test-challenge")
	assert.Contains(t, url, "code_challenge_method=S256")
	assert.Contains(t, url, "redirect_uri=")
}

func TestGitHubProvider_Name(t *testing.T) {
	p := NewGitHubProvider("id", "secret")
	assert.Equal(t, "github", p.Name())
}

func TestGitHubProvider_AuthURL(t *testing.T) {
	p := NewGitHubProvider("client-id", "client-secret")
	url := p.AuthURL("test-state", "test-challenge", "http://localhost/callback")

	assert.Contains(t, url, "github.com")
	assert.Contains(t, url, "client_id=client-id")
	assert.Contains(t, url, "state=test-state")
}

func TestAppleProvider_Name(t *testing.T) {
	p := NewAppleProvider("id", "team", "key", "privkey")
	assert.Equal(t, "apple", p.Name())
}

func TestAppleProvider_AuthURL(t *testing.T) {
	p := NewAppleProvider("client-id", "team-id", "key-id", "private-key")
	url := p.AuthURL("test-state", "test-challenge", "http://localhost/callback")

	assert.Contains(t, url, "appleid.apple.com")
	assert.Contains(t, url, "client_id=client-id")
	assert.Contains(t, url, "state=test-state")
	assert.Contains(t, url, "response_mode=form_post")
}

func TestMicrosoftProvider_Name(t *testing.T) {
	p := NewMicrosoftProvider("id", "secret", "common")
	assert.Equal(t, "microsoft", p.Name())
}

func TestMicrosoftProvider_AuthURL(t *testing.T) {
	p := NewMicrosoftProvider("client-id", "client-secret", "")
	url := p.AuthURL("test-state", "test-challenge", "http://localhost/callback")

	assert.Contains(t, url, "login.microsoftonline.com")
	assert.Contains(t, url, "common")
	assert.Contains(t, url, "client_id=client-id")
	assert.Contains(t, url, "state=test-state")
}

func TestMicrosoftProvider_DefaultTenant(t *testing.T) {
	p := NewMicrosoftProvider("id", "secret", "")
	assert.Equal(t, "common", p.tenant)
}

func TestParseGoogleIDToken(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		claims := map[string]any{
			"sub":            "google-user-123",
			"email":          "user@gmail.com",
			"email_verified": true,
			"name":           "Test User",
			"picture":        "https://example.com/photo.jpg",
		}
		token := makeTestJWT(claims)
		pu, err := parseGoogleIDToken(token)
		require.NoError(t, err)
		assert.Equal(t, "google-user-123", pu.ProviderID)
		assert.Equal(t, "user@gmail.com", pu.Email)
		assert.Equal(t, "Test User", pu.Name)
		assert.Equal(t, "https://example.com/photo.jpg", pu.AvatarURL)
		assert.True(t, pu.Verified)
	})

	t.Run("missing sub", func(t *testing.T) {
		claims := map[string]any{"email": "user@gmail.com"}
		token := makeTestJWT(claims)
		_, err := parseGoogleIDToken(token)
		assert.Error(t, err)
	})
}

func TestParseAppleIDToken(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		claims := map[string]any{
			"sub":            "apple-user-123",
			"email":          "user@icloud.com",
			"email_verified": true,
		}
		token := makeTestJWT(claims)
		pu, err := parseAppleIDToken(token)
		require.NoError(t, err)
		assert.Equal(t, "apple-user-123", pu.ProviderID)
		assert.Equal(t, "user@icloud.com", pu.Email)
		assert.True(t, pu.Verified)
	})

	t.Run("email_verified as string", func(t *testing.T) {
		claims := map[string]any{
			"sub":            "apple-user-456",
			"email":          "user@icloud.com",
			"email_verified": "true",
		}
		token := makeTestJWT(claims)
		pu, err := parseAppleIDToken(token)
		require.NoError(t, err)
		assert.True(t, pu.Verified)
	})

	t.Run("missing sub", func(t *testing.T) {
		claims := map[string]any{"email": "user@icloud.com"}
		token := makeTestJWT(claims)
		_, err := parseAppleIDToken(token)
		assert.Error(t, err)
	})
}

func TestParseMicrosoftIDToken(t *testing.T) {
	t.Run("valid token with sub", func(t *testing.T) {
		claims := map[string]any{
			"sub":   "ms-user-123",
			"email": "user@outlook.com",
			"name":  "Test User",
		}
		token := makeTestJWT(claims)
		pu, err := parseMicrosoftIDToken(token)
		require.NoError(t, err)
		assert.Equal(t, "ms-user-123", pu.ProviderID)
		assert.Equal(t, "user@outlook.com", pu.Email)
		assert.Equal(t, "Test User", pu.Name)
		assert.True(t, pu.Verified)
	})

	t.Run("fallback to oid", func(t *testing.T) {
		claims := map[string]any{
			"oid":   "ms-oid-123",
			"email": "user@outlook.com",
		}
		token := makeTestJWT(claims)
		pu, err := parseMicrosoftIDToken(token)
		require.NoError(t, err)
		assert.Equal(t, "ms-oid-123", pu.ProviderID)
	})

	t.Run("fallback to preferred_username", func(t *testing.T) {
		claims := map[string]any{
			"sub":                "ms-user-123",
			"preferred_username": "user@outlook.com",
		}
		token := makeTestJWT(claims)
		pu, err := parseMicrosoftIDToken(token)
		require.NoError(t, err)
		assert.Equal(t, "user@outlook.com", pu.Email)
	})

	t.Run("missing sub and oid", func(t *testing.T) {
		claims := map[string]any{"email": "user@outlook.com"}
		token := makeTestJWT(claims)
		_, err := parseMicrosoftIDToken(token)
		assert.Error(t, err)
	})
}

// makeTestJWT creates a test JWT with the given claims (not cryptographically signed).
func makeTestJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return header + "." + payload + "." + sig
}
