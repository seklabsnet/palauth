package token

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func newTestJWTService(t *testing.T, alg string) *JWTService {
	t.Helper()
	svc, err := NewJWTService(JWTConfig{
		Algorithm: alg,
		Logger:    slog.Default(),
	})
	require.NoError(t, err)
	return svc
}

func TestNewJWTService_PS256(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)
	require.NotNil(t, svc)
	keys := svc.PublicKeys()
	require.Len(t, keys.Keys, 1)
	assert.Equal(t, "sig", keys.Keys[0].Use)
	assert.Equal(t, AlgPS256, keys.Keys[0].Algorithm)
}

func TestNewJWTService_ES256(t *testing.T) {
	svc := newTestJWTService(t, AlgES256)
	require.NotNil(t, svc)
	keys := svc.PublicKeys()
	require.Len(t, keys.Keys, 1)
	assert.Equal(t, AlgES256, keys.Keys[0].Algorithm)
}

func TestNewJWTService_UnsupportedAlg(t *testing.T) {
	_, err := NewJWTService(JWTConfig{
		Algorithm: "RS256",
		Logger:    slog.Default(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlg)
}

func TestNewJWTService_DefaultAlg(t *testing.T) {
	svc, err := NewJWTService(JWTConfig{Logger: slog.Default()})
	require.NoError(t, err)
	keys := svc.PublicKeys()
	assert.Equal(t, AlgPS256, keys.Keys[0].Algorithm)
}

func TestJWTService_IssueAndVerify(t *testing.T) {
	tests := []struct {
		name string
		alg  string
	}{
		{"PS256", AlgPS256},
		{"ES256", AlgES256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestJWTService(t, tt.alg)

			authTime := time.Now().Add(-5 * time.Minute)
			params := &IssueParams{
				UserID:    "usr_test-user-123",
				SessionID: "sess_test-session-456",
				ProjectID: "prj_test-project-789",
				Issuer:    "palauth-test",
				Audience:  []string{"test-audience"},
				ACR:       "aal1",
				AMR:       []string{"pwd"},
				AuthTime:  authTime,
				TTL:       30 * time.Minute,
			}

			tokenStr, err := svc.Issue(params)
			require.NoError(t, err)
			require.NotEmpty(t, tokenStr)

			claims, err := svc.Verify(tokenStr)
			require.NoError(t, err)
			require.NotNil(t, claims)

			assert.Equal(t, "usr_test-user-123", claims.Subject)
			assert.Equal(t, "palauth-test", claims.Issuer)
			assert.Equal(t, []string{"test-audience"}, claims.Audience)
			assert.Equal(t, "aal1", claims.ACR)
			assert.Equal(t, []string{"pwd"}, claims.AMR)
			assert.Equal(t, authTime.Unix(), claims.AuthTime)
			assert.Equal(t, "prj_test-project-789", claims.ProjectID)
			assert.Equal(t, "sess_test-session-456", claims.SessionID)
			assert.NotEmpty(t, claims.JWTID)
			assert.NotEmpty(t, claims.KID)
			assert.WithinDuration(t, time.Now().Add(30*time.Minute), claims.ExpiresAt, 5*time.Second)
		})
	}
}

func TestJWTService_VerifyExpired(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	params := &IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now().Add(-1 * time.Hour),
		TTL:       1 * time.Millisecond, // Expires almost immediately.
	}

	tokenStr, err := svc.Issue(params)
	require.NoError(t, err)

	// Wait for token to expire.
	time.Sleep(10 * time.Millisecond)

	_, err = svc.Verify(tokenStr)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestJWTService_VerifyInvalidSignature(t *testing.T) {
	svc1 := newTestJWTService(t, AlgPS256)
	svc2 := newTestJWTService(t, AlgPS256) // Different key pair.

	params := &IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
	}

	tokenStr, err := svc1.Issue(params)
	require.NoError(t, err)

	// Verify with a different service (different key).
	_, err = svc2.Verify(tokenStr)
	require.Error(t, err)
}

func TestJWTService_VerifyInvalidToken(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	_, err := svc.Verify("not.a.valid.jwt.token")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestJWTService_KIDHeader(t *testing.T) {
	svc := newTestJWTService(t, AlgES256)

	tokenStr, err := svc.Issue(&IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	claims, err := svc.Verify(tokenStr)
	require.NoError(t, err)
	assert.NotEmpty(t, claims.KID)

	// Verify kid matches one of the public keys.
	keys := svc.PublicKeys()
	found := false
	for _, k := range keys.Keys {
		if k.KeyID == claims.KID {
			found = true
			break
		}
	}
	assert.True(t, found, "kid in token should match a public key")
}

func TestJWTService_AuthTimeMandatory(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	// Issue with AuthTime set — should work.
	tokenStr, err := svc.Issue(&IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	claims, err := svc.Verify(tokenStr)
	require.NoError(t, err)
	assert.NotZero(t, claims.AuthTime)
}

func TestJWTService_CustomClaims(t *testing.T) {
	svc := newTestJWTService(t, AlgES256)

	custom := map[string]any{
		"role":       "admin",
		"tenant_id":  "t-123",
		"permissions": []any{"read", "write"},
	}

	tokenStr, err := svc.Issue(&IssueParams{
		UserID:       "usr_test",
		ProjectID:    "prj_test",
		Issuer:       "test",
		AuthTime:     time.Now(),
		CustomClaims: custom,
	})
	require.NoError(t, err)

	claims, err := svc.Verify(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.CustomClaims["role"])
	assert.Equal(t, "t-123", claims.CustomClaims["tenant_id"])
}

func TestJWTService_MultipleKeys(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	// Issue token with first key.
	token1, err := svc.Issue(&IssueParams{
		UserID:    "usr_1",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	// Generate a second key.
	err = svc.GenerateKey(AlgES256)
	require.NoError(t, err)

	keys := svc.PublicKeys()
	assert.Len(t, keys.Keys, 2)

	// Token from first key should still verify.
	claims, err := svc.Verify(token1)
	require.NoError(t, err)
	assert.Equal(t, "usr_1", claims.Subject)

	// New token should use the second key.
	token2, err := svc.Issue(&IssueParams{
		UserID:    "usr_2",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	claims2, err := svc.Verify(token2)
	require.NoError(t, err)
	assert.Equal(t, "usr_2", claims2.Subject)
	// Keys should be different.
	assert.NotEqual(t, claims.KID, claims2.KID)
}

func TestJWTService_FAPIMode(t *testing.T) {
	svc, err := NewJWTService(JWTConfig{
		Algorithm: AlgES256,
		FAPI:      true,
		Logger:    slog.Default(),
	})
	require.NoError(t, err)

	tokenStr, err := svc.Issue(&IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	claims, err := svc.Verify(tokenStr)
	require.NoError(t, err)

	// FAPI mode: 5 min TTL.
	expectedExpiry := time.Now().Add(5 * time.Minute)
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt, 5*time.Second)
}

func TestJWTService_DefaultTTL(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	tokenStr, err := svc.Issue(&IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	claims, err := svc.Verify(tokenStr)
	require.NoError(t, err)

	// Default: 30 min.
	expectedExpiry := time.Now().Add(30 * time.Minute)
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt, 5*time.Second)
}

func TestJWTService_JWKS(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	jwks := svc.PublicKeys()
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
	assert.NotEmpty(t, jwks.Keys[0].KeyID)
	assert.True(t, jwks.Keys[0].IsPublic())
}

// Property-based tests.
func TestJWTService_IssueVerify_Property(t *testing.T) {
	// Create services outside rapid loop since key generation is expensive.
	svcPS256 := newTestJWTService(t, AlgPS256)
	svcES256 := newTestJWTService(t, AlgES256)
	svcs := map[string]*JWTService{AlgPS256: svcPS256, AlgES256: svcES256}

	rapid.Check(t, func(t *rapid.T) {
		alg := rapid.SampledFrom([]string{AlgPS256, AlgES256}).Draw(t, "alg")
		svc := svcs[alg]

		userID := "usr_" + rapid.StringMatching(`[a-z0-9]{8,32}`).Draw(t, "userID")
		projectID := "prj_" + rapid.StringMatching(`[a-z0-9]{8,32}`).Draw(t, "projectID")
		sessionID := "sess_" + rapid.StringMatching(`[a-z0-9]{8,32}`).Draw(t, "sessionID")
		issuer := rapid.StringMatching(`[a-z0-9.]{3,50}`).Draw(t, "issuer")

		params := &IssueParams{
			UserID:    userID,
			SessionID: sessionID,
			ProjectID: projectID,
			Issuer:    issuer,
			AuthTime:  time.Now(),
			TTL:       30 * time.Minute,
		}

		tokenStr, err := svc.Issue(params)
		if err != nil {
			t.Fatal(err)
		}

		claims, err := svc.Verify(tokenStr)
		if err != nil {
			t.Fatal(err)
		}

		if claims.Subject != userID {
			t.Fatalf("subject mismatch: got %q want %q", claims.Subject, userID)
		}
		if claims.ProjectID != projectID {
			t.Fatalf("project_id mismatch: got %q want %q", claims.ProjectID, projectID)
		}
		if claims.SessionID != sessionID {
			t.Fatalf("session_id mismatch: got %q want %q", claims.SessionID, sessionID)
		}
		if claims.Issuer != issuer {
			t.Fatalf("issuer mismatch: got %q want %q", claims.Issuer, issuer)
		}
		if claims.AuthTime == 0 {
			t.Fatal("auth_time must not be zero")
		}
		if claims.KID == "" {
			t.Fatal("kid must not be empty")
		}
	})
}

func TestJWTService_ExpGreaterThanIat_Property(t *testing.T) {
	svcPS256 := newTestJWTService(t, AlgPS256)
	svcES256 := newTestJWTService(t, AlgES256)
	svcs := map[string]*JWTService{AlgPS256: svcPS256, AlgES256: svcES256}

	rapid.Check(t, func(t *rapid.T) {
		alg := rapid.SampledFrom([]string{AlgPS256, AlgES256}).Draw(t, "alg")
		svc := svcs[alg]

		ttlMinutes := rapid.IntRange(1, 120).Draw(t, "ttl_minutes")
		ttl := time.Duration(ttlMinutes) * time.Minute

		tokenStr, err := svc.Issue(&IssueParams{
			UserID:    "usr_test",
			ProjectID: "prj_test",
			AuthTime:  time.Now(),
			TTL:       ttl,
		})
		if err != nil {
			t.Fatal(err)
		}

		claims, err := svc.Verify(tokenStr)
		if err != nil {
			t.Fatal(err)
		}

		if !claims.ExpiresAt.After(claims.IssuedAt) {
			t.Fatalf("exp (%v) must be after iat (%v)", claims.ExpiresAt, claims.IssuedAt)
		}
		if claims.AuthTime == 0 {
			t.Fatal("auth_time must not be zero")
		}
	})
}

func TestJWTService_TableDriven_VerifyErrors(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	tests := []struct {
		name      string
		token     string
		wantErr   error
	}{
		{
			name:    "empty token",
			token:   "",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "random string",
			token:   "this-is-not-a-jwt",
			wantErr: ErrInvalidToken,
		},
		{
			name:    "malformed JWT",
			token:   "eyJhbGciOiJQUzI1NiJ9.e30.invalid",
			wantErr: nil, // will match either ErrInvalidToken or ErrMissingKID
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Verify(tt.token)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}
