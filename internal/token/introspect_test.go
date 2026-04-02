package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectAccessToken_Valid(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	tokenStr, err := svc.Issue(&IssueParams{
		UserID:    "usr_test-user",
		ProjectID: "prj_test-project",
		Issuer:    "test",
		AuthTime:  time.Now(),
		TTL:       30 * time.Minute,
	})
	require.NoError(t, err)

	resp := svc.IntrospectAccessToken(tokenStr)
	assert.True(t, resp.Active)
	assert.Equal(t, "usr_test-user", resp.Subject)
	assert.Equal(t, "prj_test-project", resp.ProjectID)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.NotZero(t, resp.ExpiresAt)
	assert.NotZero(t, resp.IssuedAt)
	assert.NotEmpty(t, resp.JWTID)
}

func TestIntrospectAccessToken_Invalid(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	resp := svc.IntrospectAccessToken("invalid.token.here")
	assert.False(t, resp.Active)
	assert.Empty(t, resp.Subject)
}

func TestIntrospectAccessToken_Expired(t *testing.T) {
	svc := newTestJWTService(t, AlgES256)

	tokenStr, err := svc.Issue(&IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
		TTL:       1 * time.Millisecond,
	})
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	resp := svc.IntrospectAccessToken(tokenStr)
	assert.False(t, resp.Active)
}

func TestIntrospectAccessToken_WrongKey(t *testing.T) {
	svc1 := newTestJWTService(t, AlgPS256)
	svc2 := newTestJWTService(t, AlgPS256)

	tokenStr, err := svc1.Issue(&IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	resp := svc2.IntrospectAccessToken(tokenStr)
	assert.False(t, resp.Active)
}

func TestIntrospectAccessToken_TableDriven(t *testing.T) {
	svc := newTestJWTService(t, AlgPS256)

	validToken, err := svc.Issue(&IssueParams{
		UserID:    "usr_valid",
		ProjectID: "prj_test",
		Issuer:    "test",
		AuthTime:  time.Now(),
		TTL:       1 * time.Hour,
	})
	require.NoError(t, err)

	tests := []struct {
		name       string
		token      string
		wantActive bool
	}{
		{"valid token", validToken, true},
		{"empty string", "", false},
		{"random string", "not-a-jwt", false},
		{"malformed jwt", "eyJ.eyJ.xxx", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := svc.IntrospectAccessToken(tt.token)
			assert.Equal(t, tt.wantActive, resp.Active)
		})
	}
}
