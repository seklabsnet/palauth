package admin

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestService() *Service {
	return &Service{
		signingKey: []byte("test-signing-key-at-least-32-bytes!"),
		logger:     slog.Default(),
	}
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	svc := newTestService()

	claims := AdminClaims{
		Sub:  "adm_test-123",
		Role: "owner",
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(time.Hour).Unix(),
	}
	token, err := svc.signToken(claims)
	require.NoError(t, err)

	handler := svc.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := AdminClaimsFromContext(r.Context())
		require.NotNil(t, c)
		assert.Equal(t, "adm_test-123", c.Sub)
		assert.Equal(t, "owner", c.Role)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/projects", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	svc := newTestService()

	handler := svc.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/projects", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "missing_token")
}

func TestAuthMiddleware_InvalidScheme(t *testing.T) {
	svc := newTestService()

	handler := svc.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/projects", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_token")
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	svc := newTestService()

	claims := AdminClaims{
		Sub:  "adm_test-123",
		Role: "owner",
		Iat:  time.Now().Add(-2 * time.Hour).Unix(),
		Exp:  time.Now().Add(-1 * time.Hour).Unix(),
	}
	token, err := svc.signToken(claims)
	require.NoError(t, err)

	handler := svc.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/projects", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAdminClaimsFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, AdminClaimsFromContext(ctx))
}
