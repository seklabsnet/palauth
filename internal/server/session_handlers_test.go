package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/palauth/palauth/internal/token"
)

func TestSessionMiddleware_MissingAuthHeader(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/sessions", http.NoBody)

	handler := s.sessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "missing_token", resp.Error)
}

func TestSessionMiddleware_InvalidBearerScheme(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/sessions", http.NoBody)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	handler := s.sessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "missing_token", resp.Error)
}

func TestSessionMiddleware_InvalidJWT(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/sessions", http.NoBody)
	r.Header.Set("Authorization", "Bearer invalid-jwt-token")

	handler := s.sessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestSessionMiddleware_MissingSessionID(t *testing.T) {
	s := newTestServer(t)

	// Issue a JWT without session_id.
	tok, err := s.jwtSvc.Issue(&token.IssueParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/sessions", http.NoBody)
	r.Header.Set("Authorization", "Bearer "+tok)

	handler := s.sessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp ErrorResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestSessionMiddleware_ValidJWT_SetsContext(t *testing.T) {
	// This test verifies the middleware correctly extracts and validates JWT claims
	// and would set context values. Since ValidateAndTouch requires a real DB,
	// the full flow is tested in integration tests (internal/session/integration_test.go).
	// Here we only verify JWT parsing works up to the session validation call.
	s := newTestServer(t)

	tok, err := s.jwtSvc.Issue(&token.IssueParams{
		UserID:    "usr_test",
		SessionID: "sess_test-123",
		ProjectID: "prj_test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/sessions", http.NoBody)
	r.Header.Set("Authorization", "Bearer "+tok)

	// Wrap with recovery to catch nil DB panic gracefully.
	handler := Recovery(s.logger)(s.sessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	handler.ServeHTTP(w, r)

	// Without DB, the middleware hits an error at session lookup.
	// Recovery catches the panic and returns 500.
	// Important: the middleware did NOT return 401 for invalid token — it got past JWT validation.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSessionUserIDFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", SessionUserIDFromContext(ctx))
}

func TestSessionIDFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", SessionIDFromContext(ctx))
}

func TestSessionUserIDFromContext_WithValue(t *testing.T) {
	ctx := context.WithValue(context.Background(), sessionUserIDCtxKey, "usr_123")
	assert.Equal(t, "usr_123", SessionUserIDFromContext(ctx))
}

func TestSessionIDFromContext_WithValue(t *testing.T) {
	ctx := context.WithValue(context.Background(), sessionIDCtxKey, "sess_456")
	assert.Equal(t, "sess_456", SessionIDFromContext(ctx))
}

func TestHandleRevokeSession_MissingSessionID(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/auth/sessions/", http.NoBody)
	s.handleRevokeSession(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}
