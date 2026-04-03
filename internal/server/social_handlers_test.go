package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/palauth/palauth/internal/social"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSocialTestServer(withSocial bool) *Server {
	s := &Server{logger: slog.Default()}
	if withSocial {
		s.socialSvc = social.NewService(nil, nil, nil, nil, nil, "test-pepper", make([]byte, 32), slog.Default())
	}
	return s
}

func TestHandleOAuthAuthorize_NoSocialService(t *testing.T) {
	s := newSocialTestServer(false)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oauth/google/authorize?redirect_uri=http://localhost", http.NoBody)
	w := httptest.NewRecorder()

	s.handleOAuthAuthorize(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleOAuthCallback_NoSocialService(t *testing.T) {
	s := newSocialTestServer(false)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oauth/google/callback?code=abc&state=xyz", http.NoBody)
	w := httptest.NewRecorder()

	s.handleOAuthCallback(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleCredentialExchange_NoSocialService(t *testing.T) {
	s := newSocialTestServer(false)

	body := `{"provider":"google","credential":"fake-token"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/oauth/credential", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleCredentialExchange(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleCredentialExchange_InvalidJSON(t *testing.T) {
	s := newSocialTestServer(false)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/oauth/credential", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleCredentialExchange(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleCredentialExchange_MissingFields(t *testing.T) {
	s := newSocialTestServer(true)

	tests := []struct {
		name string
		body string
	}{
		{"missing provider", `{"credential":"token"}`},
		{"missing credential", `{"provider":"google"}`},
		{"both empty", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/oauth/credential", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			s.handleCredentialExchange(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)

			var resp map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "invalid_request", resp["error"])
		})
	}
}

func TestHandleCredentialExchange_UnsupportedProvider(t *testing.T) {
	s := newSocialTestServer(true)

	body := `{"provider":"facebook","credential":"token"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/oauth/credential", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleCredentialExchange(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "unsupported_provider", resp["error"])
}

func TestHandleListIdentities_NoSocialService(t *testing.T) {
	s := newSocialTestServer(false)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/identities", http.NoBody)
	w := httptest.NewRecorder()

	s.handleListIdentities(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleLinkIdentity_NoSocialService(t *testing.T) {
	s := newSocialTestServer(false)

	body := `{"provider":"google","credential":"token"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/identities/link", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleLinkIdentity(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleUnlinkIdentity_NoSocialService(t *testing.T) {
	s := newSocialTestServer(false)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/auth/identities/ident_123", http.NoBody)
	w := httptest.NewRecorder()

	s.handleUnlinkIdentity(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleUnlinkIdentity_MissingID(t *testing.T) {
	s := newSocialTestServer(true)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/auth/identities/", http.NoBody)
	w := httptest.NewRecorder()

	s.handleUnlinkIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLinkIdentity_MissingFields(t *testing.T) {
	s := newSocialTestServer(true)

	body := `{"provider":"","credential":""}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/identities/link", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleLinkIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLinkIdentity_UnsupportedProvider(t *testing.T) {
	s := newSocialTestServer(true)

	body := `{"provider":"facebook","credential":"token"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/identities/link", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleLinkIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
