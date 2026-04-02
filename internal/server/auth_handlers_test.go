package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newMinimalTestServer() *Server {
	return &Server{logger: slog.Default()}
}

func TestHandleSignup_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/signup", bytes.NewBufferString("not json"))
	s.handleSignup(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleVerifyEmail_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/verify-email", bytes.NewBufferString("not json"))
	s.handleVerifyEmail(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleVerifyEmail_MissingTokenAndCode(t *testing.T) {
	s := newMinimalTestServer()
	body := `{}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/verify-email", bytes.NewBufferString(body))
	s.handleVerifyEmail(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleResendVerification_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/resend-verification", bytes.NewBufferString("not json"))
	s.handleResendVerification(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleResendVerification_MissingEmail(t *testing.T) {
	s := newMinimalTestServer()
	body := `{}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/resend-verification", bytes.NewBufferString(body))
	s.handleResendVerification(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "email_required", resp.Error)
}
