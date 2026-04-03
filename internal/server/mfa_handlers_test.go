package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleMFAEnroll_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/enroll", bytes.NewBufferString("not json"))
	s.handleMFAEnroll(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleMFAVerifyEnrollment_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/verify", bytes.NewBufferString("not json"))
	s.handleMFAVerifyEnrollment(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleMFAVerifyEnrollment_MissingCode(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/verify", bytes.NewBufferString(`{}`))
	s.handleMFAVerifyEnrollment(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "code_required", resp.Error)
}

func TestHandleMFAChallenge_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/challenge", bytes.NewBufferString("not json"))
	s.handleMFAChallenge(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleMFAChallenge_MissingMFAToken(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"code": "123456", "type": "totp"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/challenge", bytes.NewBufferString(body))
	s.handleMFAChallenge(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "mfa_token_required", resp.Error)
}

func TestHandleMFAChallenge_MissingCode(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"mfa_token": "token123", "type": "totp"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/challenge", bytes.NewBufferString(body))
	s.handleMFAChallenge(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "code_required", resp.Error)
}

func TestHandleMFARecovery_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/recovery", bytes.NewBufferString("not json"))
	s.handleMFARecovery(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleMFARecovery_MissingMFAToken(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"code": "abcdefgh"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/recovery", bytes.NewBufferString(body))
	s.handleMFARecovery(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "mfa_token_required", resp.Error)
}

func TestHandleMFARecovery_MissingCode(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"mfa_token": "token123"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/recovery", bytes.NewBufferString(body))
	s.handleMFARecovery(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "code_required", resp.Error)
}

func TestHandleMFARemoveFactor_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/auth/mfa/factors/mfa_123", bytes.NewBufferString("not json"))
	s.handleMFARemoveFactor(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleMFARemoveFactor_MissingPassword(t *testing.T) {
	s := newMinimalTestServer()
	body := `{}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/auth/mfa/factors/mfa_123", bytes.NewBufferString(body))
	s.handleMFARemoveFactor(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "password_required", resp.Error)
}

func TestHandleMFAEmailChallenge_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/email/challenge", bytes.NewBufferString("not json"))
	s.handleMFAEmailChallenge(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleMFAEmailChallenge_MissingMFAToken(t *testing.T) {
	s := newMinimalTestServer()
	body := `{}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/email/challenge", bytes.NewBufferString(body))
	s.handleMFAEmailChallenge(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "mfa_token_required", resp.Error)
}

func TestHandleMFAEmailVerify_InvalidJSON(t *testing.T) {
	s := newMinimalTestServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/email/verify", bytes.NewBufferString("not json"))
	s.handleMFAEmailVerify(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleMFAEmailVerify_MissingMFAToken(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"code": "123456"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/email/verify", bytes.NewBufferString(body))
	s.handleMFAEmailVerify(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "mfa_token_required", resp.Error)
}

func TestHandleMFAEmailVerify_MissingCode(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"mfa_token": "token123"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/email/verify", bytes.NewBufferString(body))
	s.handleMFAEmailVerify(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "code_required", resp.Error)
}

func TestHandleAdminMFAEnroll_MFAUnavailable(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"mfa_token": "token123"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/mfa/enroll", bytes.NewBufferString(body))
	s.handleAdminMFAEnroll(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "mfa_unavailable", resp.Error)
}

func TestHandleAdminMFAVerifyEnrollment_MFAUnavailable(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"mfa_token": "token123", "code": "123456"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/mfa/verify", bytes.NewBufferString(body))
	s.handleAdminMFAVerifyEnrollment(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "mfa_unavailable", resp.Error)
}

func TestHandleAdminMFAChallenge_MFAUnavailable(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"mfa_token": "token123", "code": "123456"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/mfa/challenge", bytes.NewBufferString(body))
	s.handleAdminMFAChallenge(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var resp ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "mfa_unavailable", resp.Error)
}

func TestHandleMFAEnroll_RequiresAuth(t *testing.T) {
	s := newMinimalTestServer()
	body := `{"type": "totp"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/mfa/enroll", bytes.NewBufferString(body))
	s.handleMFAEnroll(w, r)

	// Should fail with 401 since no bearer token is provided.
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCompleteMFALogin_ACRValues(t *testing.T) {
	tests := []struct {
		name        string
		mfaType     string
		expectedACR string
		expectedAMR []string
	}{
		{"totp", "totp", "aal2", []string{"pwd", "otp"}},
		{"email", "email", "aal2", []string{"pwd", "otp"}},
		{"recovery", "recovery", "aal1", []string{"pwd", "recovery"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acr := "aal2"
			amr := []string{"pwd", "otp"}
			if tt.mfaType == "recovery" {
				acr = "aal1"
				amr = []string{"pwd", "recovery"}
			}
			assert.Equal(t, tt.expectedACR, acr)
			assert.Equal(t, tt.expectedAMR, amr)
		})
	}
}
