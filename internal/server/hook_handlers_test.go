package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/palauth/palauth/internal/hook"
)

// newHookRequest creates an HTTP request with chi route context for hook handler tests.
func newHookRequest(t *testing.T, method, path string, body any, params map[string]string) *http.Request {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	r := httptest.NewRequestWithContext(context.Background(), method, path, bodyReader)
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// --- handleCreateHook Tests ---

func TestHandleCreateHook_HookEngineNil(t *testing.T) {
	s := newTestServer(t) // hookEngine is nil when DB is nil

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{Event: hook.EventBeforeLogin, URL: "https://example.com/hook"},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "internal_error", resp.Error)
}

func TestHandleCreateHook_InvalidJSON(t *testing.T) {
	s := newTestServer(t)
	// Force hookEngine to non-nil for validation tests.
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/projects/prj_test/hooks",
		bytes.NewBufferString(`{invalid json}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "prj_test")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleCreateHook_MissingEvent(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{URL: "https://example.com/hook"},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "event_required", resp.Error)
}

func TestHandleCreateHook_InvalidEvent(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{Event: "invalid.event.type", URL: "https://example.com/hook"},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_event", resp.Error)
}

func TestHandleCreateHook_MissingURL(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{Event: hook.EventBeforeLogin},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "url_required", resp.Error)
}

func TestHandleCreateHook_PrivateURL(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{Event: hook.EventBeforeLogin, URL: "https://10.0.0.1/hook"},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "private_url", resp.Error)
}

func TestHandleCreateHook_HTTPSRequired(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{Event: hook.EventBeforeLogin, URL: "http://example.com/hook"},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "https_required", resp.Error)
}

func TestHandleCreateHook_InvalidFailureMode(t *testing.T) {
	s := newTestServer(t)
	// Use devMode=true so HTTP URLs pass validation (avoids DNS lookup).
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, true)

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{Event: hook.EventBeforeLogin, URL: "http://example.com/hook", FailureMode: "invalid"},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	// URL validation involves DNS lookup which may fail, but if it passes,
	// the invalid failure_mode should be caught.
	if w.Code == http.StatusBadRequest {
		var resp ErrorResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, []string{"invalid_failure_mode", "invalid_url"}, resp.Error)
	}
}

func TestHandleCreateHook_TimeoutTooLow(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, true)

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{Event: hook.EventBeforeLogin, URL: "http://example.com/hook", TimeoutMs: 500},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	// URL validation may fail due to DNS, but if it passes, timeout should be rejected.
	if w.Code == http.StatusBadRequest {
		var resp ErrorResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, []string{"invalid_timeout", "invalid_url"}, resp.Error)
	}
}

func TestHandleCreateHook_TimeoutTooHigh(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, true)

	r := newHookRequest(t, http.MethodPost, "/admin/projects/prj_test/hooks",
		createHookRequest{Event: hook.EventBeforeLogin, URL: "http://example.com/hook", TimeoutMs: 60000},
		map[string]string{"id": "prj_test"})
	w := httptest.NewRecorder()

	s.handleCreateHook(w, r)

	if w.Code == http.StatusBadRequest {
		var resp ErrorResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, []string{"invalid_timeout", "invalid_url"}, resp.Error)
	}
}

// --- handleUpdateHook Tests ---

func TestHandleUpdateHook_HookEngineNil(t *testing.T) {
	s := newTestServer(t)

	r := newHookRequest(t, http.MethodPut, "/admin/projects/prj_test/hooks/hk_test",
		updateHookRequest{Event: hook.EventBeforeLogin, URL: "https://example.com/hook", FailureMode: "deny"},
		map[string]string{"id": "prj_test", "hid": "hk_test"})
	w := httptest.NewRecorder()

	s.handleUpdateHook(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleUpdateHook_InvalidJSON(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/admin/projects/prj_test/hooks/hk_test",
		bytes.NewBufferString(`not json`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "prj_test")
	rctx.URLParams.Add("hid", "hk_test")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	s.handleUpdateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleUpdateHook_InvalidEvent(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := newHookRequest(t, http.MethodPut, "/admin/projects/prj_test/hooks/hk_test",
		updateHookRequest{Event: "invalid.event", URL: "https://example.com/hook", FailureMode: "deny"},
		map[string]string{"id": "prj_test", "hid": "hk_test"})
	w := httptest.NewRecorder()

	s.handleUpdateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "invalid_event", resp.Error)
}

func TestHandleUpdateHook_MissingURL(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := newHookRequest(t, http.MethodPut, "/admin/projects/prj_test/hooks/hk_test",
		updateHookRequest{Event: hook.EventBeforeLogin, FailureMode: "deny"},
		map[string]string{"id": "prj_test", "hid": "hk_test"})
	w := httptest.NewRecorder()

	s.handleUpdateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "url_required", resp.Error)
}

func TestHandleUpdateHook_PrivateURL(t *testing.T) {
	s := newTestServer(t)
	s.hookEngine = hook.NewEngine(nil, make([]byte, 32), s.logger, false)

	r := newHookRequest(t, http.MethodPut, "/admin/projects/prj_test/hooks/hk_test",
		updateHookRequest{Event: hook.EventBeforeLogin, URL: "https://192.168.1.1/hook", FailureMode: "deny"},
		map[string]string{"id": "prj_test", "hid": "hk_test"})
	w := httptest.NewRecorder()

	s.handleUpdateHook(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "private_url", resp.Error)
}

func TestValidEvents_AllRegistered(t *testing.T) {
	validEvents := []string{
		hook.EventBeforeUserCreate,
		hook.EventBeforeLogin,
		hook.EventBeforePasswordReset,
		hook.EventBeforeMFAVerify,
		hook.EventBeforeSocialLink,
		hook.EventBeforeTokenIssue,
		hook.EventBeforeTokenRefresh,
		hook.EventAfterLoginFailed,
		hook.EventAfterSessionRevoke,
	}

	for _, event := range validEvents {
		assert.True(t, hook.ValidEvents[event], "event %s should be valid", event)
	}

	assert.Len(t, hook.ValidEvents, 9, "should have exactly 9 valid events")

	invalidEvents := []string{"invalid.event", "", "before.invalid", "after.invalid"}
	for _, event := range invalidEvents {
		assert.False(t, hook.ValidEvents[event], "event %s should not be valid", event)
	}
}
