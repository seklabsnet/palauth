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

func TestHandleAdminSetup_InvalidJSON(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequestWithContext(context.Background(),http.MethodPost, "/admin/setup", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestHandleAdminLogin_InvalidJSON(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequestWithContext(context.Background(),http.MethodPost, "/admin/login", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", resp.Error)
}

func TestAdminEndpoints_CacheControl(t *testing.T) {
	s := newTestServer(t)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/admin/setup"},
		{http.MethodPost, "/admin/login"},
		{http.MethodGet, "/admin/projects"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(),route.method, route.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			s.router.ServeHTTP(rec, req)
			assert.Equal(t, "no-store, no-cache, must-revalidate", rec.Header().Get("Cache-Control"),
				"Cache-Control header must be set on auth endpoint %s %s", route.method, route.path)
		})
	}
}

func TestAdminProtectedRoutes_NoAuth(t *testing.T) {
	s := newTestServer(t)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/projects"},
		{http.MethodPost, "/admin/projects"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(),route.method, route.path, http.NoBody)
			rec := httptest.NewRecorder()

			s.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
}
