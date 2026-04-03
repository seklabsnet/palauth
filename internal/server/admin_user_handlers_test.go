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

func TestAdminUserRoutes_NoAuth(t *testing.T) {
	s := newTestServer(t)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/admin/projects/prj_1/users"},
		{http.MethodGet, "/admin/projects/prj_1/users"},
		{http.MethodGet, "/admin/projects/prj_1/users/usr_1"},
		{http.MethodPut, "/admin/projects/prj_1/users/usr_1"},
		{http.MethodDelete, "/admin/projects/prj_1/users/usr_1"},
		{http.MethodPost, "/admin/projects/prj_1/users/usr_1/ban"},
		{http.MethodPost, "/admin/projects/prj_1/users/usr_1/unban"},
		{http.MethodPost, "/admin/projects/prj_1/users/usr_1/reset-password"},
		{http.MethodGet, "/admin/projects/prj_1/analytics"},
		{http.MethodPost, "/admin/users/invite"},
		{http.MethodPost, "/admin/deactivate-inactive"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), route.method, route.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			s.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code,
				"expected 401 for unauthenticated request to %s %s", route.method, route.path)

			var resp ErrorResponse
			err := json.NewDecoder(rec.Body).Decode(&resp)
			assert.NoError(t, err)
			assert.Equal(t, "missing_token", resp.Error)
		})
	}
}

func TestAdminUserRoutes_CacheControl(t *testing.T) {
	s := newTestServer(t)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/admin/projects/prj_1/users"},
		{http.MethodGet, "/admin/projects/prj_1/users"},
		{http.MethodGet, "/admin/projects/prj_1/analytics"},
		{http.MethodPost, "/admin/users/invite"},
		{http.MethodPost, "/admin/deactivate-inactive"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), route.method, route.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			s.router.ServeHTTP(rec, req)
			assert.Equal(t, "no-store, no-cache, must-revalidate", rec.Header().Get("Cache-Control"),
				"Cache-Control header must be set on admin endpoint %s %s", route.method, route.path)
		})
	}
}
