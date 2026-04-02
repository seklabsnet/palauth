package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProjectRoutes_RequireAuth(t *testing.T) {
	s := newTestServer(t)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/projects"},
		{http.MethodPost, "/admin/projects"},
		{http.MethodGet, "/admin/projects/prj_test-123/"},
		{http.MethodPut, "/admin/projects/prj_test-123/config"},
		{http.MethodDelete, "/admin/projects/prj_test-123/"},
		{http.MethodPost, "/admin/projects/prj_test-123/keys/rotate"},
		{http.MethodGet, "/admin/projects/prj_test-123/keys"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(),route.method, route.path, http.NoBody)
			rec := httptest.NewRecorder()

			s.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "route %s %s should require auth", route.method, route.path)
		})
	}
}
