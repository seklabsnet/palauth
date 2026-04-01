package httputil

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRequestID_Empty(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", GetRequestID(ctx))
}

func TestSetAndGetRequestID(t *testing.T) {
	ctx := context.Background()
	ctx = SetRequestID(ctx, "req_test-123")
	assert.Equal(t, "req_test-123", GetRequestID(ctx))
}

func TestWriteError(t *testing.T) {
	logger := slog.Default()
	rec := httptest.NewRecorder()
	ctx := SetRequestID(context.Background(), "req_abc")
	r := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)

	WriteError(logger, rec, r, http.StatusBadRequest, "test_error", "Test description")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp ErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "test_error", resp.Error)
	assert.Equal(t, "Test description", resp.Description)
	assert.Equal(t, 400, resp.Status)
	assert.Equal(t, "req_abc", resp.RequestID)
}

func TestWriteJSON(t *testing.T) {
	logger := slog.Default()
	rec := httptest.NewRecorder()

	data := map[string]string{"key": "value"}
	WriteJSON(logger, rec, http.StatusOK, data)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "value", resp["key"])
}
