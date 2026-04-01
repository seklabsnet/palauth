package httputil

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

// ErrorResponse is the standard error response format used across all packages.
type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
	Status      int    `json:"status"`
	RequestID   string `json:"request_id"`
}

// GetRequestID returns the request ID from the context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// SetRequestID stores the request ID in the context.
func SetRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// WriteError writes a JSON error response with the standard format.
func WriteError(logger *slog.Logger, w http.ResponseWriter, r *http.Request, status int, errCode, description string) {
	resp := ErrorResponse{
		Error:       errCode,
		Description: description,
		Status:      status,
		RequestID:   GetRequestID(r.Context()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Error("failed to write error response", "error", err)
	}
}

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(logger *slog.Logger, w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error("failed to write json response", "error", err)
	}
}
