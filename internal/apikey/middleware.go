package apikey

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/palauth/palauth/internal/httputil"
)

type apiKeyCtxKey string

const projectIDCtxKey apiKeyCtxKey = "project_id"

// ProjectIDFromContext returns the project ID from the request context.
func ProjectIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(projectIDCtxKey).(string); ok {
		return v
	}
	return ""
}

// SetProjectID stores the project ID in the context.
func SetProjectID(ctx context.Context, projectID string) context.Context {
	return context.WithValue(ctx, projectIDCtxKey, projectID)
}

// Middleware returns an HTTP middleware that authenticates requests via X-API-Key header.
func (s *Service) Middleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				httputil.WriteError(logger, w, r, http.StatusUnauthorized, "missing_api_key", "X-API-Key header is required")
				return
			}

			info, err := s.Verify(r.Context(), apiKey)
			if err != nil {
				switch {
				case errors.Is(err, ErrKeyNotFound), errors.Is(err, ErrInvalidKey):
					httputil.WriteError(logger, w, r, http.StatusUnauthorized, "invalid_api_key", "The provided API key is invalid")
				case errors.Is(err, ErrKeyRevoked):
					httputil.WriteError(logger, w, r, http.StatusUnauthorized, "revoked_api_key", "The provided API key has been revoked")
				default:
					logger.Error("api key verification failed", "error", err)
					httputil.WriteError(logger, w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
				}
				return
			}

			ctx := SetProjectID(r.Context(), info.ProjectID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
