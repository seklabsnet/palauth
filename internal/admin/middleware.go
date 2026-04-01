package admin

import (
	"context"
	"net/http"
	"strings"

	"github.com/palauth/palauth/internal/httputil"
)

type adminCtxKey string

const adminClaimsCtxKey adminCtxKey = "admin_claims"

// AdminClaimsFromContext returns the admin claims from the request context.
func AdminClaimsFromContext(ctx context.Context) *AdminClaims {
	if c, ok := ctx.Value(adminClaimsCtxKey).(*AdminClaims); ok {
		return c
	}
	return nil
}

// AuthMiddleware returns an HTTP middleware that validates admin JWT tokens.
func (s *Service) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httputil.WriteError(s.logger, w, r, http.StatusUnauthorized, "missing_token", "Authorization header is required")
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				httputil.WriteError(s.logger, w, r, http.StatusUnauthorized, "invalid_token", "Authorization header must use Bearer scheme")
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := s.ValidateToken(token)
			if err != nil {
				httputil.WriteError(s.logger, w, r, http.StatusUnauthorized, "invalid_token", "The provided token is invalid or expired")
				return
			}

			ctx := context.WithValue(r.Context(), adminClaimsCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
