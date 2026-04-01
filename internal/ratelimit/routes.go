package ratelimit

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/httprate"
	"github.com/redis/go-redis/v9"
)

// RouteMiddlewares holds the rate limit middleware for each route group.
type RouteMiddlewares struct {
	// SignupByIP: 5 per 15min per IP
	SignupByIP func(http.Handler) http.Handler

	// LoginByIP: 10 per 5min per IP
	LoginByIP func(http.Handler) http.Handler

	// LoginByAccount: 5 per 5min per account (extracted from request body)
	LoginByAccount func(http.Handler) http.Handler

	// PasswordByAccount: 3 per 15min per account
	PasswordByAccount func(http.Handler) http.Handler

	// TokenRefreshBySession: 30 per 1min per session
	TokenRefreshBySession func(http.Handler) http.Handler
}

// NewRouteMiddlewares creates all route-specific rate limit middlewares.
//
// IMPORTANT: IP-based rate limits use KeyByRealIP which trusts X-Forwarded-For,
// X-Real-IP, and True-Client-IP headers. PalAuth MUST be deployed behind a
// reverse proxy (e.g., nginx, Caddy, cloud LB) that overwrites these headers
// with the actual client IP. Without this, attackers can bypass IP-based rate
// limits by spoofing these headers.
func NewRouteMiddlewares(rdb redis.UniversalClient, logger *slog.Logger) *RouteMiddlewares {
	return &RouteMiddlewares{
		SignupByIP: NewMiddleware(RateLimitConfig{
			Name:    "signup",
			Limit:   5,
			Window:  15 * time.Minute,
			KeyFunc: httprate.KeyByRealIP,
		}, rdb, logger),

		LoginByIP: NewMiddleware(RateLimitConfig{
			Name:    "login_ip",
			Limit:   10,
			Window:  5 * time.Minute,
			KeyFunc: httprate.KeyByRealIP,
		}, rdb, logger),

		LoginByAccount: NewMiddleware(RateLimitConfig{
			Name:   "login_acct",
			Limit:  5,
			Window: 5 * time.Minute,
			KeyFunc: func(r *http.Request) (string, error) {
				// Account key is set by the handler via context before rate limiting.
				// Falls back to IP if account key is not available.
				if key := GetAccountKey(r); key != "" {
					return key, nil
				}
				return httprate.KeyByRealIP(r)
			},
		}, rdb, logger),

		PasswordByAccount: NewMiddleware(RateLimitConfig{
			Name:   "pwd",
			Limit:  3,
			Window: 15 * time.Minute,
			KeyFunc: func(r *http.Request) (string, error) {
				if key := GetAccountKey(r); key != "" {
					return key, nil
				}
				return httprate.KeyByRealIP(r)
			},
		}, rdb, logger),

		TokenRefreshBySession: NewMiddleware(RateLimitConfig{
			Name:   "refresh",
			Limit:  30,
			Window: 1 * time.Minute,
			KeyFunc: func(r *http.Request) (string, error) {
				if key := GetSessionKey(r); key != "" {
					return key, nil
				}
				return httprate.KeyByRealIP(r)
			},
		}, rdb, logger),
	}
}
