package ratelimit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/httprate"
	httprateredis "github.com/go-chi/httprate-redis"
	"github.com/redis/go-redis/v9"

	"github.com/palauth/palauth/internal/server"
)

// Config holds the parameters for a single rate limit rule.
type Config struct {
	// Name identifies this rate limit rule. Used as part of the Redis key prefix
	// to ensure different route limiters have isolated counter namespaces.
	Name    string
	Limit   int
	Window  time.Duration
	KeyFunc httprate.KeyFunc
}

// errorResponse matches the project's standard error format.
type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
	Status      int    `json:"status"`
	RequestID   string `json:"request_id"`
	RetryAfter  int    `json:"retry_after"`
}

// NewMiddleware creates a Chi-compatible rate limit middleware.
// If rdb is nil, rate limiting uses in-memory only (useful for single-instance / tests).
// If Redis goes down at runtime, httprate-redis automatically falls back to a local
// in-memory counter (fail-open behavior).
func NewMiddleware(cfg Config, rdb redis.UniversalClient, logger *slog.Logger) func(http.Handler) http.Handler {
	opts := []httprate.Option{
		httprate.WithKeyFuncs(cfg.KeyFunc),
		httprate.WithLimitHandler(limitHandler(cfg.Window, logger)),
	}

	if rdb != nil {
		opts = append(opts, httprateredis.WithRedisLimitCounter(&httprateredis.Config{
			Client:          rdb,
			WindowLength:    cfg.Window,
			PrefixKey:       "palauth:rl:" + cfg.Name,
			FallbackTimeout: 250 * time.Millisecond,
			OnError: func(err error) {
				logger.Warn("rate limiter redis error, falling back to local counter",
					"error", err,
				)
			},
			OnFallbackChange: func(activated bool) {
				if activated {
					logger.Warn("rate limiter fallback activated — using local in-memory counter")
				} else {
					logger.Info("rate limiter fallback deactivated — redis reconnected")
				}
			},
		}))
	}

	return httprate.Limit(cfg.Limit, cfg.Window, opts...)
}

// limitHandler returns a 429 response in the project's standard error format.
func limitHandler(window time.Duration, logger *slog.Logger) http.HandlerFunc {
	retryAfter := int(window.Seconds())

	return func(w http.ResponseWriter, r *http.Request) {
		reqID := server.GetRequestID(r.Context())

		resp := errorResponse{
			Error:       "rate_limit_exceeded",
			Description: "Too many requests, please try again later",
			Status:      http.StatusTooManyRequests,
			RequestID:   reqID,
			RetryAfter:  retryAfter,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		w.WriteHeader(http.StatusTooManyRequests)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error("failed to write rate limit response", "error", err)
		}
	}
}
