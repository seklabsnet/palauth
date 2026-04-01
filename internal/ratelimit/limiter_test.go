package ratelimit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/redis"

	palredis "github.com/palauth/palauth/internal/redis"
	"github.com/palauth/palauth/internal/config"
)

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func TestRateLimiter_InMemory_BlocksAfterLimit(t *testing.T) {
	logger := slog.Default()
	limit := 3
	window := 1 * time.Minute

	mw := NewMiddleware(RateLimitConfig{
		Name:    "test_block",
		Limit:   limit,
		Window:  window,
		KeyFunc: httprate.KeyByIP,
	}, nil, logger)

	r := chi.NewRouter()
	r.Use(mw)
	r.Get("/test", okHandler)

	// First 3 requests should succeed
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "request %d should succeed", i+1)
	}

	// 4th request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	// Verify response body
	var resp errorResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "rate_limit_exceeded", resp.Error)
	assert.Equal(t, 429, resp.Status)
	assert.Equal(t, 60, resp.RetryAfter)
	assert.Equal(t, "Too many requests, please try again later", resp.Description)

	// Verify Retry-After header
	assert.Equal(t, "60", rec.Header().Get("Retry-After"))
}

func TestRateLimiter_DifferentIPs_IndependentLimits(t *testing.T) {
	logger := slog.Default()
	limit := 2

	mw := NewMiddleware(RateLimitConfig{
		Name:    "test_diffip",
		Limit:   limit,
		Window:  1 * time.Minute,
		KeyFunc: httprate.KeyByIP,
	}, nil, logger)

	r := chi.NewRouter()
	r.Use(mw)
	r.Get("/test", okHandler)

	// Exhaust limit for IP 1
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	// IP 1 is now limited
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	// IP 2 should still work
	req2 := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req2.RemoteAddr = "10.0.0.2:1234"
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
}

func TestRateLimiter_ResponseHeaders(t *testing.T) {
	logger := slog.Default()
	limit := 5

	mw := NewMiddleware(RateLimitConfig{
		Name:    "test_headers",
		Limit:   limit,
		Window:  1 * time.Minute,
		KeyFunc: httprate.KeyByIP,
	}, nil, logger)

	r := chi.NewRouter()
	r.Use(mw)
	r.Get("/test", okHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Limit"))
	assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Reset"))
}

func TestRateLimiter_AccountKey(t *testing.T) {
	logger := slog.Default()
	limit := 2

	mw := NewMiddleware(RateLimitConfig{
		Name:   "test_acct",
		Limit:  limit,
		Window: 1 * time.Minute,
		KeyFunc: func(r *http.Request) (string, error) {
			if key := GetAccountKey(r); key != "" {
				return key, nil
			}
			return httprate.KeyByRealIP(r)
		},
	}, nil, logger)

	// Middleware to set account key
	setAccount := func(account string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := WithAccountKey(r.Context(), account)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}
	}

	r := chi.NewRouter()
	r.Use(setAccount("user@example.com"))
	r.Use(mw)
	r.Get("/test", okHandler)

	// Two different IPs but same account — should share rate limit
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	// Same account from different IP — should be limited
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.2:1234"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestRateLimiter_WithRedis(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	container, err := redis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(ctx)) })

	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	logger := slog.Default()
	client, err := palredis.New(ctx, &config.RedisConfig{URL: connStr}, logger)
	require.NoError(t, err)
	defer client.Close()

	limit := 3
	mw := NewMiddleware(RateLimitConfig{
		Name:    "test_redis",
		Limit:   limit,
		Window:  1 * time.Minute,
		KeyFunc: httprate.KeyByIP,
	}, client.Unwrap(), logger)

	r := chi.NewRouter()
	r.Use(mw)
	r.Get("/test", okHandler)

	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "request %d should succeed", i+1)
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestRateLimiter_FailOpen_RedisUnavailable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	container, err := redis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	logger := slog.Default()
	client, err := palredis.New(ctx, &config.RedisConfig{URL: connStr}, logger)
	require.NoError(t, err)

	rdb := client.Unwrap()

	mw := NewMiddleware(RateLimitConfig{
		Name:    "test_failopen",
		Limit:   100,
		Window:  1 * time.Minute,
		KeyFunc: httprate.KeyByIP,
	}, rdb, logger)

	r := chi.NewRouter()
	r.Use(mw)
	r.Get("/test", okHandler)

	// Verify it works initially
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Kill Redis container
	require.NoError(t, container.Terminate(ctx))

	// Wait for fallback to activate
	time.Sleep(500 * time.Millisecond)

	// Requests should still go through (fail-open via local fallback)
	req2 := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req2.RemoteAddr = "10.0.0.1:1234"
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code, "should fail-open when Redis is down")
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Account key
	ctx = WithAccountKey(ctx, "test@example.com")
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(ctx)
	assert.Equal(t, "test@example.com", GetAccountKey(r))

	// Session key
	ctx = WithSessionKey(ctx, "sess_123")
	r = httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(ctx)
	assert.Equal(t, "sess_123", GetSessionKey(r))

	// Missing keys return empty
	r2 := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	assert.Empty(t, GetAccountKey(r2))
	assert.Empty(t, GetSessionKey(r2))
}

func TestRateLimiter_CrossRouteIsolation(t *testing.T) {
	// Verify that two rate limiters with different Names but the same KeyFunc
	// maintain independent counters (no cross-route collision).
	logger := slog.Default()
	limit := 2

	signupMw := NewMiddleware(RateLimitConfig{
		Name:    "signup",
		Limit:   limit,
		Window:  1 * time.Minute,
		KeyFunc: httprate.KeyByIP,
	}, nil, logger)

	loginMw := NewMiddleware(RateLimitConfig{
		Name:    "login_ip",
		Limit:   limit,
		Window:  1 * time.Minute,
		KeyFunc: httprate.KeyByIP,
	}, nil, logger)

	signupRouter := chi.NewRouter()
	signupRouter.Use(signupMw)
	signupRouter.Post("/auth/signup", okHandler)

	loginRouter := chi.NewRouter()
	loginRouter.Use(loginMw)
	loginRouter.Post("/auth/login", okHandler)

	ip := "10.0.0.99:1234"

	// Exhaust signup limit
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/signup", http.NoBody)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		signupRouter.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "signup request %d should succeed", i+1)
	}

	// Signup is now limited
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", http.NoBody)
	req.RemoteAddr = ip
	rec := httptest.NewRecorder()
	signupRouter.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "signup should be rate limited")

	// Login from the same IP should still work (different Name = different counter)
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", http.NoBody)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		loginRouter.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "login request %d should succeed despite signup being limited", i+1)
	}
}

func TestNewRouteMiddlewares(t *testing.T) {
	logger := slog.Default()
	rm := NewRouteMiddlewares(nil, logger)

	assert.NotNil(t, rm.SignupByIP)
	assert.NotNil(t, rm.LoginByIP)
	assert.NotNil(t, rm.LoginByAccount)
	assert.NotNil(t, rm.PasswordByAccount)
	assert.NotNil(t, rm.TokenRefreshBySession)
}
