package chaos_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/auth"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/project"
	"github.com/palauth/palauth/internal/token"
)

const testPepper = "chaos-test-pepper-at-least-32-bytes-long-ok!!"

func TestChaos_RedisDown_LockoutFailOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chaos test in short mode")
	}

	ctx := context.Background()

	// 1. Start Postgres + Redis.
	pool, pgCleanup := startPostgres(t)
	defer pgCleanup()

	redisContainer, rdb, redisCleanup := startRedisWithContainer(t)
	defer redisCleanup()

	// Run migrations.
	migrationsDir, err := filepath.Abs("../../migrations")
	require.NoError(t, err)
	runMigrations(t, pool, migrationsDir)

	// 2. Create service with lockout (uses Redis).
	svc := newTestAuthServiceWithLockout(t, pool, rdb)

	projectID := createTestProject(t, pool, "code")

	// 3. Verify login works normally.
	_, err = svc.Signup(ctx, "chaos@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	result, _, err := svc.Login(ctx, &auth.LoginParams{
		Email:     "chaos@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken, "login should work when Redis is up")

	// 4. Stop Redis container.
	err = redisContainer.Stop(ctx, nil)
	require.NoError(t, err)
	t.Log("Redis container stopped")

	// Wait for Redis connection to fail.
	time.Sleep(1 * time.Second)

	// 5. Verify login STILL works (lockout fail-open).
	result2, _, err := svc.Login(ctx, &auth.LoginParams{
		Email:     "chaos@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err, "login should still work when Redis is down (fail-open)")
	assert.NotEmpty(t, result2.AccessToken)

	// 6. Restart Redis.
	err = redisContainer.Start(ctx)
	require.NoError(t, err)
	t.Log("Redis container restarted")

	// Wait for reconnection.
	time.Sleep(2 * time.Second)

	// 7. Verify lockout resumes — record failures until lockout triggers.
	for i := 0; i < 10; i++ {
		_, _, err = svc.Login(ctx, &auth.LoginParams{
			Email:     "chaos@example.com",
			Password:  "wrong-password-12345!",
			ProjectID: projectID,
		})
		assert.ErrorIs(t, err, auth.ErrInvalidCredentials, "attempt %d", i+1)
	}

	// Should now be locked.
	_, retryAfter, err := svc.Login(ctx, &auth.LoginParams{
		Email:     "chaos@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	assert.ErrorIs(t, err, auth.ErrAccountLocked, "should be locked after 10 failures with Redis up")
	assert.True(t, retryAfter > 0, "retry_after should be positive")
}

// Helper functions.

func startPostgres(t *testing.T) (pool *pgxpool.Pool, cleanup func()) { //nolint:unparam // test helper
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("palauth_chaos"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err = pgxpool.New(ctx, connStr)
	require.NoError(t, err)

	return pool, func() {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
	}
}

func startRedisWithContainer(t *testing.T) (testcontainers.Container, *redis.Client, func()) {
	t.Helper()
	ctx := context.Background()

	redisContainer, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	connStr, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	opts, err := redis.ParseURL(connStr)
	require.NoError(t, err)

	client := redis.NewClient(opts)

	return redisContainer, client, func() {
		_ = client.Close()
		_ = redisContainer.Terminate(ctx)
	}
}

func runMigrations(t *testing.T, pool *pgxpool.Pool, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var upFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	for _, f := range upFiles {
		sqlBytes, err := os.ReadFile(filepath.Join(dir, f))
		require.NoError(t, err, "reading migration %s", f)
		_, err = pool.Exec(context.Background(), string(sqlBytes))
		require.NoError(t, err, "executing migration %s", f)
	}
}

func createTestProject(t *testing.T, pool *pgxpool.Pool, verificationMethod string) string {
	t.Helper()
	cfg := project.DefaultConfig()
	cfg.EmailVerificationMethod = verificationMethod

	configJSON, err := json.Marshal(cfg)
	require.NoError(t, err)

	projectID := fmt.Sprintf("prj_chaos_%d", time.Now().UnixNano())
	_, err = pool.Exec(context.Background(),
		"INSERT INTO projects (id, name, config) VALUES ($1, $2, $3)",
		projectID, "Chaos Test Project", configJSON)
	require.NoError(t, err)
	return projectID
}

func notBreachedHIBPServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:0\r\n"))
	}))
}

func newTestAuthServiceWithLockout(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client) *auth.Service {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	projectSvc := project.NewService(pool, nil, logger)

	jwtSvc, err := token.NewJWTService(token.JWTConfig{
		Algorithm: token.AlgPS256,
		Logger:    logger,
	})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)

	auditKEKMac := hmac.New(sha256.New, []byte(testPepper))
	auditKEKMac.Write([]byte("audit-log-kek"))
	auditKEK := auditKEKMac.Sum(nil)
	auditSvc := audit.NewService(pool, auditKEK, logger)

	hibp := notBreachedHIBPServer()
	t.Cleanup(hibp.Close)
	bc := crypto.NewBreachCheckerWithURL(hibp.URL + "/range/")

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}

	var lockoutSvc *auth.LockoutService
	if rdb != nil {
		lockoutSvc = auth.NewLockoutService(rdb, logger)
	}

	return auth.NewService(pool, projectSvc, jwtSvc, refreshSvc, auditSvc, bc, lockoutSvc, nil, nil, testPepper, kek, logger)
}
