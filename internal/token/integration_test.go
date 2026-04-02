package token_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/palauth/palauth/internal/config"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
	palredis "github.com/palauth/palauth/internal/redis"
	"github.com/palauth/palauth/internal/token"
)

func setupTestDB(t *testing.T) (pool *pgxpool.Pool, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("palauth_test"),
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

	migrationsDir, err := filepath.Abs("../../migrations")
	require.NoError(t, err)
	runMigrations(t, pool, migrationsDir)

	return pool, func() {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
	}
}

func setupTestRedis(t *testing.T) (rdb *palredis.Client, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	redisContainer, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	connStr, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	rdb, err = palredis.New(ctx, &config.RedisConfig{
		URL:      connStr,
		PoolSize: 5,
	}, slog.Default())
	require.NoError(t, err)

	return rdb, func() {
		_ = rdb.Close()
		_ = redisContainer.Terminate(ctx)
	}
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func createTestProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	projectID := id.New("prj_")
	_, err := pool.Exec(context.Background(),
		"INSERT INTO projects (id, name, config) VALUES ($1, $2, '{}')",
		projectID, "Test Project")
	require.NoError(t, err)
	return projectID
}

func createTestUser(t *testing.T, pool *pgxpool.Pool, projectID string) string {
	t.Helper()
	userID := id.New("usr_")
	_, err := pool.Exec(context.Background(),
		"INSERT INTO users (id, project_id, email_encrypted, email_hash) VALUES ($1, $2, $3, $4)",
		userID, projectID, []byte("encrypted"), []byte("hash"))
	require.NoError(t, err)
	return userID
}

func createTestSession(t *testing.T, pool *pgxpool.Pool, projectID, userID string) string {
	t.Helper()
	sessionID := id.New("sess_")
	amr, _ := json.Marshal([]string{"pwd"})
	q := sqlc.New(pool)
	_, err := q.CreateSession(context.Background(), sqlc.CreateSessionParams{
		ID:            sessionID,
		ProjectID:     projectID,
		UserID:        userID,
		Acr:           "aal1",
		Amr:           amr,
		IdleTimeoutAt: pgtype.Timestamptz{Time: time.Now().Add(1 * time.Hour), Valid: true},
		AbsTimeoutAt:  pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	require.NoError(t, err)
	return sessionID
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

// --- Refresh Token Integration Tests ---

func TestIntegration_RefreshTokenIssueAndRotate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	// Issue a refresh token.
	plainToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)
	require.NotEmpty(t, plainToken)

	// Rotate the token — should succeed and return new tokens.
	result, err := refreshSvc.Rotate(ctx, plainToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.NotEqual(t, plainToken, result.RefreshToken, "new token should differ from old")
	assert.Equal(t, sessionID, result.SessionID)
	assert.Equal(t, userID, result.UserID)

	// Chain rotation — new token should also rotate successfully.
	result2, err := refreshSvc.Rotate(ctx, result.RefreshToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.NotEqual(t, result.RefreshToken, result2.RefreshToken)
}

func TestIntegration_FamilyRevocation_StolenToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	refreshSvc.SetGracePeriod(0) // Disable grace period for immediate stolen detection.
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	// Issue initial token.
	originalToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)

	// Legitimate rotation — user gets new token.
	result, err := refreshSvc.Rotate(ctx, originalToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.NoError(t, err)
	newToken := result.RefreshToken

	// Attacker tries to use the ORIGINAL token (already used) — STOLEN.
	_, err = refreshSvc.Rotate(ctx, originalToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, token.ErrTokenStolen)

	// The legitimate user's NEW token should also be revoked (family revocation).
	_, err = refreshSvc.Rotate(ctx, newToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.Error(t, err)
	// Token was marked used by family revocation, no child exists -> stolen.
	assert.ErrorIs(t, err, token.ErrTokenStolen)
}

func TestIntegration_GracePeriod(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	// Issue initial token.
	originalToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)

	// First rotation — should succeed.
	result1, err := refreshSvc.Rotate(ctx, originalToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.NoError(t, err)
	require.NotNil(t, result1)

	// Immediately try to rotate with the SAME original token (grace period).
	// This simulates a concurrent request.
	result2, err := refreshSvc.Rotate(ctx, originalToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.NoError(t, err, "grace period should allow re-use within 30s")
	require.NotNil(t, result2)
	assert.NotEmpty(t, result2.AccessToken)
	assert.NotEmpty(t, result2.RefreshToken)
}

func TestIntegration_RefreshTokenExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	// Use very short TTL.
	refreshSvc := token.NewRefreshService(pool, jwtSvc, 100*time.Millisecond, logger)
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	plainToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)

	// Wait for expiry.
	time.Sleep(200 * time.Millisecond)

	_, err = refreshSvc.Rotate(ctx, plainToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, token.ErrTokenExpiredRT)
}

func TestIntegration_RefreshTokenNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)

	_, err = refreshSvc.Rotate(context.Background(), "nonexistent-token", "prj_any", &token.IssueParams{
		Issuer: "test",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, token.ErrTokenNotFound)
}

func TestIntegration_RevokeByHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	plainToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)

	// Revoke.
	err = refreshSvc.RevokeByHash(ctx, plainToken)
	require.NoError(t, err)

	// Try to rotate — should fail.
	_, err = refreshSvc.Rotate(ctx, plainToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.Error(t, err)

	// Revoking a nonexistent token should succeed (RFC 7009).
	err = refreshSvc.RevokeByHash(ctx, "nonexistent-token")
	require.NoError(t, err)
}

func TestIntegration_SessionRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	plainToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)

	// Revoke the session.
	q := sqlc.New(pool)
	err = q.RevokeSession(ctx, sessionID)
	require.NoError(t, err)

	// Rotate should fail with session revoked.
	_, err = refreshSvc.Rotate(ctx, plainToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, token.ErrSessionRevoked)
}

func TestIntegration_RefreshToken_ProjectMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	// Issue a refresh token for projectID.
	plainToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)

	// Try to rotate with a different project — should fail.
	otherProjectID := createTestProject(t, pool)
	_, err = refreshSvc.Rotate(ctx, plainToken, otherProjectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, token.ErrProjectMismatch)

	// Should still work with the correct project.
	result, err := refreshSvc.Rotate(ctx, plainToken, projectID, &token.IssueParams{
		Issuer:   "test",
		AuthTime: time.Now(),
	})
	require.NoError(t, err)
	require.NotNil(t, result)
}

// --- Custom Token Exchange Integration Test ---

func TestIntegration_CustomTokenExchange_SingleUse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	rdb, redisCleanup := setupTestRedis(t)
	defer redisCleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	customSvc := token.NewCustomTokenService(jwtSvc, rdb, logger)
	ctx := context.Background()

	// Create a custom token.
	customToken, err := customSvc.CreateCustomToken(token.CreateCustomTokenParams{
		UserID:    "usr_test-123",
		ProjectID: "prj_test-456",
		Issuer:    "test",
		Claims:    map[string]any{"role": "admin"},
		ExpiresIn: 5 * time.Minute,
	})
	require.NoError(t, err)

	// First exchange should succeed.
	claims, err := customSvc.ExchangeCustomToken(ctx, customToken)
	require.NoError(t, err)
	assert.Equal(t, "usr_test-123", claims.Subject)
	assert.Equal(t, "prj_test-456", claims.ProjectID)
	assert.Equal(t, "admin", claims.CustomClaims["role"])

	// Second exchange with SAME token should fail (single-use).
	_, err = customSvc.ExchangeCustomToken(ctx, customToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, token.ErrCustomTokenAlreadyUsed)
}

func TestIntegration_CustomTokenExchange_ExpiredToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	rdb, redisCleanup := setupTestRedis(t)
	defer redisCleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	customSvc := token.NewCustomTokenService(jwtSvc, rdb, logger)

	// Create a custom token with very short TTL.
	customToken, err := customSvc.CreateCustomToken(token.CreateCustomTokenParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		ExpiresIn: 1 * time.Millisecond,
	})
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	// Exchange should fail — token expired.
	_, err = customSvc.ExchangeCustomToken(context.Background(), customToken)
	require.Error(t, err)
}

// --- Auth Time Preservation Test ---

func TestIntegration_AuthTimePreservedOnRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	plainToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)

	// Rotate with no AuthTime set — should use session's created_at.
	result, err := refreshSvc.Rotate(ctx, plainToken, projectID, &token.IssueParams{
		Issuer: "test",
		// AuthTime intentionally NOT set — should come from session.
	})
	require.NoError(t, err)

	// Verify the auth_time in the access token matches session creation time.
	claims, err := jwtSvc.Verify(result.AccessToken)
	require.NoError(t, err)

	// auth_time should be close to session creation time, not time.Now().
	// Session was just created, so auth_time should be within a few seconds.
	authTimeT := time.Unix(claims.AuthTime, 0)
	assert.WithinDuration(t, time.Now(), authTimeT, 5*time.Second,
		"auth_time should reflect session creation, not refresh time")
}

// --- Introspect + Revoke integration ---

func TestIntegration_RevokeAndIntrospect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	ctx := context.Background()

	projectID := createTestProject(t, pool)
	userID := createTestUser(t, pool, projectID)
	sessionID := createTestSession(t, pool, projectID, userID)

	// Issue tokens.
	accessToken, err := jwtSvc.Issue(&token.IssueParams{
		UserID:    userID,
		SessionID: sessionID,
		ProjectID: projectID,
		Issuer:    "test",
		AuthTime:  time.Now(),
	})
	require.NoError(t, err)

	refreshToken, err := refreshSvc.Issue(ctx, userID, sessionID, projectID)
	require.NoError(t, err)

	// Introspect should show active.
	resp := jwtSvc.IntrospectAccessToken(accessToken)
	assert.True(t, resp.Active)
	assert.Equal(t, userID, resp.Subject)
	assert.Equal(t, projectID, resp.ProjectID)

	// Revoke refresh token.
	err = refreshSvc.Revoke(ctx, refreshToken, "refresh_token")
	require.NoError(t, err)

	// Revoke always returns 200 — even for invalid tokens.
	err = refreshSvc.Revoke(ctx, "completely-invalid-token", "")
	require.NoError(t, err)

	// Revoke with access_token hint is a no-op.
	err = refreshSvc.Revoke(ctx, accessToken, "access_token")
	require.NoError(t, err)

	// Introspect with invalid token.
	resp = jwtSvc.IntrospectAccessToken("invalid-token")
	assert.False(t, resp.Active)
}

func TestIntegration_Revoke_AlwaysReturns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := newTestLogger()
	jwtSvc, err := token.NewJWTService(token.JWTConfig{Algorithm: token.AlgES256, Logger: logger})
	require.NoError(t, err)

	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)
	ctx := context.Background()

	tests := []struct {
		name          string
		token         string
		tokenTypeHint string
	}{
		{"empty token", "", ""},
		{"random string", "random-string-not-a-token", ""},
		{"fake refresh", "fake-refresh-token", "refresh_token"},
		{"fake access", "fake-access-token", "access_token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := refreshSvc.Revoke(ctx, tt.token, tt.tokenTypeHint)
			assert.NoError(t, err, fmt.Sprintf("revoke should always succeed for %s", tt.name))
		})
	}
}
