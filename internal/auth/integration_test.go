package auth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA1 is required for HIBP k-Anonymity API
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

const testPepper = "this-is-a-test-pepper-at-least-32-bytes-long-ok"

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

	cleanup = func() {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
	}

	return pool, cleanup
}

func testKEK() []byte {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	return kek
}

func newTestAuthService(t *testing.T, pool *pgxpool.Pool, hibpServer *httptest.Server) *auth.Service {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	projectSvc := project.NewService(pool, logger)

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

	var bc *crypto.BreachChecker
	if hibpServer != nil {
		bc = crypto.NewBreachCheckerWithURL(hibpServer.URL + "/range/")
	} else {
		// Create a server that returns no breaches.
		s := notBreachedHIBPServer()
		t.Cleanup(s.Close)
		bc = crypto.NewBreachCheckerWithURL(s.URL + "/range/")
	}

	return auth.NewService(pool, projectSvc, jwtSvc, refreshSvc, auditSvc, bc, nil, testPepper, testKEK(), logger)
}

func createTestProject(t *testing.T, pool *pgxpool.Pool, verificationMethod string) string {
	t.Helper()
	cfg := project.DefaultConfig()
	cfg.EmailVerificationMethod = verificationMethod

	configJSON, err := json.Marshal(cfg)
	require.NoError(t, err)

	projectID := fmt.Sprintf("prj_test_%d", time.Now().UnixNano())
	_, err = pool.Exec(context.Background(),
		"INSERT INTO projects (id, name, config) VALUES ($1, $2, $3)",
		projectID, "Test Project", configJSON)
	require.NoError(t, err)
	return projectID
}

// notBreachedHIBPServer returns a mock HIBP server that never reports breaches.
func notBreachedHIBPServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:0\r\n"))
	}))
}

// breachedHIBPServer returns a mock HIBP server that reports the given password as breached.
func breachedHIBPServer(password string) *httptest.Server {
	// Compute SHA1 to find the suffix the breach checker will look for.
	h := sha1.New() //nolint:gosec // SHA1 is required for HIBP k-Anonymity
	h.Write([]byte(password))
	fullHash := fmt.Sprintf("%X", h.Sum(nil))
	suffix := fullHash[5:]

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(suffix + ":999\r\n"))
	}))
}

func TestIntegration_SignupSuccess_CodeVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	result, err := svc.Signup(ctx, "alice@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify tokens are returned.
	assert.NotEmpty(t, result.AccessToken, "access token should be present")
	assert.NotEmpty(t, result.RefreshToken, "refresh token should be present")
	assert.Equal(t, "Bearer", result.TokenType)
	assert.Equal(t, 1800, result.ExpiresIn)

	// Verify user info.
	assert.NotEmpty(t, result.User.ID)
	assert.True(t, strings.HasPrefix(result.User.ID, "usr_"))
	assert.Equal(t, "alice@example.com", result.User.Email)
	assert.False(t, result.User.EmailVerified)

	// Verify OTP code is returned (code-based verification).
	assert.NotEmpty(t, result.VerificationCode, "verification code should be present")
	assert.Empty(t, result.VerificationToken, "verification token should not be present for code-based")
	assert.Len(t, result.VerificationCode, 6, "OTP should be 6 digits")
}

func TestIntegration_SignupSuccess_LinkVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "link")

	result, err := svc.Signup(ctx, "bob@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify link token is returned.
	assert.NotEmpty(t, result.VerificationToken, "verification token should be present")
	assert.Empty(t, result.VerificationCode, "verification code should not be present for link-based")
}

func TestIntegration_SignupDuplicateEmail_Enumeration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// First signup succeeds.
	_, err := svc.Signup(ctx, "alice@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Second signup with same email returns generic error (no enumeration).
	_, err = svc.Signup(ctx, "alice@example.com", "another-password-5678!", projectID)
	assert.ErrorIs(t, err, auth.ErrSignupFailed)
}

func TestIntegration_SignupBreachedPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	password := "secure-password-1234!"
	hibp := breachedHIBPServer(password)
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "breach@example.com", password, projectID)
	assert.ErrorIs(t, err, crypto.ErrPasswordBreached)
}

func TestIntegration_VerifyEmail_Link(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "link")

	// Signup to get verification token.
	result, err := svc.Signup(ctx, "verify-link@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)
	require.NotEmpty(t, result.VerificationToken)

	// Verify email with valid token.
	err = svc.VerifyEmailByToken(ctx, result.VerificationToken, projectID)
	assert.NoError(t, err)

	// Verify again with same token — should fail (used).
	err = svc.VerifyEmailByToken(ctx, result.VerificationToken, projectID)
	assert.ErrorIs(t, err, auth.ErrTokenNotFound)
}

func TestIntegration_VerifyEmail_OTP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup to get OTP code.
	result, err := svc.Signup(ctx, "verify-otp@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)
	require.NotEmpty(t, result.VerificationCode)

	// Verify email with valid code.
	err = svc.VerifyEmailByCode(ctx, result.VerificationCode, "verify-otp@example.com", projectID)
	assert.NoError(t, err)
}

func TestIntegration_VerifyEmail_InvalidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := newTestAuthService(t, pool, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "link")

	// Try to verify with a non-existent token.
	err := svc.VerifyEmailByToken(ctx, "non-existent-token", projectID)
	assert.ErrorIs(t, err, auth.ErrTokenNotFound)
}

func TestIntegration_VerifyEmail_ExpiredToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "link")

	// Signup.
	result, err := svc.Signup(ctx, "expired@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)
	require.NotEmpty(t, result.VerificationToken)

	// Manually expire the token in the database.
	_, err = pool.Exec(ctx,
		"UPDATE verification_tokens SET expires_at = $1 WHERE user_id = $2",
		time.Now().Add(-1*time.Hour), result.User.ID)
	require.NoError(t, err)

	// Try to verify with expired token.
	err = svc.VerifyEmailByToken(ctx, result.VerificationToken, projectID)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestIntegration_ResendVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup.
	_, err := svc.Signup(ctx, "resend@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Resend — should succeed with new code.
	resendResult, err := svc.ResendVerification(ctx, "resend@example.com", projectID)
	require.NoError(t, err)
	assert.NotEmpty(t, resendResult.VerificationCode)
}

func TestIntegration_ResendVerification_NonExistentEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := newTestAuthService(t, pool, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Resend for non-existent email — should succeed (enumeration prevention).
	result, err := svc.ResendVerification(ctx, "nobody@example.com", projectID)
	require.NoError(t, err)
	assert.Empty(t, result.VerificationCode, "no code for non-existent user")
}

func TestIntegration_AuditLogWrittenOnSignup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "audit@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Verify audit log was written.
	var count int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE project_id = $1 AND event_type = $2",
		projectID, "auth.signup").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "audit log should have one signup event")
}

func TestIntegration_WeakPasswordRejected_14Chars(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := newTestAuthService(t, pool, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// 14 char password — should be rejected (spec: 15 char min).
	_, err := svc.Signup(ctx, "weak@example.com", "14charpasswrd!", projectID)
	assert.ErrorIs(t, err, crypto.ErrPasswordTooShort)
}

func TestIntegration_AuditLogWrittenOnVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "link")

	result, err := svc.Signup(ctx, "auditverify@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.VerifyEmailByToken(ctx, result.VerificationToken, projectID)
	require.NoError(t, err)

	// Verify audit log for email verification.
	var count int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE project_id = $1 AND event_type = $2",
		projectID, "auth.email.verify").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "audit log should have one email verify event")
}

func TestIntegration_OTPMaxAttempts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup to get OTP code.
	result, err := svc.Signup(ctx, "otplimit@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)
	require.NotEmpty(t, result.VerificationCode)

	// Try 4 wrong codes — should get ErrTokenNotFound each time.
	for i := 0; i < 4; i++ {
		err = svc.VerifyEmailByCode(ctx, "000000", "otplimit@example.com", projectID)
		assert.ErrorIs(t, err, auth.ErrTokenNotFound, "attempt %d should return token not found", i+1)
	}

	// 5th wrong attempt — hits max attempts, token gets invalidated.
	err = svc.VerifyEmailByCode(ctx, "000000", "otplimit@example.com", projectID)
	assert.ErrorIs(t, err, auth.ErrOTPMaxAttempts, "5th failure should return max attempts")

	// After invalidation, even the correct code fails (token is used/gone).
	err = svc.VerifyEmailByCode(ctx, result.VerificationCode, "otplimit@example.com", projectID)
	assert.Error(t, err, "correct code should fail after max attempts")
}

func TestIntegration_EmailNormalization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup with mixed case email.
	result, err := svc.Signup(ctx, "Alice@Example.COM", "secure-password-1234!", projectID)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", result.User.Email, "email should be normalized")

	// Duplicate signup with different casing should fail (same user).
	_, err = svc.Signup(ctx, "alice@example.com", "another-password-5678!", projectID)
	assert.ErrorIs(t, err, auth.ErrSignupFailed)

	// OTP verification with different casing should work.
	err = svc.VerifyEmailByCode(ctx, result.VerificationCode, "ALICE@example.com", projectID)
	assert.NoError(t, err)
}

func TestIntegration_HIBPFailClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	// HIBP server that returns errors.
	hibpDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer hibpDown.Close()

	svc := newTestAuthService(t, pool, hibpDown)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "hibpfail@example.com", "secure-password-1234!", projectID)
	assert.ErrorIs(t, err, auth.ErrHIBPUnavailable, "should fail closed when HIBP is unavailable")
}

func setupTestRedis(t *testing.T) (client *redis.Client, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	redisContainer, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	connStr, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	opts, err := redis.ParseURL(connStr)
	require.NoError(t, err)

	client = redis.NewClient(opts)

	cleanup = func() {
		_ = client.Close()
		_ = redisContainer.Terminate(ctx)
	}
	return client, cleanup
}

func newTestAuthServiceWithLockout(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, hibpServer *httptest.Server) *auth.Service { //nolint:unparam // hibpServer kept for parity with newTestAuthService
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	projectSvc := project.NewService(pool, logger)

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

	var bc *crypto.BreachChecker
	if hibpServer != nil {
		bc = crypto.NewBreachCheckerWithURL(hibpServer.URL + "/range/")
	} else {
		s := notBreachedHIBPServer()
		t.Cleanup(s.Close)
		bc = crypto.NewBreachCheckerWithURL(s.URL + "/range/")
	}

	var lockoutSvc *auth.LockoutService
	if rdb != nil {
		lockoutSvc = auth.NewLockoutService(rdb, logger)
	}

	return auth.NewService(pool, projectSvc, jwtSvc, refreshSvc, auditSvc, bc, lockoutSvc, testPepper, testKEK(), logger)
}

func TestIntegration_LoginSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()
	rdb, redisCleanup := setupTestRedis(t)
	defer redisCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, rdb, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup first.
	_, err := svc.Signup(ctx, "login@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Login with correct credentials.
	result, _, err := svc.Login(ctx, &auth.LoginParams{
		Email:     "login@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, "Bearer", result.TokenType)
	assert.Equal(t, 1800, result.ExpiresIn)
	assert.Equal(t, "login@example.com", result.User.Email)
}

func TestIntegration_LoginWrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()
	rdb, redisCleanup := setupTestRedis(t)
	defer redisCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, rdb, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "wrongpw@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "wrongpw@example.com",
		Password:  "wrong-password-12345!",
		ProjectID: projectID,
	})
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestIntegration_LoginNonExistingEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, nil, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, _, err := svc.Login(ctx, &auth.LoginParams{
		Email:     "nobody@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials, "non-existing email should return same error")
}

func TestIntegration_LoginLockout_10Failures(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()
	rdb, redisCleanup := setupTestRedis(t)
	defer redisCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, rdb, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "lockout@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// 10 failed attempts.
	for i := 0; i < 10; i++ {
		_, _, err = svc.Login(ctx, &auth.LoginParams{
			Email:     "lockout@example.com",
			Password:  "wrong-password-12345!",
			ProjectID: projectID,
		})
		assert.ErrorIs(t, err, auth.ErrInvalidCredentials, "attempt %d should fail", i+1)
	}

	// 11th attempt should return account_locked.
	_, retryAfter, err := svc.Login(ctx, &auth.LoginParams{
		Email:     "lockout@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	assert.ErrorIs(t, err, auth.ErrAccountLocked)
	assert.True(t, retryAfter > 0, "retry_after should be positive")
}

func TestIntegration_LoginSuccessResetsCounter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()
	rdb, redisCleanup := setupTestRedis(t)
	defer redisCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, rdb, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "reset@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// 5 failed attempts.
	for i := 0; i < 5; i++ {
		_, _, err = svc.Login(ctx, &auth.LoginParams{
			Email:     "reset@example.com",
			Password:  "wrong-password-12345!",
			ProjectID: projectID,
		})
		assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
	}

	// Successful login resets counter.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "reset@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	// 9 more failed attempts — should NOT lock (counter was reset).
	for i := 0; i < 9; i++ {
		_, _, err = svc.Login(ctx, &auth.LoginParams{
			Email:     "reset@example.com",
			Password:  "wrong-password-12345!",
			ProjectID: projectID,
		})
		assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
	}

	// Should still be able to login (total 9 failed after reset, not 10).
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "reset@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err, "should login after counter reset")
}

func TestIntegration_LoginBannedUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, nil, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	result, err := svc.Signup(ctx, "banned@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Ban the user.
	_, err = pool.Exec(ctx, "UPDATE users SET banned = true WHERE id = $1", result.User.ID)
	require.NoError(t, err)

	// Login should fail with user_banned.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "banned@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	assert.ErrorIs(t, err, auth.ErrUserBanned)
}

func TestIntegration_LoginUpdatesLastLoginAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, nil, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	signupResult, err := svc.Signup(ctx, "lastlogin@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Check last_login_at is null before login.
	var lastLoginAtBefore *time.Time
	err = pool.QueryRow(ctx, "SELECT last_login_at FROM users WHERE id = $1", signupResult.User.ID).Scan(&lastLoginAtBefore)
	require.NoError(t, err)
	assert.Nil(t, lastLoginAtBefore, "last_login_at should be null before first login")

	// Login.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "lastlogin@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	// Check last_login_at is set.
	var lastLoginAtAfter *time.Time
	err = pool.QueryRow(ctx, "SELECT last_login_at FROM users WHERE id = $1", signupResult.User.ID).Scan(&lastLoginAtAfter)
	require.NoError(t, err)
	assert.NotNil(t, lastLoginAtAfter, "last_login_at should be set after login")
}

func TestIntegration_LoginAuditLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, nil, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "auditlogin@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Successful login.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "auditlogin@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	// Check audit log for login success.
	var count int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE project_id = $1 AND event_type = $2",
		projectID, "auth.login.success").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Failed login.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "auditlogin@example.com",
		Password:  "wrong-password-12345!",
		ProjectID: projectID,
	})
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)

	// Check audit log for login failure.
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE project_id = $1 AND event_type = $2",
		projectID, "auth.login.failure").Scan(&count)
	require.NoError(t, err)
	assert.True(t, count >= 1)
}

func TestIntegration_LoginTimingEqualization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, dbCleanup := setupTestDB(t)
	defer dbCleanup()

	svc := newTestAuthServiceWithLockout(t, pool, nil, nil)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "timing@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Measure time for existing user with wrong password.
	const iterations = 3
	var existingTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _, _ = svc.Login(ctx, &auth.LoginParams{
			Email:     "timing@example.com",
			Password:  "wrong-password-12345!",
			ProjectID: projectID,
		})
		existingTotal += time.Since(start)
	}
	existingAvg := existingTotal / iterations

	// Measure time for non-existing user.
	var nonExistingTotal time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, _, _ = svc.Login(ctx, &auth.LoginParams{
			Email:     "nonexistent@example.com",
			Password:  "wrong-password-12345!",
			ProjectID: projectID,
		})
		nonExistingTotal += time.Since(start)
	}
	nonExistingAvg := nonExistingTotal / iterations

	// The timing difference should be < 20%.
	var ratio float64
	if existingAvg > nonExistingAvg {
		ratio = float64(existingAvg) / float64(nonExistingAvg)
	} else {
		ratio = float64(nonExistingAvg) / float64(existingAvg)
	}

	t.Logf("existing user avg: %v, non-existing user avg: %v, ratio: %.2f", existingAvg, nonExistingAvg, ratio)
	assert.Less(t, ratio, 1.20, "timing difference between existing and non-existing user should be < 20%%")
}

// sha256Hash computes SHA-256 hash of a string and returns the raw bytes (test helper).
func sha256Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// ============================================================================
// Password Reset Integration Tests
// ============================================================================

func TestIntegration_PasswordReset_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup.
	_, err := svc.Signup(ctx, "reset-flow@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Request password reset.
	err = svc.RequestReset(ctx, projectID, "reset-flow@example.com")
	require.NoError(t, err)

	// Get the token from the DB (in prod this comes via email).
	var tokenHash []byte
	err = pool.QueryRow(ctx,
		"SELECT token_hash FROM verification_tokens WHERE type = 'password_reset' AND project_id = $1 ORDER BY created_at DESC LIMIT 1",
		projectID).Scan(&tokenHash)
	require.NoError(t, err)

	// We need the plain token. Since we can't reverse the hash, read it from logs.
	// For testing, generate a new token and insert it manually.
	plainToken, err := crypto.GenerateToken(32)
	require.NoError(t, err)
	newHash := sha256Hash(plainToken)
	_, err = pool.Exec(ctx,
		"UPDATE verification_tokens SET token_hash = $1 WHERE type = 'password_reset' AND project_id = $2 AND token_hash = $3",
		newHash, projectID, tokenHash)
	require.NoError(t, err)

	// Confirm reset with the new password.
	err = svc.ConfirmReset(ctx, projectID, plainToken, "brand-new-password-5678!")
	require.NoError(t, err)

	// Login with new password should succeed.
	result, _, err := svc.Login(ctx, &auth.LoginParams{
		Email:     "reset-flow@example.com",
		Password:  "brand-new-password-5678!",
		ProjectID: projectID,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, result.AccessToken)

	// Login with old password should fail.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "reset-flow@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestIntegration_PasswordReset_ExpiredToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "expired-reset@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.RequestReset(ctx, projectID, "expired-reset@example.com")
	require.NoError(t, err)

	// Replace with a known token and expire it.
	plainToken, err := crypto.GenerateToken(32)
	require.NoError(t, err)
	newHash := sha256Hash(plainToken)
	_, err = pool.Exec(ctx,
		"UPDATE verification_tokens SET token_hash = $1, expires_at = $2 WHERE type = 'password_reset' AND project_id = $3",
		newHash, time.Now().Add(-1*time.Hour), projectID)
	require.NoError(t, err)

	err = svc.ConfirmReset(ctx, projectID, plainToken, "brand-new-password-5678!")
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestIntegration_PasswordReset_UsedToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "used-token@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.RequestReset(ctx, projectID, "used-token@example.com")
	require.NoError(t, err)

	// Replace with a known token.
	plainToken, err := crypto.GenerateToken(32)
	require.NoError(t, err)
	newHash := sha256Hash(plainToken)
	_, err = pool.Exec(ctx,
		"UPDATE verification_tokens SET token_hash = $1 WHERE type = 'password_reset' AND project_id = $2",
		newHash, projectID)
	require.NoError(t, err)

	// First confirm succeeds.
	err = svc.ConfirmReset(ctx, projectID, plainToken, "brand-new-password-5678!")
	require.NoError(t, err)

	// Second confirm fails (token used).
	err = svc.ConfirmReset(ctx, projectID, plainToken, "yet-another-password-999!")
	assert.ErrorIs(t, err, auth.ErrTokenNotFound, "used token should not be found (used=true filtered)")
}

func TestIntegration_PasswordReset_PasswordHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup with password 1.
	_, err := svc.Signup(ctx, "history@example.com", "original-password-1234!", projectID)
	require.NoError(t, err)

	// Helper to request reset and get a usable token.
	getResetToken := func() string {
		err := svc.RequestReset(ctx, projectID, "history@example.com")
		require.NoError(t, err)
		pt, err := crypto.GenerateToken(32)
		require.NoError(t, err)
		h := sha256Hash(pt)
		_, err = pool.Exec(ctx,
			"UPDATE verification_tokens SET token_hash = $1 WHERE id = (SELECT id FROM verification_tokens WHERE type = 'password_reset' AND project_id = $2 AND used = false ORDER BY created_at DESC LIMIT 1)",
			h, projectID)
		require.NoError(t, err)
		return pt
	}

	// Try to reset to the original password — should fail (reuse).
	token1 := getResetToken()
	err = svc.ConfirmReset(ctx, projectID, token1, "original-password-1234!")
	assert.ErrorIs(t, err, crypto.ErrPasswordReused)

	// Reset to password 2.
	token2 := getResetToken()
	err = svc.ConfirmReset(ctx, projectID, token2, "second-password-56789!")
	require.NoError(t, err)

	// Reset to password 3.
	token3 := getResetToken()
	err = svc.ConfirmReset(ctx, projectID, token3, "third-password-abcdef!")
	require.NoError(t, err)

	// Reset to password 4.
	token4 := getResetToken()
	err = svc.ConfirmReset(ctx, projectID, token4, "fourth-password-ghijkl!")
	require.NoError(t, err)

	// Reset to password 5.
	token5 := getResetToken()
	err = svc.ConfirmReset(ctx, projectID, token5, "fifth-password-mnopqr!")
	require.NoError(t, err)

	// Now the original password should be allowed (only last 4 are checked).
	token6 := getResetToken()
	err = svc.ConfirmReset(ctx, projectID, token6, "original-password-1234!")
	require.NoError(t, err, "original password should be allowed after 4 other passwords")
}

func TestIntegration_PasswordReset_WeakPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "weakreset@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.RequestReset(ctx, projectID, "weakreset@example.com")
	require.NoError(t, err)

	plainToken, err := crypto.GenerateToken(32)
	require.NoError(t, err)
	newHash := sha256Hash(plainToken)
	_, err = pool.Exec(ctx,
		"UPDATE verification_tokens SET token_hash = $1 WHERE type = 'password_reset' AND project_id = $2 AND used = false",
		newHash, projectID)
	require.NoError(t, err)

	// Too short password.
	err = svc.ConfirmReset(ctx, projectID, plainToken, "short")
	assert.ErrorIs(t, err, crypto.ErrPasswordTooShort)
}

func TestIntegration_PasswordReset_BreachedPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "breachreset@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.RequestReset(ctx, projectID, "breachreset@example.com")
	require.NoError(t, err)

	plainToken, err := crypto.GenerateToken(32)
	require.NoError(t, err)
	newHash := sha256Hash(plainToken)
	_, err = pool.Exec(ctx,
		"UPDATE verification_tokens SET token_hash = $1 WHERE type = 'password_reset' AND project_id = $2 AND used = false",
		newHash, projectID)
	require.NoError(t, err)

	// Now create a new service with a breached HIBP server for the new password.
	breachedPw := "brand-new-password-5678!"
	hibpBreached := breachedHIBPServer(breachedPw)
	defer hibpBreached.Close()
	svcBreached := newTestAuthService(t, pool, hibpBreached)

	err = svcBreached.ConfirmReset(ctx, projectID, plainToken, breachedPw)
	assert.ErrorIs(t, err, crypto.ErrPasswordBreached)
}

func TestIntegration_PasswordReset_SessionsRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup creates a session.
	signupResult, err := svc.Signup(ctx, "sessions-reset@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Login creates another session.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "sessions-reset@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	// Verify we have active sessions.
	var activeCount int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM sessions WHERE user_id = $1 AND project_id = $2 AND revoked_at IS NULL",
		signupResult.User.ID, projectID).Scan(&activeCount)
	require.NoError(t, err)
	assert.True(t, activeCount >= 2, "should have at least 2 active sessions")

	// Request and confirm reset.
	err = svc.RequestReset(ctx, projectID, "sessions-reset@example.com")
	require.NoError(t, err)

	plainToken, err := crypto.GenerateToken(32)
	require.NoError(t, err)
	newHash := sha256Hash(plainToken)
	_, err = pool.Exec(ctx,
		"UPDATE verification_tokens SET token_hash = $1 WHERE type = 'password_reset' AND project_id = $2 AND used = false",
		newHash, projectID)
	require.NoError(t, err)

	err = svc.ConfirmReset(ctx, projectID, plainToken, "brand-new-password-5678!")
	require.NoError(t, err)

	// Verify all sessions are revoked.
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM sessions WHERE user_id = $1 AND project_id = $2 AND revoked_at IS NULL",
		signupResult.User.ID, projectID).Scan(&activeCount)
	require.NoError(t, err)
	assert.Equal(t, int64(0), activeCount, "all sessions should be revoked after password reset")
}

func TestIntegration_PasswordReset_NonExistingEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Request reset for non-existing email — should return nil (enumeration prevention).
	err := svc.RequestReset(ctx, projectID, "nobody-here@example.com")
	assert.NoError(t, err, "should return nil for non-existing email")
}

func TestIntegration_PasswordReset_AuditLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	_, err := svc.Signup(ctx, "auditreset@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.RequestReset(ctx, projectID, "auditreset@example.com")
	require.NoError(t, err)

	// Check audit log for reset request.
	var count int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE project_id = $1 AND event_type = $2",
		projectID, "auth.password.reset.request").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "should have password reset request audit event")
}

// ============================================================================
// Password Change Integration Tests
// ============================================================================

func TestIntegration_PasswordChange_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	signupResult, err := svc.Signup(ctx, "change@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.ChangePassword(ctx, projectID, signupResult.User.ID, "secure-password-1234!", "brand-new-password-5678!")
	require.NoError(t, err)

	// Login with new password should work.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "change@example.com",
		Password:  "brand-new-password-5678!",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	// Login with old password should fail.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "change@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestIntegration_PasswordChange_WrongCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	signupResult, err := svc.Signup(ctx, "wrongcurrent@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.ChangePassword(ctx, projectID, signupResult.User.ID, "wrong-current-12345!", "brand-new-password-5678!")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestIntegration_PasswordChange_PasswordHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	signupResult, err := svc.Signup(ctx, "changehistory@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Try to change to the same password — should fail.
	err = svc.ChangePassword(ctx, projectID, signupResult.User.ID, "secure-password-1234!", "secure-password-1234!")
	assert.ErrorIs(t, err, crypto.ErrPasswordReused)
}

func TestIntegration_PasswordChange_AuditLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	signupResult, err := svc.Signup(ctx, "auditchange@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.ChangePassword(ctx, projectID, signupResult.User.ID, "secure-password-1234!", "brand-new-password-5678!")
	require.NoError(t, err)

	// Check audit log.
	var count int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE project_id = $1 AND event_type = $2 AND result = 'success'",
		projectID, "auth.password.change").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestIntegration_PasswordChange_WeakNewPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	signupResult, err := svc.Signup(ctx, "weakchange@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.ChangePassword(ctx, projectID, signupResult.User.ID, "secure-password-1234!", "tooshort")
	assert.ErrorIs(t, err, crypto.ErrPasswordTooShort)
}

func TestIntegration_PasswordChange_SessionsRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup creates a session.
	signupResult, err := svc.Signup(ctx, "changesess@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	// Login creates another session.
	_, _, err = svc.Login(ctx, &auth.LoginParams{
		Email:     "changesess@example.com",
		Password:  "secure-password-1234!",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	// Verify we have active sessions.
	var activeCount int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM sessions WHERE user_id = $1 AND project_id = $2 AND revoked_at IS NULL",
		signupResult.User.ID, projectID).Scan(&activeCount)
	require.NoError(t, err)
	assert.True(t, activeCount >= 2, "should have at least 2 active sessions")

	// Change password.
	err = svc.ChangePassword(ctx, projectID, signupResult.User.ID, "secure-password-1234!", "brand-new-password-5678!")
	require.NoError(t, err)

	// Verify all sessions are revoked.
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM sessions WHERE user_id = $1 AND project_id = $2 AND revoked_at IS NULL",
		signupResult.User.ID, projectID).Scan(&activeCount)
	require.NoError(t, err)
	assert.Equal(t, int64(0), activeCount, "all sessions should be revoked after password change")
}

func TestIntegration_PasswordReset_FailedConfirm_AuditLogged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	hibp := notBreachedHIBPServer()
	defer hibp.Close()

	svc := newTestAuthService(t, pool, hibp)
	ctx := context.Background()
	projectID := createTestProject(t, pool, "code")

	// Signup and request reset so we have a real token with user context.
	_, err := svc.Signup(ctx, "auditfail@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	err = svc.RequestReset(ctx, projectID, "auditfail@example.com")
	require.NoError(t, err)

	// Replace the token hash and expire it so ConfirmReset fails with token_expired.
	plainToken, err := crypto.GenerateToken(32)
	require.NoError(t, err)
	newHash := sha256Hash(plainToken)
	_, err = pool.Exec(ctx,
		"UPDATE verification_tokens SET token_hash = $1, expires_at = $2 WHERE type = 'password_reset' AND project_id = $3 AND used = false",
		newHash, time.Now().Add(-1*time.Hour), projectID)
	require.NoError(t, err)

	// Try to confirm with expired token.
	err = svc.ConfirmReset(ctx, projectID, plainToken, "brand-new-password-5678!")
	assert.ErrorIs(t, err, auth.ErrTokenExpired)

	// Check that the failed attempt was audit-logged.
	var count int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM audit_logs WHERE project_id = $1 AND event_type = $2 AND result = 'failure'",
		projectID, "auth.password.reset.complete").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "failed reset confirm should be audit-logged")
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
