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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
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

	return auth.NewService(pool, projectSvc, jwtSvc, refreshSvc, auditSvc, bc, testPepper, testKEK(), logger)
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
