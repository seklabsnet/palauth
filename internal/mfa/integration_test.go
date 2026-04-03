package mfa_test

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
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/palauth/palauth/internal/admin"
	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/auth"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/email"
	"github.com/palauth/palauth/internal/mfa"
	"github.com/palauth/palauth/internal/project"
	"github.com/palauth/palauth/internal/session"
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

func setupTestRedis(t *testing.T) (rdb *redis.Client, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	redisContainer, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	connStr, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	opts, err := redis.ParseURL(connStr)
	require.NoError(t, err)

	rdb = redis.NewClient(opts)

	cleanup = func() {
		rdb.Close()
		_ = redisContainer.Terminate(ctx)
	}

	return rdb, cleanup
}

func notBreachedHIBPServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:0\r\n"))
	}))
}

type testEnv struct {
	pool       *pgxpool.Pool
	rdb        *redis.Client
	mfaSvc     *mfa.Service
	authSvc    *auth.Service
	sessionSvc *session.Service
	projectID  string
	userID     string
	cleanup    func()
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	pool, dbCleanup := setupTestDB(t)
	rdb, redisCleanup := setupTestRedis(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	auditKEKMac := hmac.New(sha256.New, []byte(testPepper))
	auditKEKMac.Write([]byte("audit-log-kek"))
	auditKEK := auditKEKMac.Sum(nil)
	auditSvc := audit.NewService(pool, auditKEK, logger)

	sessionSvc := session.NewService(pool, auditSvc, logger)

	emailSender := email.NewConsoleSender(logger)

	authKEKMac := hmac.New(sha256.New, []byte(testPepper))
	authKEKMac.Write([]byte("auth-email-kek"))
	authKEK := authKEKMac.Sum(nil)

	mfaSvc := mfa.NewService(pool, rdb, authKEK, testPepper, auditSvc, sessionSvc, emailSender, nil, logger)

	projectSvc := project.NewService(pool, logger)
	jwtSvc, err := token.NewJWTService(token.JWTConfig{
		Algorithm: token.AlgPS256,
		Logger:    logger,
	})
	require.NoError(t, err)
	refreshSvc := token.NewRefreshService(pool, jwtSvc, 0, logger)

	hibp := notBreachedHIBPServer()
	t.Cleanup(hibp.Close)
	bc := crypto.NewBreachCheckerWithURL(hibp.URL + "/range/")
	lockoutSvc := auth.NewLockoutService(rdb, logger)

	authSvc := auth.NewService(pool, projectSvc, jwtSvc, refreshSvc, auditSvc, bc, lockoutSvc, emailSender, nil, testPepper, authKEK, logger)
	authSvc.SetMFAChecker(mfaSvc)

	// Create test project.
	projectID := fmt.Sprintf("prj_test_%d", time.Now().UnixNano())
	cfg := project.DefaultConfig()
	configJSON, err := json.Marshal(cfg)
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(),
		"INSERT INTO projects (id, name, config) VALUES ($1, $2, $3)",
		projectID, "Test Project", configJSON)
	require.NoError(t, err)

	// Create test user via signup.
	result, err := authSvc.Signup(context.Background(), "test@example.com", "secure-password-1234!", projectID)
	require.NoError(t, err)

	return &testEnv{
		pool:       pool,
		rdb:        rdb,
		mfaSvc:     mfaSvc,
		authSvc:    authSvc,
		sessionSvc: sessionSvc,
		projectID:  projectID,
		userID:     result.User.ID,
		cleanup: func() {
			dbCleanup()
			redisCleanup()
		},
	}
}

// --- TOTP Tests ---

func TestIntegration_TOTPEnrollAndVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll TOTP.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, enrollment.EnrollmentID)
	assert.NotEmpty(t, enrollment.Secret)
	assert.NotEmpty(t, enrollment.OTPURL)
	assert.NotEmpty(t, enrollment.QRCode)
	assert.Contains(t, enrollment.OTPURL, "otpauth://totp/")
	assert.Contains(t, enrollment.OTPURL, "PalAuth")

	// Generate a valid TOTP code.
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)

	// Verify enrollment.
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, code)
	require.NoError(t, err)

	// Verify user has_mfa is true.
	var hasMFA bool
	err = env.pool.QueryRow(ctx, "SELECT has_mfa FROM users WHERE id = $1 AND project_id = $2",
		env.userID, env.projectID).Scan(&hasMFA)
	require.NoError(t, err)
	assert.True(t, hasMFA)
}

func TestIntegration_TOTPWrongCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll TOTP.
	_, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)

	// Try wrong code.
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, "000000")
	assert.ErrorIs(t, err, mfa.ErrInvalidCode)
}

func TestIntegration_TOTPAlreadyVerified(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll and verify TOTP.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, code)
	require.NoError(t, err)

	// Try to enroll again.
	_, err = env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	assert.ErrorIs(t, err, mfa.ErrMFAAlreadyVerified)
}

func TestIntegration_TOTPChallengeSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll and verify TOTP.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, code)
	require.NoError(t, err)

	// Wait a bit so we get a new TOTP code for the challenge.
	time.Sleep(1 * time.Second)

	// Generate code for challenge.
	challengeCode, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)

	// Validate challenge.
	err = env.mfaSvc.ValidateTOTPChallenge(ctx, env.projectID, env.userID, challengeCode)
	require.NoError(t, err)
}

func TestIntegration_TOTPChallengeReplayProtection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll and verify TOTP.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, code)
	require.NoError(t, err)

	// Wait for new code period.
	time.Sleep(1 * time.Second)

	// Generate and use a code.
	challengeCode, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)

	err = env.mfaSvc.ValidateTOTPChallenge(ctx, env.projectID, env.userID, challengeCode)
	require.NoError(t, err)

	// Try to use the same code again — should be rejected.
	err = env.mfaSvc.ValidateTOTPChallenge(ctx, env.projectID, env.userID, challengeCode)
	assert.ErrorIs(t, err, mfa.ErrReplayDetected)
}

func TestIntegration_TOTPChallengeLockout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll and verify TOTP.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, code)
	require.NoError(t, err)

	// 5 failed attempts → lockout.
	for i := 0; i < 5; i++ {
		err = env.mfaSvc.ValidateTOTPChallenge(ctx, env.projectID, env.userID, "000000")
		assert.ErrorIs(t, err, mfa.ErrInvalidCode)
	}

	// 6th attempt should be locked out.
	err = env.mfaSvc.ValidateTOTPChallenge(ctx, env.projectID, env.userID, "000000")
	assert.ErrorIs(t, err, mfa.ErrMFALockout)
}

// --- MFA Token Tests ---

func TestIntegration_MFATokenIssueValidateConsume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Issue token.
	mfaToken, err := env.mfaSvc.IssueMFAToken(ctx, &mfa.TokenData{
		UserID:    env.userID,
		ProjectID: env.projectID,
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, mfaToken)
	// 32 bytes = 64 hex chars.
	assert.Len(t, mfaToken, 64)

	// Validate token.
	data, err := env.mfaSvc.ValidateMFAToken(ctx, mfaToken)
	require.NoError(t, err)
	assert.Equal(t, env.userID, data.UserID)
	assert.Equal(t, env.projectID, data.ProjectID)
	assert.Equal(t, "127.0.0.1", data.IP)
	assert.Equal(t, "test-agent", data.UserAgent)

	// Consume token.
	data, err = env.mfaSvc.ConsumeMFAToken(ctx, mfaToken)
	require.NoError(t, err)
	assert.Equal(t, env.userID, data.UserID)

	// Token should be gone after consumption.
	_, err = env.mfaSvc.ValidateMFAToken(ctx, mfaToken)
	assert.ErrorIs(t, err, mfa.ErrMFATokenInvalid)
}

func TestIntegration_MFATokenInvalid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	_, err := env.mfaSvc.ValidateMFAToken(ctx, "nonexistent-token")
	assert.ErrorIs(t, err, mfa.ErrMFATokenInvalid)
}

// --- Recovery Code Tests ---

func TestIntegration_RecoveryCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Generate codes.
	codes, err := env.mfaSvc.GenerateRecoveryCodes(ctx, env.projectID, env.userID)
	require.NoError(t, err)
	assert.Len(t, codes, 10)

	// All codes should be unique.
	seen := make(map[string]bool)
	for _, c := range codes {
		assert.False(t, seen[c], "duplicate recovery code")
		seen[c] = true
		assert.Len(t, c, 8) // 5 bytes = 8 base32 chars
	}
}

func TestIntegration_UseRecoveryCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll TOTP first so has_mfa is set.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, code)
	require.NoError(t, err)

	// Generate recovery codes.
	codes, err := env.mfaSvc.GenerateRecoveryCodes(ctx, env.projectID, env.userID)
	require.NoError(t, err)

	// Use first code.
	err = env.mfaSvc.UseRecoveryCode(ctx, env.projectID, env.userID, codes[0])
	require.NoError(t, err)

	// Verify has_mfa is false after recovery code use.
	var hasMFA bool
	err = env.pool.QueryRow(ctx, "SELECT has_mfa FROM users WHERE id = $1 AND project_id = $2",
		env.userID, env.projectID).Scan(&hasMFA)
	require.NoError(t, err)
	assert.False(t, hasMFA, "has_mfa should be false after recovery code use")

	// Same code should not work again.
	err = env.mfaSvc.UseRecoveryCode(ctx, env.projectID, env.userID, codes[0])
	// After recovery, all enrollments are deleted so codes are deleted too.
	assert.Error(t, err)
}

func TestIntegration_RecoveryCodeWrongCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Generate codes.
	_, err := env.mfaSvc.GenerateRecoveryCodes(ctx, env.projectID, env.userID)
	require.NoError(t, err)

	// Try wrong code.
	err = env.mfaSvc.UseRecoveryCode(ctx, env.projectID, env.userID, "wrongcod")
	assert.ErrorIs(t, err, mfa.ErrInvalidCode)
}

func TestIntegration_RegenerateRecoveryCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Generate codes.
	oldCodes, err := env.mfaSvc.GenerateRecoveryCodes(ctx, env.projectID, env.userID)
	require.NoError(t, err)

	// Regenerate codes.
	newCodes, err := env.mfaSvc.RegenerateRecoveryCodes(ctx, env.projectID, env.userID)
	require.NoError(t, err)
	assert.Len(t, newCodes, 10)

	// Old codes should not match new codes.
	for _, oldCode := range oldCodes {
		for _, newCode := range newCodes {
			assert.NotEqual(t, oldCode, newCode, "regenerated codes should be different")
		}
	}
}

// --- Login MFA Flow ---

func TestIntegration_LoginWithMFA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll and verify TOTP.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, code)
	require.NoError(t, err)

	// Login should require MFA.
	ip := "127.0.0.1"
	ua := "test-agent"
	_, _, err = env.authSvc.Login(ctx, &auth.LoginParams{
		Email:     "test@example.com",
		Password:  "secure-password-1234!",
		ProjectID: env.projectID,
		IP:        &ip,
		UserAgent: &ua,
	})

	// Should get MFARequiredError.
	var mfaErr *auth.MFARequiredError
	require.ErrorAs(t, err, &mfaErr)
	assert.NotEmpty(t, mfaErr.MFAToken)
	assert.Contains(t, mfaErr.Factors, "totp")
}

// --- Email OTP Tests ---

func TestIntegration_EmailOTPEnroll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// First verify the user's email.
	_, err := env.pool.Exec(ctx, "UPDATE users SET email_verified = true WHERE id = $1 AND project_id = $2",
		env.userID, env.projectID)
	require.NoError(t, err)

	// Enroll email OTP.
	err = env.mfaSvc.EnrollEmail(ctx, env.projectID, env.userID)
	require.NoError(t, err)

	// Verify has_mfa is true.
	var hasMFA bool
	err = env.pool.QueryRow(ctx, "SELECT has_mfa FROM users WHERE id = $1 AND project_id = $2",
		env.userID, env.projectID).Scan(&hasMFA)
	require.NoError(t, err)
	assert.True(t, hasMFA)
}

func TestIntegration_EmailOTPEnrollRequiresVerifiedEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Try to enroll without verified email.
	err := env.mfaSvc.EnrollEmail(ctx, env.projectID, env.userID)
	assert.ErrorIs(t, err, mfa.ErrEmailNotVerified)
}

// --- Factor List & Remove ---

func TestIntegration_ListAndRemoveFactors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Enroll and verify TOTP.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, env.projectID, env.userID, "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, env.projectID, env.userID, code)
	require.NoError(t, err)

	// List factors.
	factors, err := env.mfaSvc.ListFactors(ctx, env.projectID, env.userID)
	require.NoError(t, err)
	assert.Len(t, factors, 1)
	assert.Equal(t, "totp", factors[0].Type)
	assert.True(t, factors[0].Verified)

	// Remove factor.
	err = env.mfaSvc.RemoveFactor(ctx, env.projectID, env.userID, factors[0].ID)
	require.NoError(t, err)

	// Verify has_mfa is false after removing all factors.
	var hasMFA bool
	err = env.pool.QueryRow(ctx, "SELECT has_mfa FROM users WHERE id = $1 AND project_id = $2",
		env.userID, env.projectID).Scan(&hasMFA)
	require.NoError(t, err)
	assert.False(t, hasMFA)
}

// --- Admin MFA Enforcement ---

func TestIntegration_AdminMFAEnforcement_NotEnrolled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create an admin user.
	adminPassword := "admin-secure-password-123!"
	adminHash, err := crypto.Hash(adminPassword, testPepper)
	require.NoError(t, err)

	adminID := "adm_test_mfa_1"
	_, err = env.pool.Exec(ctx,
		"INSERT INTO admin_users (id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
		adminID, "admin@example.com", adminHash, "owner")
	require.NoError(t, err)

	// Create admin service with MFA checker.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	adminSvc := admin.NewService(env.pool, testPepper, []byte("admin-signing-key-at-least-32-bytes!"), nil, logger)
	adminSvc.SetMFAChecker(env.mfaSvc)

	// Admin login should return MFA required with MFAEnrolled=false.
	_, err = adminSvc.Login(ctx, "admin@example.com", adminPassword, "127.0.0.1", "test-agent")
	var mfaErr *admin.MFARequiredError
	require.ErrorAs(t, err, &mfaErr)
	assert.False(t, mfaErr.MFAEnrolled, "admin should not have MFA enrolled yet")
	assert.NotEmpty(t, mfaErr.MFAToken)
	assert.Equal(t, adminID, mfaErr.AdminID)
}

func TestIntegration_AdminMFAEnforcement_Enrolled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create an admin user with has_mfa=true.
	adminPassword := "admin-secure-password-123!"
	adminHash, err := crypto.Hash(adminPassword, testPepper)
	require.NoError(t, err)

	adminID := "adm_test_mfa_2"
	_, err = env.pool.Exec(ctx,
		"INSERT INTO admin_users (id, email, password_hash, role, has_mfa) VALUES ($1, $2, $3, $4, $5)",
		adminID, "admin2@example.com", adminHash, "owner", true)
	require.NoError(t, err)

	// Enroll TOTP for the admin in __admin__ project scope.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, admin.AdminProjectID, adminID, "admin2@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, admin.AdminProjectID, adminID, code)
	require.NoError(t, err)

	// Admin login should return MFA required with MFAEnrolled=true.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	adminSvc := admin.NewService(env.pool, testPepper, []byte("admin-signing-key-at-least-32-bytes!"), nil, logger)
	adminSvc.SetMFAChecker(env.mfaSvc)

	_, err = adminSvc.Login(ctx, "admin2@example.com", adminPassword, "127.0.0.1", "test-agent")
	var mfaErr *admin.MFARequiredError
	require.ErrorAs(t, err, &mfaErr)
	assert.True(t, mfaErr.MFAEnrolled, "admin should have MFA enrolled")
	assert.NotEmpty(t, mfaErr.MFAToken)
}

func TestIntegration_AdminMFAEnforcement_JWTAfterMFA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create an admin user with has_mfa=true.
	adminPassword := "admin-secure-password-123!"
	adminHash, err := crypto.Hash(adminPassword, testPepper)
	require.NoError(t, err)

	adminID := "adm_test_mfa_3"
	_, err = env.pool.Exec(ctx,
		"INSERT INTO admin_users (id, email, password_hash, role, has_mfa) VALUES ($1, $2, $3, $4, $5)",
		adminID, "admin3@example.com", adminHash, "owner", true)
	require.NoError(t, err)

	// Enroll TOTP.
	enrollment, err := env.mfaSvc.EnrollTOTP(ctx, admin.AdminProjectID, adminID, "admin3@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.VerifyTOTPEnrollment(ctx, admin.AdminProjectID, adminID, code)
	require.NoError(t, err)

	// Login should require MFA — no JWT returned.
	signingKey := []byte("admin-signing-key-at-least-32-bytes!")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	adminSvc := admin.NewService(env.pool, testPepper, signingKey, nil, logger)
	adminSvc.SetMFAChecker(env.mfaSvc)

	_, err = adminSvc.Login(ctx, "admin3@example.com", adminPassword, "127.0.0.1", "test-agent")
	var mfaErr *admin.MFARequiredError
	require.ErrorAs(t, err, &mfaErr)

	// Validate MFA token.
	tokenData, err := env.mfaSvc.ValidateMFAToken(ctx, mfaErr.MFAToken)
	require.NoError(t, err)
	assert.Equal(t, adminID, tokenData.UserID)
	assert.Equal(t, admin.AdminProjectID, tokenData.ProjectID)

	// Complete MFA challenge.
	code2, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = env.mfaSvc.ValidateTOTPChallenge(ctx, admin.AdminProjectID, adminID, code2)
	require.NoError(t, err)

	// Now issue admin JWT (simulating what the handler does).
	adminToken, err := adminSvc.IssueTokenAfterMFA(ctx, adminID)
	require.NoError(t, err)
	assert.NotEmpty(t, adminToken, "admin JWT should be issued after MFA completion")

	// Validate the admin JWT.
	claims, err := adminSvc.ValidateToken(adminToken)
	require.NoError(t, err)
	assert.Equal(t, adminID, claims.Sub)
	assert.Equal(t, "owner", claims.Role)
}

func TestIntegration_AdminMFAEnforcement_NoMFAChecker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx := context.Background()

	// Create an admin user.
	adminPassword := "admin-secure-password-123!"
	adminHash, err := crypto.Hash(adminPassword, testPepper)
	require.NoError(t, err)

	adminID := "adm_test_mfa_4"
	_, err = env.pool.Exec(ctx,
		"INSERT INTO admin_users (id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
		adminID, "admin4@example.com", adminHash, "owner")
	require.NoError(t, err)

	// Create admin service WITHOUT MFA checker (no Redis = no MFA).
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	adminSvc := admin.NewService(env.pool, testPepper, []byte("admin-signing-key-at-least-32-bytes!"), nil, logger)
	// Not calling SetMFAChecker — mfaChecker is nil.

	// Admin login should succeed directly (no MFA enforcement).
	adminToken, err := adminSvc.Login(ctx, "admin4@example.com", adminPassword, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	assert.NotEmpty(t, adminToken, "admin JWT should be issued without MFA when checker is nil")
}

// --- Helpers ---

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

		sql := string(sqlBytes)
		// Strip goose directives.
		sql = strings.ReplaceAll(sql, "-- +goose Up", "")
		sql = strings.ReplaceAll(sql, "-- +goose Down", "")

		_, err = pool.Exec(context.Background(), sql)
		require.NoError(t, err, "running migration %s", f)
	}
}
