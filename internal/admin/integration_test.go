package admin_test

import (
	"context"
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

	"github.com/palauth/palauth/internal/admin"
	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/session"
)

const testPepper = "test-pepper-at-least-32-bytes!!!"

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

func newTestHIBPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return empty response — no breached passwords.
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "")
	}))
}

func newTestServices(t *testing.T, pool *pgxpool.Pool) (*admin.UserService, *audit.Service) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	kek := testKEK()

	auditSvc := audit.NewService(pool, kek, logger)
	sessionSvc := session.NewService(pool, auditSvc, logger)

	hibpServer := newTestHIBPServer(t)
	t.Cleanup(hibpServer.Close)
	breachChecker := crypto.NewBreachCheckerWithURL(hibpServer.URL + "/")

	userSvc := admin.NewUserService(pool, auditSvc, sessionSvc, breachChecker, nil, nil, testPepper, kek, logger)

	return userSvc, auditSvc
}

func createTestProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	projectID := fmt.Sprintf("prj_test_%d", time.Now().UnixNano())
	_, err := pool.Exec(context.Background(),
		"INSERT INTO projects (id, name, config) VALUES ($1, $2, '{}')",
		projectID, "Test Project")
	require.NoError(t, err)
	return projectID
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

func TestIntegration_CreateUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	// Create user with password.
	user, err := userSvc.CreateUser(ctx, projectID, "alice@example.com", "super-secure-password-123!", json.RawMessage(`{"role":"user"}`), "adm_1")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, projectID, user.ProjectID)
	assert.False(t, user.Banned)
	assert.False(t, user.EmailVerified)
	var meta map[string]string
	err = json.Unmarshal(user.Metadata, &meta)
	require.NoError(t, err)
	assert.Equal(t, "user", meta["role"])
}

func TestIntegration_CreateUser_DuplicateEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	_, err := userSvc.CreateUser(ctx, projectID, "alice@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	_, err = userSvc.CreateUser(ctx, projectID, "alice@example.com", "another-secure-password-456!", nil, "adm_1")
	assert.ErrorIs(t, err, admin.ErrDuplicateEmail)
}

func TestIntegration_CreateUser_WeakPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	// 14 char password — too short (min 15).
	_, err := userSvc.CreateUser(ctx, projectID, "user@example.com", "14charpasswrd!", nil, "adm_1")
	assert.ErrorIs(t, err, crypto.ErrPasswordTooShort)
}

func TestIntegration_GetUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	created, err := userSvc.CreateUser(ctx, projectID, "bob@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	got, err := userSvc.GetUser(ctx, projectID, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "bob@example.com", got.Email)
}

func TestIntegration_GetUser_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	_, err := userSvc.GetUser(ctx, projectID, "usr_nonexistent")
	assert.ErrorIs(t, err, admin.ErrUserNotFound)
}

func TestIntegration_ListUsers_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	// Create 5 users.
	for i := 0; i < 5; i++ {
		email := fmt.Sprintf("user%d@example.com", i)
		_, err := userSvc.CreateUser(ctx, projectID, email, "super-secure-password-123!", nil, "adm_1")
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // ensure different created_at
	}

	// First page (limit 2).
	result, err := userSvc.ListUsers(ctx, projectID, admin.UserListOptions{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, result.Users, 2)
	assert.Equal(t, int64(5), result.Total)
	assert.NotNil(t, result.NextCursor)

	// Second page.
	result2, err := userSvc.ListUsers(ctx, projectID, admin.UserListOptions{
		Limit:  2,
		Cursor: result.NextCursor,
	})
	require.NoError(t, err)
	assert.Len(t, result2.Users, 2)
	assert.NotNil(t, result2.NextCursor)

	// No overlap between pages.
	assert.NotEqual(t, result.Users[0].ID, result2.Users[0].ID)
	assert.NotEqual(t, result.Users[1].ID, result2.Users[1].ID)
}

func TestIntegration_ListUsers_BannedFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	u1, err := userSvc.CreateUser(ctx, projectID, "good@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)
	_, err = userSvc.CreateUser(ctx, projectID, "bad@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	// Ban one user.
	err = userSvc.BanUser(ctx, projectID, u1.ID, "test reason", "adm_1")
	require.NoError(t, err)

	// Filter banned=true.
	banned := true
	result, err := userSvc.ListUsers(ctx, projectID, admin.UserListOptions{Banned: &banned})
	require.NoError(t, err)
	assert.Len(t, result.Users, 1)
	assert.True(t, result.Users[0].Banned)

	// Filter banned=false.
	notBanned := false
	result2, err := userSvc.ListUsers(ctx, projectID, admin.UserListOptions{Banned: &notBanned})
	require.NoError(t, err)
	assert.Len(t, result2.Users, 1)
	assert.False(t, result2.Users[0].Banned)
}

func TestIntegration_ListUsers_EmailSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	_, err := userSvc.CreateUser(ctx, projectID, "alice@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)
	_, err = userSvc.CreateUser(ctx, projectID, "bob@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	// Search for alice.
	result, err := userSvc.ListUsers(ctx, projectID, admin.UserListOptions{EmailQuery: "alice@example.com"})
	require.NoError(t, err)
	assert.Len(t, result.Users, 1)
	assert.Equal(t, "alice@example.com", result.Users[0].Email)
}

func TestIntegration_UpdateUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	created, err := userSvc.CreateUser(ctx, projectID, "user@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)
	assert.False(t, created.EmailVerified)

	verified := true
	meta := json.RawMessage(`{"tier":"premium"}`)
	updated, err := userSvc.UpdateUser(ctx, projectID, created.ID, admin.UpdateUserParams{
		EmailVerified: &verified,
		Metadata:      &meta,
	}, "adm_1")
	require.NoError(t, err)
	assert.True(t, updated.EmailVerified)
	var updatedMeta map[string]string
	err = json.Unmarshal(updated.Metadata, &updatedMeta)
	require.NoError(t, err)
	assert.Equal(t, "premium", updatedMeta["tier"])
}

func TestIntegration_BanUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	created, err := userSvc.CreateUser(ctx, projectID, "user@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	// Ban user.
	err = userSvc.BanUser(ctx, projectID, created.ID, "policy violation", "adm_1")
	require.NoError(t, err)

	// Verify banned.
	got, err := userSvc.GetUser(ctx, projectID, created.ID)
	require.NoError(t, err)
	assert.True(t, got.Banned)
	assert.Equal(t, "policy violation", got.BanReason)

	// Double-ban should fail.
	err = userSvc.BanUser(ctx, projectID, created.ID, "another reason", "adm_1")
	assert.ErrorIs(t, err, admin.ErrUserAlreadyBanned)
}

func TestIntegration_UnbanUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	created, err := userSvc.CreateUser(ctx, projectID, "user@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	err = userSvc.BanUser(ctx, projectID, created.ID, "policy violation", "adm_1")
	require.NoError(t, err)

	err = userSvc.UnbanUser(ctx, projectID, created.ID, "adm_1")
	require.NoError(t, err)

	got, err := userSvc.GetUser(ctx, projectID, created.ID)
	require.NoError(t, err)
	assert.False(t, got.Banned)
	assert.Empty(t, got.BanReason)

	// Double-unban should fail.
	err = userSvc.UnbanUser(ctx, projectID, created.ID, "adm_1")
	assert.ErrorIs(t, err, admin.ErrUserNotBanned)
}

func TestIntegration_DeleteUser_GDPRErasure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, auditSvc := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	// Create "system" user record needed by audit.Erase for the gdpr.erasure event actor DEK.
	_, err := pool.Exec(ctx,
		"INSERT INTO users (id, project_id, email_encrypted, email_hash, metadata) VALUES ($1, $2, $3, $4, '{}') ON CONFLICT DO NOTHING",
		"system", projectID, []byte("enc"), []byte("hash"))
	require.NoError(t, err)

	// Create user + some audit events.
	created, err := userSvc.CreateUser(ctx, projectID, "gdpr-user@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	// Delete user (GDPR erasure).
	err = userSvc.DeleteUser(ctx, projectID, created.ID, "adm_1")
	require.NoError(t, err)

	// User should no longer exist.
	_, err = userSvc.GetUser(ctx, projectID, created.ID)
	assert.ErrorIs(t, err, admin.ErrUserNotFound)

	// Audit log chain should still be valid.
	report, err := auditSvc.Verify(ctx, projectID)
	require.NoError(t, err)
	assert.True(t, report.Valid, "audit log chain should be valid after GDPR erasure")

	// gdpr.erasure event should exist.
	listResult, err := auditSvc.List(ctx, projectID, audit.ListOptions{EventType: "gdpr.erasure"})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(listResult.Events), 1)
}

func TestIntegration_DeleteUser_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	err := userSvc.DeleteUser(ctx, projectID, "usr_nonexistent", "adm_1")
	assert.ErrorIs(t, err, admin.ErrUserNotFound)
}

func TestIntegration_ResetUserPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	created, err := userSvc.CreateUser(ctx, projectID, "user@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	err = userSvc.ResetUserPassword(ctx, projectID, created.ID, "adm_1")
	require.NoError(t, err)

	// Verify reset token was created.
	q := sqlc.New(pool)
	var count int64
	err = pool.QueryRow(ctx,
		"SELECT count(*) FROM verification_tokens WHERE user_id = $1 AND type = 'password_reset'",
		created.ID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "password reset token should be created")

	// Verify all sessions revoked (there are no sessions for this user, so count should be 0).
	sessionCount, err := q.CountActiveSessionsByUser(ctx, sqlc.CountActiveSessionsByUserParams{
		UserID:    created.ID,
		ProjectID: projectID,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), sessionCount)
}

func TestIntegration_DeactivateInactiveUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	// Create user with old last_login_at.
	created, err := userSvc.CreateUser(ctx, projectID, "inactive@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	// Set last_login_at to 100 days ago.
	_, err = pool.Exec(ctx,
		"UPDATE users SET last_login_at = now() - interval '100 days' WHERE id = $1",
		created.ID)
	require.NoError(t, err)

	count, err := userSvc.DeactivateInactiveUsers(ctx, 90)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify user is banned with reason.
	got, err := userSvc.GetUser(ctx, projectID, created.ID)
	require.NoError(t, err)
	assert.True(t, got.Banned)
	assert.Equal(t, "inactive_90d", got.BanReason)
}

func TestIntegration_Analytics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	// Create users.
	_, err := userSvc.CreateUser(ctx, projectID, "active@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)
	created2, err := userSvc.CreateUser(ctx, projectID, "recent@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	// Set one user's last_login_at to recent.
	_, err = pool.Exec(ctx, "UPDATE users SET last_login_at = now() WHERE id = $1", created2.ID)
	require.NoError(t, err)

	analytics, err := userSvc.GetProjectAnalytics(ctx, projectID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), analytics.TotalUsers)
	assert.Equal(t, int64(1), analytics.MAU) // only the user with recent last_login
	assert.Equal(t, int64(0), analytics.ActiveSessions)
	assert.Equal(t, int64(0), analytics.LoginTrend24h) // no login audit events in this test
}

func TestIntegration_BanUser_RequiresReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, _ := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	created, err := userSvc.CreateUser(ctx, projectID, "user@example.com", "super-secure-password-123!", nil, "adm_1")
	require.NoError(t, err)

	err = userSvc.BanUser(ctx, projectID, created.ID, "", "adm_1")
	assert.ErrorIs(t, err, admin.ErrBanReasonRequired)
}

func TestIntegration_AuditLogAfterOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	userSvc, auditSvc := newTestServices(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	// Create a fake admin user record so audit log actor DEK can be created.
	adminID := "adm_test_audit"
	_, err := pool.Exec(ctx,
		"INSERT INTO users (id, project_id, email_encrypted, email_hash, metadata) VALUES ($1, $2, $3, $4, '{}') ON CONFLICT DO NOTHING",
		adminID, projectID, []byte("enc"), []byte("hash"))
	require.NoError(t, err)

	// Create user — audit event.
	created, err := userSvc.CreateUser(ctx, projectID, "audit-test@example.com", "super-secure-password-123!", nil, adminID)
	require.NoError(t, err)

	// Ban — audit event.
	err = userSvc.BanUser(ctx, projectID, created.ID, "test ban", adminID)
	require.NoError(t, err)

	// Unban — audit event.
	err = userSvc.UnbanUser(ctx, projectID, created.ID, adminID)
	require.NoError(t, err)

	// Update — audit event.
	verified := true
	_, err = userSvc.UpdateUser(ctx, projectID, created.ID, admin.UpdateUserParams{EmailVerified: &verified}, adminID)
	require.NoError(t, err)

	// All operations should have produced audit logs.
	result, err := auditSvc.List(ctx, projectID, audit.ListOptions{Limit: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Events), 4, "at least 4 audit events expected")

	// Chain should be valid.
	report, err := auditSvc.Verify(ctx, projectID)
	require.NoError(t, err)
	assert.True(t, report.Valid)
}
