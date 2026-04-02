package session_test

import (
	"context"
	"log/slog"
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
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/session"
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

	cleanup = func() {
		pool.Close()
		_ = pgContainer.Terminate(ctx)
	}

	return pool, cleanup
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

func testKEK() []byte {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	return kek
}

func setupService(t *testing.T, pool *pgxpool.Pool) *session.Service {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	auditSvc := audit.NewService(pool, testKEK(), logger)
	return session.NewService(pool, auditSvc, logger)
}

func createTestProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	projectID := id.New("prj_")
	q := sqlc.New(pool)
	_, err := q.CreateProject(context.Background(), sqlc.CreateProjectParams{
		ID:     projectID,
		Name:   "test-project",
		Config: []byte(`{}`),
	})
	require.NoError(t, err)
	return projectID
}

func createTestUser(t *testing.T, pool *pgxpool.Pool, userID, projectID string) {
	t.Helper()
	q := sqlc.New(pool)
	pw := "dummy-hash"
	_, err := q.CreateUser(context.Background(), sqlc.CreateUserParams{
		ID:             userID,
		ProjectID:      projectID,
		EmailEncrypted: []byte("encrypted"),
		EmailHash:      []byte("hash"),
		PasswordHash:   &pw,
		Metadata:       []byte(`{}`),
	})
	require.NoError(t, err)
}

func TestIntegration_CreateSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := setupService(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	t.Run("creates AAL1 session", func(t *testing.T) {
		createTestUser(t, pool, "usr_test-1", projectID)
		sess, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_test-1",
			IP:        "192.168.1.1",
			UserAgent: "TestBrowser/1.0",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)
		require.NotNil(t, sess)

		assert.True(t, strings.HasPrefix(sess.ID, "sess_"))
		assert.Equal(t, projectID, sess.ProjectID)
		assert.Equal(t, "usr_test-1", sess.UserID)
		assert.Equal(t, "192.168.1.1", sess.IP)
		assert.Equal(t, "TestBrowser/1.0", sess.UserAgent)
		assert.Equal(t, "aal1", sess.ACR)
		assert.Equal(t, []string{"pwd"}, sess.AMR)
		assert.Nil(t, sess.IdleTimeoutAt, "AAL1 should have no idle timeout")

		// Absolute timeout should be ~30 days from now.
		expectedAbs := time.Now().Add(30 * 24 * time.Hour)
		assert.WithinDuration(t, expectedAbs, sess.AbsTimeoutAt, 5*time.Second)
	})

	t.Run("creates AAL2 session", func(t *testing.T) {
		createTestUser(t, pool, "usr_test-2", projectID)
		sess, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_test-2",
			IP:        "10.0.0.1",
			UserAgent: "TestBrowser/2.0",
			ACR:       "aal2",
			AMR:       []string{"pwd", "otp"},
		})
		require.NoError(t, err)
		require.NotNil(t, sess)

		assert.Equal(t, "aal2", sess.ACR)
		assert.Equal(t, []string{"pwd", "otp"}, sess.AMR)
		require.NotNil(t, sess.IdleTimeoutAt, "AAL2 should have idle timeout")

		// Idle timeout ~1 hour.
		expectedIdle := time.Now().Add(1 * time.Hour)
		assert.WithinDuration(t, expectedIdle, *sess.IdleTimeoutAt, 5*time.Second)

		// Absolute timeout ~24 hours.
		expectedAbs := time.Now().Add(24 * time.Hour)
		assert.WithinDuration(t, expectedAbs, sess.AbsTimeoutAt, 5*time.Second)
	})

	t.Run("creates AAL3 session", func(t *testing.T) {
		createTestUser(t, pool, "usr_test-3", projectID)
		sess, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_test-3",
			IP:        "10.0.0.2",
			UserAgent: "TestBrowser/3.0",
			ACR:       "aal3",
			AMR:       []string{"pwd", "hwk"},
		})
		require.NoError(t, err)
		require.NotNil(t, sess)

		assert.Equal(t, "aal3", sess.ACR)
		require.NotNil(t, sess.IdleTimeoutAt, "AAL3 should have idle timeout")

		// Idle timeout ~15 minutes.
		expectedIdle := time.Now().Add(15 * time.Minute)
		assert.WithinDuration(t, expectedIdle, *sess.IdleTimeoutAt, 5*time.Second)

		// Absolute timeout ~12 hours.
		expectedAbs := time.Now().Add(12 * time.Hour)
		assert.WithinDuration(t, expectedAbs, sess.AbsTimeoutAt, 5*time.Second)
	})
}

func TestIntegration_GetSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := setupService(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	t.Run("get returns valid session", func(t *testing.T) {
		createTestUser(t, pool, "usr_get-1", projectID)
		created, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_get-1",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		got, err := svc.Get(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, got.ID)
		assert.Equal(t, "usr_get-1", got.UserID)
	})

	t.Run("get returns not found for nonexistent session", func(t *testing.T) {
		_, err := svc.Get(ctx, "sess_nonexistent")
		assert.ErrorIs(t, err, session.ErrSessionNotFound)
	})
}

func TestIntegration_TouchSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := setupService(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	t.Run("touch resets idle timeout", func(t *testing.T) {
		createTestUser(t, pool, "usr_touch-1", projectID)
		sess, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_touch-1",
			ACR:       "aal2",
			AMR:       []string{"pwd", "otp"},
		})
		require.NoError(t, err)
		require.NotNil(t, sess.IdleTimeoutAt)

		originalIdle := *sess.IdleTimeoutAt

		// Sleep briefly to ensure time difference.
		time.Sleep(10 * time.Millisecond)

		err = svc.Touch(ctx, sess)
		require.NoError(t, err)

		// Re-fetch and verify idle timeout was updated.
		updated, err := svc.Get(ctx, sess.ID)
		require.NoError(t, err)
		require.NotNil(t, updated.IdleTimeoutAt)
		assert.True(t, updated.IdleTimeoutAt.After(originalIdle),
			"idle timeout should be reset to later time: original=%v updated=%v", originalIdle, *updated.IdleTimeoutAt)
	})
}

func TestIntegration_RevokeSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := setupService(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	t.Run("revoke single session", func(t *testing.T) {
		createTestUser(t, pool, "usr_revoke-1", projectID)
		sess, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_revoke-1",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		err = svc.Revoke(ctx, sess.ID, projectID, "usr_revoke-1")
		require.NoError(t, err)

		// Get should return not found (revoked sessions are filtered).
		_, err = svc.Get(ctx, sess.ID)
		assert.ErrorIs(t, err, session.ErrSessionNotFound)
	})

	t.Run("revoke nonexistent session returns not found", func(t *testing.T) {
		err := svc.Revoke(ctx, "sess_nonexistent", projectID, "usr_nobody")
		assert.ErrorIs(t, err, session.ErrSessionNotFound)
	})

	t.Run("revoke session from wrong project returns not found", func(t *testing.T) {
		createTestUser(t, pool, "usr_revoke-2", projectID)
		sess, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_revoke-2",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		err = svc.Revoke(ctx, sess.ID, "prj_wrong-project", "usr_revoke-2")
		assert.ErrorIs(t, err, session.ErrSessionNotFound)

		// Session should still be valid.
		got, err := svc.Get(ctx, sess.ID)
		require.NoError(t, err)
		assert.Equal(t, sess.ID, got.ID)
	})

	t.Run("revoke session from wrong user returns not found", func(t *testing.T) {
		createTestUser(t, pool, "usr_revoke-3", projectID)
		createTestUser(t, pool, "usr_revoke-4", projectID)
		sess, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_revoke-3",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		// Another user should NOT be able to revoke this session.
		err = svc.Revoke(ctx, sess.ID, projectID, "usr_revoke-4")
		assert.ErrorIs(t, err, session.ErrSessionNotFound)

		// Session should still be valid.
		got, err := svc.Get(ctx, sess.ID)
		require.NoError(t, err)
		assert.Equal(t, sess.ID, got.ID)
	})
}

func TestIntegration_RevokeAllSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := setupService(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	t.Run("revoke all sessions", func(t *testing.T) {
		userID := "usr_revokeall-1"
		createTestUser(t, pool, userID, projectID)

		// Create 3 sessions.
		for i := 0; i < 3; i++ {
			_, err := svc.Create(ctx, &session.CreateParams{
				ProjectID: projectID,
				UserID:    userID,
				ACR:       "aal1",
				AMR:       []string{"pwd"},
			})
			require.NoError(t, err)
		}

		// Verify they exist.
		sessions, err := svc.List(ctx, userID, projectID)
		require.NoError(t, err)
		assert.Len(t, sessions, 3)

		// Revoke all.
		err = svc.RevokeAll(ctx, userID, projectID)
		require.NoError(t, err)

		// Verify all gone.
		sessions, err = svc.List(ctx, userID, projectID)
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})
}

func TestIntegration_ListSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := setupService(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	t.Run("list returns only active sessions", func(t *testing.T) {
		userID := "usr_list-1"
		createTestUser(t, pool, userID, projectID)

		// Create 2 sessions.
		sess1, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    userID,
			IP:        "1.1.1.1",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		_, err = svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    userID,
			IP:        "2.2.2.2",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		// Revoke one.
		err = svc.Revoke(ctx, sess1.ID, projectID, userID)
		require.NoError(t, err)

		// List should return only the active one.
		sessions, err := svc.List(ctx, userID, projectID)
		require.NoError(t, err)
		assert.Len(t, sessions, 1)
		assert.Equal(t, "2.2.2.2", sessions[0].IP)
	})

	t.Run("list returns sessions with device info", func(t *testing.T) {
		userID := "usr_list-2"
		createTestUser(t, pool, userID, projectID)

		_, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    userID,
			IP:        "10.0.0.1",
			UserAgent: "Chrome/120",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		sessions, err := svc.List(ctx, userID, projectID)
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		assert.Equal(t, "10.0.0.1", sessions[0].IP)
		assert.Equal(t, "Chrome/120", sessions[0].UserAgent)
		assert.False(t, sessions[0].LastActivity.IsZero())
	})

	t.Run("list scoped to project — cross-project isolation", func(t *testing.T) {
		userID := "usr_list-3"
		createTestUser(t, pool, userID, projectID)

		// Create session in project A.
		_, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    userID,
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		// List for a different project should be empty.
		sessions, err := svc.List(ctx, userID, "prj_other-project")
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})
}

func TestIntegration_ValidateAndTouch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	svc := setupService(t, pool)
	ctx := context.Background()
	projectID := createTestProject(t, pool)

	t.Run("validates and touches valid session", func(t *testing.T) {
		createTestUser(t, pool, "usr_vt-1", projectID)
		created, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_vt-1",
			ACR:       "aal2",
			AMR:       []string{"pwd", "otp"},
		})
		require.NoError(t, err)

		sess, err := svc.ValidateAndTouch(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, sess.ID)
	})

	t.Run("returns error for revoked session", func(t *testing.T) {
		createTestUser(t, pool, "usr_vt-2", projectID)
		created, err := svc.Create(ctx, &session.CreateParams{
			ProjectID: projectID,
			UserID:    "usr_vt-2",
			ACR:       "aal1",
			AMR:       []string{"pwd"},
		})
		require.NoError(t, err)

		err = svc.Revoke(ctx, created.ID, projectID, "usr_vt-2")
		require.NoError(t, err)

		_, err = svc.ValidateAndTouch(ctx, created.ID)
		assert.ErrorIs(t, err, session.ErrSessionNotFound)
	})

	t.Run("returns error for nonexistent session", func(t *testing.T) {
		_, err := svc.ValidateAndTouch(ctx, "sess_nonexistent")
		assert.ErrorIs(t, err, session.ErrSessionNotFound)
	})
}
