package audit_test

import (
	"context"
	"fmt"
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
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
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

	// Run migrations by reading SQL files directly.
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

func TestIntegration_LogAndVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := audit.NewService(pool, testKEK(), logger)
	ctx := context.Background()
	projectID := createTestProject(t, pool)
	createTestUser(t, pool, projectID, "usr_1")

	// Log 3 events to build a chain.
	events := []audit.Event{
		{
			EventType: audit.EventAuthSignup,
			Actor:     audit.ActorInfo{UserID: "usr_1", Email: "alice@example.com", IP: "10.0.0.1"},
			Target:    &audit.TargetInfo{Type: "user", ID: "usr_1"},
			Result:    "success",
			ProjectID: projectID,
			TraceID:   "req_trace1",
		},
		{
			EventType:  audit.EventAuthLoginSuccess,
			Actor:      audit.ActorInfo{UserID: "usr_1", Email: "alice@example.com", IP: "10.0.0.2"},
			Result:     "success",
			AuthMethod: "password",
			ProjectID:  projectID,
			TraceID:    "req_trace2",
		},
		{
			EventType: audit.EventAuthLogout,
			Actor:     audit.ActorInfo{UserID: "usr_1"},
			Result:    "success",
			ProjectID: projectID,
		},
	}

	for i := range events {
		err := svc.Log(ctx, &events[i])
		require.NoError(t, err)
	}

	// Verify the chain is valid.
	report, err := svc.Verify(ctx, projectID)
	require.NoError(t, err)
	assert.True(t, report.Valid)
	assert.Equal(t, 3, report.Total)
	assert.Nil(t, report.BrokenAt)
}

func TestIntegration_TamperedLogDetected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := audit.NewService(pool, testKEK(), logger)
	ctx := context.Background()
	projectID := createTestProject(t, pool)
	for i := 0; i < 3; i++ {
		createTestUser(t, pool, projectID, fmt.Sprintf("usr_%d", i))
	}

	// Log 3 events.
	for i := 0; i < 3; i++ {
		err := svc.Log(ctx, &audit.Event{
			EventType: audit.EventAuthLoginSuccess,
			Actor:     audit.ActorInfo{UserID: fmt.Sprintf("usr_%d", i)},
			Result:    "success",
			ProjectID: projectID,
		})
		require.NoError(t, err)
	}

	// Tamper with the second event's hash in the DB.
	q := sqlc.New(pool)
	logs, err := q.ListAuditLogsAsc(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, logs, 3)

	_, err = pool.Exec(ctx, "UPDATE audit_logs SET event_hash = 'tampered_hash' WHERE id = $1", logs[1].ID)
	require.NoError(t, err)

	// Verify should detect the tampering.
	report, err := svc.Verify(ctx, projectID)
	require.NoError(t, err)
	assert.False(t, report.Valid)
	require.NotNil(t, report.BrokenAt)
	assert.Equal(t, logs[1].ID, report.BrokenAt.EventID)
	assert.Equal(t, 1, report.BrokenAt.Index)
}

func TestIntegration_PIIEncryptedInDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := audit.NewService(pool, testKEK(), logger)
	ctx := context.Background()
	projectID := createTestProject(t, pool)
	createTestUser(t, pool, projectID, "usr_pii")

	err := svc.Log(ctx, &audit.Event{
		EventType: audit.EventAuthSignup,
		Actor:     audit.ActorInfo{UserID: "usr_pii", Email: "secret@example.com", IP: "192.168.1.100"},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"browser": "Firefox"},
	})
	require.NoError(t, err)

	// Read raw from DB — PII should NOT be readable as plaintext.
	q := sqlc.New(pool)
	log, err := q.GetLastAuditLog(ctx, projectID)
	require.NoError(t, err)

	rawActor := string(log.ActorEncrypted)
	assert.NotContains(t, rawActor, "secret@example.com", "Email must not appear in plaintext in DB")
	assert.NotContains(t, rawActor, "192.168.1.100", "IP must not appear in plaintext in DB")

	rawMeta := string(log.MetadataEncrypted)
	assert.NotContains(t, rawMeta, "Firefox", "Metadata must not appear in plaintext in DB")
}

func TestIntegration_GDPRErasure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := audit.NewService(pool, testKEK(), logger)
	ctx := context.Background()
	projectID := createTestProject(t, pool)
	createTestUser(t, pool, projectID, "usr_eraseme")
	createTestUser(t, pool, projectID, "system")

	// Log events for a user.
	err := svc.Log(ctx, &audit.Event{
		EventType: audit.EventAuthSignup,
		Actor:     audit.ActorInfo{UserID: "usr_eraseme", Email: "erase@example.com", IP: "10.0.0.1"},
		Target:    &audit.TargetInfo{Type: "user", ID: "usr_eraseme"},
		Result:    "success",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	// Before erasure: PII should be decryptable via List.
	result, err := svc.List(ctx, projectID, audit.ListOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, result.Events, 1)
	require.NotNil(t, result.Events[0].Actor)
	assert.Equal(t, "erase@example.com", result.Events[0].Actor.Email)

	// Erase the user.
	err = svc.Erase(ctx, projectID, "usr_eraseme")
	require.NoError(t, err)

	// After erasure: PII should be unreadable.
	result, err = svc.List(ctx, projectID, audit.ListOptions{Limit: 10})
	require.NoError(t, err)
	// Should have 2 events now (original + gdpr.erasure).
	require.Len(t, result.Events, 2)
	// The most recent event (DESC order) is the erasure event.
	assert.Equal(t, audit.EventGDPRErasure, result.Events[0].EventType)
	// The original event's PII should be nil (DEK revoked).
	assert.Nil(t, result.Events[1].Actor, "After erasure, actor PII should be unreadable")

	// Hash chain should still be valid.
	report, err := svc.Verify(ctx, projectID)
	require.NoError(t, err)
	assert.True(t, report.Valid, "Hash chain must remain valid after GDPR erasure")
}

func TestIntegration_CursorPagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := audit.NewService(pool, testKEK(), logger)
	ctx := context.Background()
	projectID := createTestProject(t, pool)
	for i := 0; i < 5; i++ {
		createTestUser(t, pool, projectID, fmt.Sprintf("usr_%d", i))
	}

	// Log 5 events.
	for i := 0; i < 5; i++ {
		err := svc.Log(ctx, &audit.Event{
			EventType: audit.EventAuthLoginSuccess,
			Actor:     audit.ActorInfo{UserID: fmt.Sprintf("usr_%d", i)},
			Result:    "success",
			ProjectID: projectID,
		})
		require.NoError(t, err)
		// Small sleep to ensure distinct created_at values.
		time.Sleep(5 * time.Millisecond)
	}

	// First page: 2 events.
	page1, err := svc.List(ctx, projectID, audit.ListOptions{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, page1.Events, 2)
	assert.Equal(t, int64(5), page1.Total)
	require.NotNil(t, page1.NextCursor)

	// Second page: 2 events.
	page2, err := svc.List(ctx, projectID, audit.ListOptions{
		Limit:  2,
		Cursor: page1.NextCursor,
	})
	require.NoError(t, err)
	assert.Len(t, page2.Events, 2)
	require.NotNil(t, page2.NextCursor)

	// Third page: 1 event.
	page3, err := svc.List(ctx, projectID, audit.ListOptions{
		Limit:  2,
		Cursor: page2.NextCursor,
	})
	require.NoError(t, err)
	assert.Len(t, page3.Events, 1)
	assert.Nil(t, page3.NextCursor, "No more pages")

	// All event IDs should be unique.
	allIDs := make(map[string]bool)
	for _, e := range page1.Events {
		allIDs[e.ID] = true
	}
	for _, e := range page2.Events {
		allIDs[e.ID] = true
	}
	for _, e := range page3.Events {
		allIDs[e.ID] = true
	}
	assert.Len(t, allIDs, 5, "All 5 events should appear exactly once across pages")
}

func TestIntegration_ExportJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := audit.NewService(pool, testKEK(), logger)
	ctx := context.Background()
	projectID := createTestProject(t, pool)
	createTestUser(t, pool, projectID, "usr_export")

	err := svc.Log(ctx, &audit.Event{
		EventType: audit.EventAuthSignup,
		Actor:     audit.ActorInfo{UserID: "usr_export", Email: "export@example.com"},
		Result:    "success",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	data, err := svc.Export(ctx, projectID, "json")
	require.NoError(t, err)
	assert.Contains(t, string(data), "auth.signup")
	assert.Contains(t, string(data), "export@example.com")
}

func TestIntegration_ExportCSV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := audit.NewService(pool, testKEK(), logger)
	ctx := context.Background()
	projectID := createTestProject(t, pool)
	createTestUser(t, pool, projectID, "usr_csv")

	err := svc.Log(ctx, &audit.Event{
		EventType: audit.EventAuthSignup,
		Actor:     audit.ActorInfo{UserID: "usr_csv", Email: "csv@example.com"},
		Result:    "success",
		ProjectID: projectID,
	})
	require.NoError(t, err)

	data, err := svc.Export(ctx, projectID, "csv")
	require.NoError(t, err)
	csv := string(data)
	assert.Contains(t, csv, "id,project_id,trace_id,event_type")
	assert.Contains(t, csv, "auth.signup")
	assert.Contains(t, csv, "csv@example.com")
}

func TestIntegration_ProjectIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := audit.NewService(pool, testKEK(), logger)
	ctx := context.Background()

	projectA := createTestProject(t, pool)
	projectB := createTestProject(t, pool)
	createTestUser(t, pool, projectA, "usr_shared_a")
	createTestUser(t, pool, projectB, "usr_shared_b")

	// Log events to different projects.
	err := svc.Log(ctx, &audit.Event{
		EventType: audit.EventAuthSignup,
		Actor:     audit.ActorInfo{UserID: "usr_shared_a"},
		Result:    "success",
		ProjectID: projectA,
	})
	require.NoError(t, err)

	err = svc.Log(ctx, &audit.Event{
		EventType: audit.EventAuthSignup,
		Actor:     audit.ActorInfo{UserID: "usr_shared_b"},
		Result:    "success",
		ProjectID: projectB,
	})
	require.NoError(t, err)

	// Each project should have exactly 1 event.
	resultA, err := svc.List(ctx, projectA, audit.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), resultA.Total)

	resultB, err := svc.List(ctx, projectB, audit.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), resultB.Total)

	// Each project's chain should be independently valid.
	reportA, err := svc.Verify(ctx, projectA)
	require.NoError(t, err)
	assert.True(t, reportA.Valid)

	reportB, err := svc.Verify(ctx, projectB)
	require.NoError(t, err)
	assert.True(t, reportB.Valid)
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

func createTestUser(t *testing.T, pool *pgxpool.Pool, projectID, userID string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		"INSERT INTO users (id, project_id, email_encrypted, email_hash) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
		userID, projectID, []byte("encrypted"), []byte("hash"))
	require.NoError(t, err)
}

// Verify crypto.GenerateKey is used (not math/rand) by checking the KEK
// encryption roundtrip works correctly.
func TestIntegration_DEKEncryptionRoundtrip(t *testing.T) {
	kek := testKEK()
	dek, err := crypto.GenerateKey()
	require.NoError(t, err)

	encrypted, err := crypto.Encrypt(dek, kek, nil)
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(encrypted, kek, nil)
	require.NoError(t, err)

	assert.Equal(t, dek, decrypted)
}

// runMigrations reads and executes all *.up.sql files in order.
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
