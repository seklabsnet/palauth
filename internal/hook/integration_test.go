package hook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/hook"
	"github.com/palauth/palauth/internal/id"
)

const testPepper = "this-is-a-test-pepper-at-least-32-bytes-long-ok"

func testKEK() []byte {
	mac := hmac.New(sha256.New, []byte(testPepper))
	mac.Write([]byte("hook-signing-kek"))
	return mac.Sum(nil)
}

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

func runMigrations(t *testing.T, pool *pgxpool.Pool, migrationsDir string) {
	t.Helper()
	entries, err := os.ReadDir(migrationsDir)
	require.NoError(t, err)

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		content, readErr := os.ReadFile(filepath.Join(migrationsDir, entry.Name()))
		require.NoError(t, readErr)
		_, execErr := pool.Exec(context.Background(), string(content))
		require.NoError(t, execErr, "migration %s failed", entry.Name())
	}
}

func createTestProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	q := sqlc.New(pool)
	projectID := id.New("prj_")
	_, err := q.CreateProject(context.Background(), sqlc.CreateProjectParams{
		ID:     projectID,
		Name:   "test-project",
		Config: []byte(`{}`),
	})
	require.NoError(t, err)
	return projectID
}

// signedHookHandler wraps a hook response handler to add Standard Webhooks response signing.
func signedHookHandler(signingKey []byte, handler func(w http.ResponseWriter, r *http.Request) hook.Response) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := handler(w, r)
		respBody, _ := json.Marshal(resp)

		respWebhookID := fmt.Sprintf("msg_resp_%s", id.New(""))
		respTimestamp := fmt.Sprintf("%d", time.Now().Unix())

		mac := hmac.New(sha256.New, signingKey)
		mac.Write([]byte(respWebhookID))
		mac.Write([]byte("."))
		mac.Write([]byte(respTimestamp))
		mac.Write([]byte("."))
		mac.Write(respBody)
		respSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("webhook-id", respWebhookID)
		w.Header().Set("webhook-timestamp", respTimestamp)
		w.Header().Set("webhook-signature", "v1,"+respSig)
		w.Write(respBody) //nolint:errcheck // test helper, error not critical
	}
}

func newTestEngine(t *testing.T, pool *pgxpool.Pool) *hook.Engine {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	engine := hook.NewEngine(pool, testKEK(), logger, true)
	// Use plain HTTP client for testing — bypasses SSRF transport that blocks localhost.
	engine.SetHTTPClient(&http.Client{})
	return engine
}

// --- Integration Tests ---

func TestIntegration_ExecuteBlocking_Allow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	// We need the signing key before creating the server, but the server URL before creating the config.
	// Generate signing key first, create server, then config.
	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	var capturedHeaders struct {
		method, contentType, webhookID, webhookTimestamp, webhookSignature string
		event, pProjectID                                                 string
	}

	hookServer := httptest.NewServer(signedHookHandler(signingKey, func(w http.ResponseWriter, r *http.Request) hook.Response {
		capturedHeaders.method = r.Method
		capturedHeaders.contentType = r.Header.Get("Content-Type")
		capturedHeaders.webhookID = r.Header.Get("webhook-id")
		capturedHeaders.webhookTimestamp = r.Header.Get("webhook-timestamp")
		capturedHeaders.webhookSignature = r.Header.Get("webhook-signature")

		body, _ := io.ReadAll(r.Body)
		var payload hook.Payload
		_ = json.Unmarshal(body, &payload)
		capturedHeaders.event = payload.Event
		capturedHeaders.pProjectID = payload.ProjectID

		return hook.Response{Verdict: "allow"}
	}))
	defer hookServer.Close()

	// Create hook config with the pre-generated signing key.
	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventBeforeUserCreate,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	resp, err := engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeUserCreate, hook.Payload{
		User: &hook.UserInfo{ID: "usr_test", Email: "test@example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "allow", resp.Verdict)

	// Verify Standard Webhooks headers were sent.
	assert.Equal(t, "POST", capturedHeaders.method)
	assert.Equal(t, "application/json", capturedHeaders.contentType)
	assert.True(t, strings.HasPrefix(capturedHeaders.webhookID, "msg_"))
	assert.NotEmpty(t, capturedHeaders.webhookTimestamp)
	assert.True(t, strings.HasPrefix(capturedHeaders.webhookSignature, "v1,"))
	assert.Equal(t, hook.EventBeforeUserCreate, capturedHeaders.event)
	assert.Equal(t, projectID, capturedHeaders.pProjectID)
}

func TestIntegration_ExecuteBlocking_Deny(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hookServer := httptest.NewServer(signedHookHandler(signingKey, func(w http.ResponseWriter, _ *http.Request) hook.Response {
		return hook.Response{Verdict: "deny", Reason: "user blocked by policy"}
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventBeforeLogin,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	resp, err := engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{
		User: &hook.UserInfo{ID: "usr_test"},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, hook.ErrHookDenied)
	require.NotNil(t, resp)
	assert.Equal(t, "deny", resp.Verdict)
	assert.Equal(t, "user blocked by policy", resp.Reason)
}

func TestIntegration_ExecuteBlocking_Timeout_DenyMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hook.Response{Verdict: "allow"})
	}))
	defer hookServer.Close()

	// Create hook with very short timeout and deny failure mode.
	hookID := id.New("hk_")
	signingKey, _ := crypto.GenerateKey()
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, _ := crypto.Encrypt(signingKey, testKEK(), aad)

	q := sqlc.New(pool)
	_, err := q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID:                  hookID,
		ProjectID:           projectID,
		Event:               hook.EventBeforeLogin,
		Url:                 hookServer.URL,
		SigningKeyEncrypted: encryptedKey,
		TimeoutMs:           100, // 100ms timeout
		FailureMode:         "deny",
		Enabled:             true,
	})
	require.NoError(t, err)

	_, err = engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{})
	require.Error(t, err)
	// Should fail due to timeout with deny mode.
}

func TestIntegration_ExecuteBlocking_Timeout_AllowMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hook.Response{Verdict: "allow"})
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	signingKey, _ := crypto.GenerateKey()
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, _ := crypto.Encrypt(signingKey, testKEK(), aad)

	q := sqlc.New(pool)
	_, err := q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID:                  hookID,
		ProjectID:           projectID,
		Event:               hook.EventBeforeLogin,
		Url:                 hookServer.URL,
		SigningKeyEncrypted: encryptedKey,
		TimeoutMs:           100, // 100ms timeout
		FailureMode:         "allow",
		Enabled:             true,
	})
	require.NoError(t, err)

	resp, err := engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{})
	require.NoError(t, err) // Should succeed because failure_mode=allow.
	assert.Equal(t, "allow", resp.Verdict)
}

func TestIntegration_ExecuteBlocking_CustomClaims(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hookServer := httptest.NewServer(signedHookHandler(signingKey, func(w http.ResponseWriter, _ *http.Request) hook.Response {
		return hook.Response{
			Verdict: "allow",
			CustomClaims: map[string]any{
				"role":  "admin",
				"team":  "engineering",
				"level": float64(3),
			},
		}
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventBeforeTokenIssue,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	resp, err := engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeTokenIssue, hook.Payload{
		User: &hook.UserInfo{ID: "usr_test"},
	})
	require.NoError(t, err)
	assert.Equal(t, "allow", resp.Verdict)
	assert.Equal(t, "admin", resp.CustomClaims["role"])
	assert.Equal(t, "engineering", resp.CustomClaims["team"])
	assert.Equal(t, float64(3), resp.CustomClaims["level"])
}

func TestIntegration_ExecuteBlocking_NoHooksConfigured(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	resp, err := engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{})
	require.NoError(t, err)
	assert.Equal(t, "allow", resp.Verdict)
}

func TestIntegration_ExecuteBlocking_HMACVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	// Create a hook server that captures request headers and signs the response.
	var receivedWebhookID, receivedTimestamp, receivedSignature string

	hookServer := httptest.NewServer(signedHookHandler(signingKey, func(w http.ResponseWriter, r *http.Request) hook.Response {
		receivedWebhookID = r.Header.Get("webhook-id")
		receivedTimestamp = r.Header.Get("webhook-timestamp")
		receivedSignature = r.Header.Get("webhook-signature")
		return hook.Response{Verdict: "allow"}
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventBeforeLogin,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	_, err = engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{
		User: &hook.UserInfo{ID: "usr_test"},
	})
	require.NoError(t, err)

	// Verify Standard Webhooks header format.
	assert.True(t, strings.HasPrefix(receivedWebhookID, "msg_"), "webhook-id should start with msg_")
	assert.NotEmpty(t, receivedTimestamp)
	assert.True(t, strings.HasPrefix(receivedSignature, "v1,"), "webhook-signature should start with v1,")

	// Verify the signature is valid base64 after v1, prefix.
	sigParts := strings.SplitN(receivedSignature, ",", 2)
	require.Len(t, sigParts, 2)
	_, err = base64.StdEncoding.DecodeString(sigParts[1])
	assert.NoError(t, err, "signature should be valid base64")
}

func TestIntegration_ExecuteBlocking_BidirectionalSigning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	kek := testKEK()

	// We need the signing key to produce a valid response signature.
	hookID := id.New("hk_")
	signingKey, _ := crypto.GenerateKey()
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, _ := crypto.Encrypt(signingKey, kek, aad)

	q := sqlc.New(pool)
	_, err := q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID:                  hookID,
		ProjectID:           projectID,
		Event:               hook.EventBeforeLogin,
		Url:                 "", // Will be set after server is created
		SigningKeyEncrypted: encryptedKey,
		TimeoutMs:           15000,
		FailureMode:         "deny",
		Enabled:             true,
	})
	require.NoError(t, err)

	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respBody, _ := json.Marshal(hook.Response{Verdict: "allow"})

		// Compute response signature using the same signing key.
		respWebhookID := fmt.Sprintf("msg_resp_%s", hookID)
		respTimestamp := fmt.Sprintf("%d", time.Now().Unix())

		mac := hmac.New(sha256.New, signingKey)
		mac.Write([]byte(respWebhookID))
		mac.Write([]byte("."))
		mac.Write([]byte(respTimestamp))
		mac.Write([]byte("."))
		mac.Write(respBody)
		respSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("webhook-id", respWebhookID)
		w.Header().Set("webhook-timestamp", respTimestamp)
		w.Header().Set("webhook-signature", "v1,"+respSig)
		w.Write(respBody)
	}))
	defer hookServer.Close()

	// Update hook URL to point to our test server.
	_, err = q.UpdateHookConfig(context.Background(), sqlc.UpdateHookConfigParams{
		ID:          hookID,
		ProjectID:   projectID,
		Event:       hook.EventBeforeLogin,
		Url:         hookServer.URL,
		TimeoutMs:   15000,
		FailureMode: "deny",
		Enabled:     true,
	})
	require.NoError(t, err)

	resp, err := engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{
		User: &hook.UserInfo{ID: "usr_test"},
	})
	require.NoError(t, err)
	assert.Equal(t, "allow", resp.Verdict)
}

func TestIntegration_ExecuteBlocking_InvalidResponseSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		respBody, _ := json.Marshal(hook.Response{Verdict: "allow"})

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("webhook-id", "msg_resp")
		w.Header().Set("webhook-timestamp", fmt.Sprintf("%d", time.Now().Unix()))
		w.Header().Set("webhook-signature", "v1,invalidsignature==")
		w.Write(respBody) //nolint:errcheck // test helper, error not critical
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventBeforeLogin,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	_, err = engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{})
	require.Error(t, err)
	assert.ErrorIs(t, err, hook.ErrInvalidSignature)
}

func TestIntegration_ExecuteBlocking_MissingResponseSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	// Server returns valid JSON but no webhook-signature header.
	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hook.Response{Verdict: "allow"}) //nolint:errcheck // test helper, error not critical
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventBeforeLogin,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	_, err = engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{})
	require.Error(t, err)
	assert.ErrorIs(t, err, hook.ErrInvalidSignature)
}

func TestIntegration_ExecuteBlocking_ReplayedTimestamp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	// Server signs response but uses an old timestamp (replay attack).
	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		respBody, _ := json.Marshal(hook.Response{Verdict: "allow"})

		oldTimestamp := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
		respWebhookID := "msg_replayed"

		mac := hmac.New(sha256.New, signingKey)
		mac.Write([]byte(respWebhookID))
		mac.Write([]byte("."))
		mac.Write([]byte(oldTimestamp))
		mac.Write([]byte("."))
		mac.Write(respBody)
		respSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("webhook-id", respWebhookID)
		w.Header().Set("webhook-timestamp", oldTimestamp)
		w.Header().Set("webhook-signature", "v1,"+respSig)
		w.Write(respBody) //nolint:errcheck // test helper, error not critical
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventBeforeLogin,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	_, err = engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeLogin, hook.Payload{})
	require.Error(t, err)
	assert.ErrorIs(t, err, hook.ErrReplayedWebhook)
}

func TestIntegration_HookLogsRecorded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	hookServer := httptest.NewServer(signedHookHandler(signingKey, func(w http.ResponseWriter, _ *http.Request) hook.Response {
		return hook.Response{Verdict: "allow"}
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventBeforeUserCreate,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	_, err = engine.ExecuteBlocking(context.Background(), projectID, hook.EventBeforeUserCreate, hook.Payload{
		User: &hook.UserInfo{ID: "usr_test"},
	})
	require.NoError(t, err)

	// Verify hook log was recorded.
	logs, err := q.ListHookLogs(context.Background(), sqlc.ListHookLogsParams{
		HookConfigID: hookID,
		ProjectID:    projectID,
		Limit:        10,
	})
	require.NoError(t, err)
	require.Len(t, logs, 1)
	assert.Equal(t, "allow", logs[0].Result)
	assert.Equal(t, hook.EventBeforeUserCreate, logs[0].Event)
	assert.GreaterOrEqual(t, logs[0].LatencyMs, int32(0))
	assert.NotNil(t, logs[0].ResponseStatus)
	assert.Equal(t, int32(200), *logs[0].ResponseStatus)
}

func TestIntegration_ExecuteAsync(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	projectID := createTestProject(t, pool)
	engine := newTestEngine(t, pool)

	signingKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	called := make(chan bool, 1)
	hookServer := httptest.NewServer(signedHookHandler(signingKey, func(w http.ResponseWriter, _ *http.Request) hook.Response {
		called <- true
		return hook.Response{Verdict: "allow"}
	}))
	defer hookServer.Close()

	hookID := id.New("hk_")
	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encryptedKey, err := crypto.Encrypt(signingKey, testKEK(), aad)
	require.NoError(t, err)
	q := sqlc.New(pool)
	_, err = q.CreateHookConfig(context.Background(), sqlc.CreateHookConfigParams{
		ID: hookID, ProjectID: projectID, Event: hook.EventAfterLoginFailed,
		Url: hookServer.URL, SigningKeyEncrypted: encryptedKey, TimeoutMs: 15000,
		FailureMode: "deny", Enabled: true,
	})
	require.NoError(t, err)

	engine.ExecuteAsync(context.Background(), projectID, hook.EventAfterLoginFailed, hook.Payload{
		User: &hook.UserInfo{ID: "usr_test"},
	})

	// Wait for async hook to fire.
	select {
	case <-called:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("async hook was not called within timeout")
	}
}
