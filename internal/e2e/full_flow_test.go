package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	"github.com/palauth/palauth/internal/config"
	"github.com/palauth/palauth/internal/server"
)

const testPepper = "e2e-test-pepper-at-least-32-bytes-long-ok!!"

func TestE2E_FullAuthFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	// 1. Start Postgres container.
	pool, pgCleanup := startPostgres(t)
	defer pgCleanup()

	// 2. Run migrations.
	migrationsDir, err := filepath.Abs("../../migrations")
	require.NoError(t, err)
	runMigrations(t, pool, migrationsDir)

	// 3. Start mock HIBP server (always returns "not breached").
	hibpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:0\r\n"))
	}))
	defer hibpServer.Close()

	// 4. Create server instance (nil Redis — rate limiting disabled, lockout disabled).
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "0.0.0.0",
			Port: 0,
		},
		Auth: config.AuthConfig{
			Pepper:      testPepper,
			HIBPBaseURL: hibpServer.URL + "/range/",
		},
	}

	srv := server.New(cfg, logger, pool, nil)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	client := ts.Client()

	// 4. Admin setup.
	setupResp := doPost(t, client, ts.URL+"/admin/setup", map[string]any{
		"email":        "admin@palauth.test",
		"password":     "admin-secure-password-1234!",
		"project_name": "E2E Test Project",
	})
	require.Equal(t, http.StatusOK, setupResp.StatusCode, "admin setup should succeed")

	var setupResult struct {
		Admin struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"admin"`
		Project struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"project"`
		APIKeys struct {
			PublishableKey string `json:"publishable_key"`
			SecretKey      string `json:"secret_key"`
		} `json:"api_keys"`
	}
	decodeJSON(t, setupResp, &setupResult)
	assert.NotEmpty(t, setupResult.Admin.ID)
	assert.Equal(t, "admin@palauth.test", setupResult.Admin.Email)
	assert.NotEmpty(t, setupResult.Project.ID)
	assert.NotEmpty(t, setupResult.APIKeys.PublishableKey)
	assert.NotEmpty(t, setupResult.APIKeys.SecretKey)

	projectID := setupResult.Project.ID
	apiKey := setupResult.APIKeys.PublishableKey

	// 5. Admin login.
	loginResp := doPost(t, client, ts.URL+"/admin/login", map[string]any{
		"email":    "admin@palauth.test",
		"password": "admin-secure-password-1234!",
	})
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "admin login should succeed")

	var adminLogin struct {
		Token string `json:"token"`
	}
	decodeJSON(t, loginResp, &adminLogin)
	assert.NotEmpty(t, adminLogin.Token)
	adminToken := adminLogin.Token

	// 6. Duplicate admin setup should fail.
	dup := doPost(t, client, ts.URL+"/admin/setup", map[string]any{
		"email":        "admin2@palauth.test",
		"password":     "admin-secure-password-5678!",
		"project_name": "Duplicate Project",
	})
	assert.NotEqual(t, http.StatusOK, dup.StatusCode, "duplicate setup should fail")
	dup.Body.Close()

	// 7. User signup via API.
	signupResp := doPostWithKey(t, client, ts.URL+"/auth/signup", apiKey, map[string]any{
		"email":    "user@palauth.test",
		"password": "user-secure-password-12345!",
	})
	signupBody := readBody(t, signupResp)
	if signupResp.StatusCode == http.StatusOK {
		var signupResult struct {
			AccessToken      string `json:"access_token"`
			RefreshToken     string `json:"refresh_token"`
			VerificationCode string `json:"verification_code"`
			User             struct {
				ID            string `json:"id"`
				Email         string `json:"email"`
				EmailVerified bool   `json:"email_verified"`
			} `json:"user"`
		}
		require.NoError(t, json.Unmarshal(signupBody, &signupResult))
		assert.NotEmpty(t, signupResult.AccessToken)
		assert.NotEmpty(t, signupResult.RefreshToken)
		assert.Equal(t, "user@palauth.test", signupResult.User.Email)
		assert.False(t, signupResult.User.EmailVerified)

		userID := signupResult.User.ID

		// 8. Verify email with OTP code.
		if signupResult.VerificationCode != "" {
			verifyResp := doPostWithKey(t, client, ts.URL+"/auth/verify-email", apiKey, map[string]any{
				"code":  signupResult.VerificationCode,
				"email": "user@palauth.test",
			})
			assert.Equal(t, http.StatusOK, verifyResp.StatusCode, "email verification should succeed")
			verifyResp.Body.Close()
		}

		// 9. User login.
		userLoginResp := doPostWithKey(t, client, ts.URL+"/auth/login", apiKey, map[string]any{
			"email":    "user@palauth.test",
			"password": "user-secure-password-12345!",
		})
		assert.Equal(t, http.StatusOK, userLoginResp.StatusCode, "user login should succeed")
		var userLoginResult struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSON(t, userLoginResp, &userLoginResult)
		userRefreshToken := userLoginResult.RefreshToken

		// 10. Token refresh.
		refreshResp := doPostWithKey(t, client, ts.URL+"/auth/token/refresh", apiKey, map[string]any{
			"refresh_token": userRefreshToken,
		})
		assert.Equal(t, http.StatusOK, refreshResp.StatusCode, "token refresh should succeed")
		var refreshResult struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		decodeJSON(t, refreshResp, &refreshResult)
		assert.NotEmpty(t, refreshResult.AccessToken)
		assert.NotEmpty(t, refreshResult.RefreshToken)
		assert.NotEqual(t, userRefreshToken, refreshResult.RefreshToken, "new refresh token should differ")
		userAccessToken := refreshResult.AccessToken

		// 11. List sessions.
		sessResp := doGetWithKeyAndAuth(t, client, ts.URL+"/auth/sessions", apiKey, userAccessToken)
		assert.Equal(t, http.StatusOK, sessResp.StatusCode, "list sessions should succeed")
		sessResp.Body.Close()

		// 12. Logout.
		logoutResp := doPostWithKeyAndAuth(t, client, ts.URL+"/auth/logout", apiKey, userAccessToken, nil)
		assert.Equal(t, http.StatusOK, logoutResp.StatusCode, "logout should succeed")
		logoutResp.Body.Close()

		// 13. Password reset request.
		resetReqResp := doPostWithKey(t, client, ts.URL+"/auth/password/reset", apiKey, map[string]any{
			"email": "user@palauth.test",
		})
		assert.Equal(t, http.StatusOK, resetReqResp.StatusCode, "password reset request should return 200")
		resetReqResp.Body.Close()

		// 14. Ban user (admin).
		banResp := doRequestWithAuth(t, client, "POST",
			fmt.Sprintf("%s/admin/projects/%s/users/%s/ban", ts.URL, projectID, userID), adminToken)
		assert.Equal(t, http.StatusOK, banResp.StatusCode, "ban should succeed")
		banResp.Body.Close()

		// Login should fail for banned user.
		bannedLogin := doPostWithKey(t, client, ts.URL+"/auth/login", apiKey, map[string]any{
			"email":    "user@palauth.test",
			"password": "user-secure-password-12345!",
		})
		assert.NotEqual(t, http.StatusOK, bannedLogin.StatusCode, "banned user login should fail")
		bannedLogin.Body.Close()

		// 15. Unban user.
		unbanResp := doRequestWithAuth(t, client, "POST",
			fmt.Sprintf("%s/admin/projects/%s/users/%s/unban", ts.URL, projectID, userID), adminToken)
		assert.Equal(t, http.StatusOK, unbanResp.StatusCode, "unban should succeed")
		unbanResp.Body.Close()

		// Login should work after unban.
		unbannedLogin := doPostWithKey(t, client, ts.URL+"/auth/login", apiKey, map[string]any{
			"email":    "user@palauth.test",
			"password": "user-secure-password-12345!",
		})
		assert.Equal(t, http.StatusOK, unbannedLogin.StatusCode, "unbanned user login should succeed")
		unbannedLogin.Body.Close()

		// 16. Delete user (GDPR).
		delResp := doRequestWithAuth(t, client, "DELETE",
			fmt.Sprintf("%s/admin/projects/%s/users/%s", ts.URL, projectID, userID), adminToken)
		assert.Equal(t, http.StatusOK, delResp.StatusCode, "delete user should succeed")
		delResp.Body.Close()

		// Verify audit chain is intact after deletion.
		verifyResp2 := doPostWithAdminAuth(t, client,
			fmt.Sprintf("%s/admin/projects/%s/audit-logs/verify", ts.URL, projectID), adminToken, nil)
		if verifyResp2.StatusCode == http.StatusOK {
			var verifyResult struct {
				Valid bool `json:"valid"`
				Total int  `json:"total"`
			}
			decodeJSON(t, verifyResp2, &verifyResult)
			assert.True(t, verifyResult.Valid, "audit chain should be valid after GDPR erasure")
			assert.True(t, verifyResult.Total > 0, "audit logs should exist")
		} else {
			verifyResp2.Body.Close()
		}
	} else {
		t.Fatalf("signup failed with status %d: %s", signupResp.StatusCode, string(signupBody))
	}

	// 17. JWKS endpoint should be public.
	jwksResp := doGetWithContext(t, client, ts.URL+"/.well-known/jwks.json")
	assert.Equal(t, http.StatusOK, jwksResp.StatusCode)
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	decodeJSON(t, jwksResp, &jwks)
	assert.NotEmpty(t, jwks.Keys, "JWKS should have at least one key")

	// 18. Health check.
	healthResp := doGetWithContext(t, client, ts.URL+"/healthz")
	assert.Equal(t, http.StatusOK, healthResp.StatusCode)
	healthResp.Body.Close()
}

// Helper functions.

func startPostgres(t *testing.T) (pool *pgxpool.Pool, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("palauth_e2e"),
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

func doPost(t *testing.T, client *http.Client, url string, body map[string]any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func doPostWithKey(t *testing.T, client *http.Client, url, apiKey string, body map[string]any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func doPostWithKeyAndAuth(t *testing.T, client *http.Client, url, apiKey, token string, body map[string]any) *http.Response {
	t.Helper()
	var bodyReader io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), "POST", url, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func doPostWithAdminAuth(t *testing.T, client *http.Client, url, token string, body map[string]any) *http.Response {
	t.Helper()
	var bodyReader io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), "POST", url, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func doGetWithKeyAndAuth(t *testing.T, client *http.Client, url, apiKey, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", url, http.NoBody)
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func doRequestWithAuth(t *testing.T, client *http.Client, method, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, url, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func doGetWithContext(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", url, http.NoBody)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.NoError(t, json.Unmarshal(body, v), "decode JSON: %s", string(body))
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	return body
}
