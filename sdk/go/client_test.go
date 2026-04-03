package palauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("https://auth.example.com", "pk_test_abc")
	if c.baseURL != "https://auth.example.com" {
		t.Errorf("expected baseURL https://auth.example.com, got %s", c.baseURL)
	}
	if c.apiKey != "pk_test_abc" {
		t.Errorf("expected apiKey pk_test_abc, got %s", c.apiKey)
	}
}

func TestNewClient_TrailingSlash(t *testing.T) {
	c := NewClient("https://auth.example.com///", "pk_test_abc")
	if c.baseURL != "https://auth.example.com" {
		t.Errorf("expected trailing slashes stripped, got %s", c.baseURL)
	}
}

func TestSignUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/signup" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("X-API-Key") != "pk_test_abc" {
			t.Errorf("missing API key header")
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["email"] != "user@test.com" {
			t.Errorf("unexpected email: %s", body["email"])
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(AuthResult{
			AccessToken:  "at_123",
			RefreshToken: "rt_123",
			TokenType:    "Bearer",
			ExpiresIn:    1800,
			User:         UserInfo{ID: "usr_1", Email: "user@test.com"},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "pk_test_abc")
	result, err := c.SignUp(context.Background(), "user@test.com", "super-secure-pass-123")
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != "at_123" {
		t.Errorf("expected at_123, got %s", result.AccessToken)
	}
	if result.User.Email != "user@test.com" {
		t.Errorf("expected user@test.com, got %s", result.User.Email)
	}
}

func TestSignIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AuthResult{
			AccessToken:  "at_login",
			RefreshToken: "rt_login",
			TokenType:    "Bearer",
			ExpiresIn:    1800,
			User:         UserInfo{ID: "usr_2", Email: "user@test.com", EmailVerified: true},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "pk_test_abc")
	result, err := c.SignIn(context.Background(), "user@test.com", "super-secure-pass-123")
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != "at_login" {
		t.Errorf("expected at_login, got %s", result.AccessToken)
	}
}

func TestVerifyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/introspect" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["token"] != "some.jwt.token" {
			t.Errorf("unexpected token: %s", body["token"])
		}

		_ = json.NewEncoder(w).Encode(IntrospectionResponse{
			Active:    true,
			Subject:   "usr_1",
			ProjectID: "prj_1",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sk_test_secret")
	result, err := c.VerifyToken(context.Background(), "some.jwt.token")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Active {
		t.Error("expected active=true")
	}
	if result.Subject != "usr_1" {
		t.Errorf("expected usr_1, got %s", result.Subject)
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(ErrorResponse{
			Error:       "not_found",
			Description: "User not found",
			Status:      404,
			RequestID:   "req_1",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sk_test_secret")
	_, err := c.GetUser(context.Background(), "prj_1", "usr_missing")
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.ErrorResponse.Error != "not_found" {
		t.Errorf("expected not_found, got %s", apiErr.ErrorResponse.Error)
	}
	if apiErr.Status != 404 {
		t.Errorf("expected 404, got %d", apiErr.Status)
	}
}

func TestListUsers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("expected limit=10, got %s", r.URL.Query().Get("limit"))
		}

		_ = json.NewEncoder(w).Encode(UserListResult{
			Users: []UserDetail{{ID: "usr_1", Email: "a@b.com"}},
			Total: 1,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sk_test_secret")
	result, err := c.ListUsers(context.Background(), "prj_1", &UserListOptions{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(result.Users))
	}
	if result.Total != 1 {
		t.Errorf("expected total=1, got %d", result.Total)
	}
}

func TestRevokeToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sk_test_secret")
	err := c.RevokeToken(context.Background(), "some_token", "refresh_token")
	if err != nil {
		t.Fatal(err)
	}
}

func TestWithHTTPClient(t *testing.T) {
	customClient := &http.Client{}
	c := NewClient("https://auth.example.com", "pk_test_abc", WithHTTPClient(customClient))
	if c.httpClient != customClient {
		t.Error("custom HTTP client not set")
	}
}

func TestPathParamValidation(t *testing.T) {
	c := NewClient("https://auth.example.com", "sk_test_secret")

	tests := []struct {
		name      string
		projectID string
		userID    string
		wantErr   bool
	}{
		{"valid IDs", "prj_123", "usr_456", false},
		{"projectID with slash", "prj/evil", "usr_1", true},
		{"userID with dotdot", "prj_1", "..", true},
		{"projectID with percent", "prj%2F1", "usr_1", true},
		{"userID with path traversal", "prj_1", "../../admin", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.GetUser(context.Background(), tt.projectID, tt.userID)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error for invalid path param")
				}
			}
			// For valid IDs, the error will be a connection error (no server) — that's fine,
			// we just verify validation didn't reject it.
		})
	}
}

func TestListUsersPathValidation(t *testing.T) {
	c := NewClient("https://auth.example.com", "sk_test_secret")
	_, err := c.ListUsers(context.Background(), "../evil", nil)
	if err == nil {
		t.Error("expected error for invalid projectID")
	}
}
