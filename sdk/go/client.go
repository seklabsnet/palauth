package palauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// validatePathParam ensures a path parameter does not contain path traversal characters.
func validatePathParam(name, value string) error {
	if strings.ContainsAny(value, "/.%") {
		return fmt.Errorf("palauth: invalid %s: must not contain path separators", name)
	}
	return nil
}

// APIError is returned when the PalAuth server returns a non-2xx status.
type APIError struct {
	ErrorResponse
}

func (e *APIError) Error() string {
	return fmt.Sprintf("palauth: %s: %s (status %d)", e.ErrorResponse.Error, e.Description, e.Status)
}

// Client is a PalAuth API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientOption configures the client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(client *Client) {
		client.httpClient = c
	}
}

// NewClient creates a new PalAuth client.
func NewClient(baseURL, apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SignUp registers a new user.
func (c *Client) SignUp(ctx context.Context, email, password string) (*AuthResult, error) {
	var result AuthResult
	err := c.post(ctx, "/auth/signup", map[string]string{
		"email":    email,
		"password": password,
	}, &result)
	return &result, err
}

// SignIn authenticates with email and password.
func (c *Client) SignIn(ctx context.Context, email, password string) (*AuthResult, error) {
	var result AuthResult
	err := c.post(ctx, "/auth/login", map[string]string{
		"email":    email,
		"password": password,
	}, &result)
	return &result, err
}

// RefreshToken refreshes an access token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	var result TokenResponse
	err := c.post(ctx, "/auth/token/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, &result)
	return &result, err
}

// VerifyToken introspects an access token.
func (c *Client) VerifyToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	var result IntrospectionResponse
	err := c.post(ctx, "/oauth/introspect", map[string]string{
		"token": token,
	}, &result)
	return &result, err
}

// GetUser retrieves a user by ID.
func (c *Client) GetUser(ctx context.Context, projectID, userID string) (*UserDetail, error) {
	if err := validatePathParam("projectID", projectID); err != nil {
		return nil, err
	}
	if err := validatePathParam("userID", userID); err != nil {
		return nil, err
	}
	var result UserDetail
	err := c.get(ctx, fmt.Sprintf("/admin/projects/%s/users/%s", projectID, userID), &result)
	return &result, err
}

// ListUsers lists users in a project.
func (c *Client) ListUsers(ctx context.Context, projectID string, opts *UserListOptions) (*UserListResult, error) {
	if err := validatePathParam("projectID", projectID); err != nil {
		return nil, err
	}
	params := url.Values{}
	if opts != nil {
		if opts.Limit > 0 {
			params.Set("limit", strconv.Itoa(opts.Limit))
		}
		if opts.CursorCreatedAt != "" {
			params.Set("cursor_created_at", opts.CursorCreatedAt)
		}
		if opts.CursorID != "" {
			params.Set("cursor_id", opts.CursorID)
		}
		if opts.Banned != nil {
			params.Set("banned", strconv.FormatBool(*opts.Banned))
		}
		if opts.Email != "" {
			params.Set("email", opts.Email)
		}
	}

	path := fmt.Sprintf("/admin/projects/%s/users", projectID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var result UserListResult
	err := c.get(ctx, path, &result)
	return &result, err
}

// RevokeToken revokes a token (RFC 7009).
func (c *Client) RevokeToken(ctx context.Context, token, tokenTypeHint string) error {
	body := map[string]string{"token": token}
	if tokenTypeHint != "" {
		body["token_type_hint"] = tokenTypeHint
	}
	return c.post(ctx, "/oauth/revoke", body, nil)
}

func (c *Client) post(ctx context.Context, path string, body, result interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	return c.do(req, result)
}

func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	return c.do(req, result)
}

func (c *Client) do(req *http.Request, result interface{}) error {
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // baseURL is intentionally user-configured in SDK client
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
			return &APIError{ErrorResponse{
				Error:       "unknown_error",
				Description: fmt.Sprintf("HTTP %d", resp.StatusCode),
				Status:      resp.StatusCode,
			}}
		}
		return &APIError{errResp}
	}

	if result != nil {
		if decErr := json.NewDecoder(resp.Body).Decode(result); decErr != nil {
			return fmt.Errorf("decode response: %w", decErr)
		}
	}

	return nil
}
