package hook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

// Known hook events.
const (
	EventBeforeUserCreate  = "before.user.create"
	EventBeforeLogin       = "before.login"
	EventBeforePasswordReset = "before.password.reset"
	EventBeforeMFAVerify   = "before.mfa.verify"
	EventBeforeSocialLink  = "before.social.link"
	EventBeforeTokenIssue  = "before.token.issue"
	EventBeforeTokenRefresh = "before.token.refresh"
	EventAfterLoginFailed  = "after.login.failed"
	EventAfterSessionRevoke = "after.session.revoke"
)

// ValidEvents is the set of all valid hook event names.
var ValidEvents = map[string]bool{
	EventBeforeUserCreate:   true,
	EventBeforeLogin:        true,
	EventBeforePasswordReset: true,
	EventBeforeMFAVerify:    true,
	EventBeforeSocialLink:   true,
	EventBeforeTokenIssue:   true,
	EventBeforeTokenRefresh: true,
	EventAfterLoginFailed:   true,
	EventAfterSessionRevoke: true,
}

// Errors.
var (
	ErrHookDenied          = errors.New("hook denied the operation")
	ErrHookTimeout         = errors.New("hook timed out")
	ErrHookError           = errors.New("hook returned an error")
	ErrInvalidSignature    = errors.New("invalid hook response signature")
	ErrPrivateURL          = errors.New("hook URL resolves to a private IP address")
	ErrInvalidURL          = errors.New("invalid hook URL")
	ErrHTTPSRequired       = errors.New("hook URL must use HTTPS")
	ErrReplayedWebhook     = errors.New("webhook timestamp outside tolerance window")
)

const (
	maxResponseBodySize       = 1 << 20         // 1 MB
	signingKeyBytes           = 32              // 256-bit HMAC key
	webhookTimestampTolerance = 5 * time.Minute // Standard Webhooks spec: reject timestamps older than 5 minutes
	MinHookTimeoutMs          = 1000            // Minimum hook timeout: 1 second
	MaxHookTimeoutMs          = 30000           // Maximum hook timeout: 30 seconds
)

// UserInfo contains user information for hook payloads.
type UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// ContextInfo contains request context for hook payloads.
type ContextInfo struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// Payload is the request body sent to hook endpoints.
type Payload struct {
	Event          string         `json:"event"`
	User           *UserInfo      `json:"user,omitempty"`
	Context        *ContextInfo   `json:"context,omitempty"`
	ProjectID      string         `json:"project_id"`
	ClientMetadata map[string]any `json:"client_metadata,omitempty"`
}

// Response is the expected response from hook endpoints.
type Response struct {
	Verdict      string         `json:"verdict"` // "allow" or "deny"
	Reason       string         `json:"reason,omitempty"`
	CustomClaims map[string]any `json:"custom_claims,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// Caller is the interface that auth services depend on for hook execution.
type Caller interface {
	ExecuteBlocking(ctx context.Context, projectID, event string, payload Payload) (*Response, error)
	ExecuteAsync(ctx context.Context, projectID, event string, payload Payload)
}

// Engine executes blocking hooks with HMAC signing per Standard Webhooks spec.
type Engine struct {
	db     *pgxpool.Pool
	kek    []byte // for signing key encryption/decryption
	client *http.Client
	logger *slog.Logger
	devMode bool // allows HTTP URLs for local development
}

// NewEngine creates a new hook engine.
func NewEngine(db *pgxpool.Pool, kek []byte, logger *slog.Logger, devMode bool) *Engine {
	return &Engine{
		db:  db,
		kek: kek,
		client: &http.Client{
			// No default timeout — each request uses per-hook timeout via context.
			// SSRF protection at the dialer level prevents DNS rebinding attacks.
			Transport: newSSRFSafeTransport(),
		},
		logger:  logger,
		devMode: devMode,
	}
}

// SetHTTPClient overrides the HTTP client used by the engine.
// Intended for testing only — allows bypassing SSRF transport for httptest servers.
func (e *Engine) SetHTTPClient(client *http.Client) {
	e.client = client
}

// KEK returns the key encryption key used for signing key management.
func (e *Engine) KEK() []byte {
	return e.kek
}

// DevMode returns whether the engine is running in development mode.
func (e *Engine) DevMode() bool {
	return e.devMode
}

// ExecuteBlocking queries enabled hooks for the given project+event and calls them synchronously.
// Returns the merged response from all hooks, or an error if any hook denies or fails.
func (e *Engine) ExecuteBlocking(ctx context.Context, projectID, event string, payload Payload) (*Response, error) {
	q := sqlc.New(e.db)

	hooks, err := q.ListEnabledHooksByProjectEvent(ctx, sqlc.ListEnabledHooksByProjectEventParams{
		ProjectID: projectID,
		Event:     event,
	})
	if err != nil {
		return nil, fmt.Errorf("list hooks: %w", err)
	}

	if len(hooks) == 0 {
		return &Response{Verdict: "allow"}, nil
	}

	payload.Event = event
	payload.ProjectID = projectID

	var mergedResponse Response
	mergedResponse.Verdict = "allow"

	for i := range hooks {
		resp, execErr := e.executeOne(ctx, q, &hooks[i], &payload)
		if execErr != nil {
			// Check failure mode.
			if hooks[i].FailureMode == "allow" {
				e.logger.Warn("hook execution failed, allowing due to failure_mode=allow",
					"hook_id", hooks[i].ID,
					"event", event,
					"error", execErr,
				)
				continue
			}
			return nil, fmt.Errorf("%w: %w", ErrHookError, execErr)
		}

		if resp.Verdict == "deny" {
			return resp, ErrHookDenied
		}

		// Merge custom claims and metadata from allow responses.
		if resp.CustomClaims != nil {
			if mergedResponse.CustomClaims == nil {
				mergedResponse.CustomClaims = make(map[string]any)
			}
			for k, v := range resp.CustomClaims {
				mergedResponse.CustomClaims[k] = v
			}
		}
		if resp.Metadata != nil {
			if mergedResponse.Metadata == nil {
				mergedResponse.Metadata = make(map[string]any)
			}
			for k, v := range resp.Metadata {
				mergedResponse.Metadata[k] = v
			}
		}
	}

	return &mergedResponse, nil
}

// ExecuteAsync fires hooks asynchronously (fire-and-forget for after.* events).
func (e *Engine) ExecuteAsync(ctx context.Context, projectID, event string, payload Payload) {
	go func() { //nolint:gosec // G118: Async hooks intentionally use background context to outlive the request
		// Use a fresh context with a generous timeout for async hooks.
		asyncCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second) //nolint:gosec // G118: intentional
		defer cancel()

		q := sqlc.New(e.db)
		hooks, err := q.ListEnabledHooksByProjectEvent(asyncCtx, sqlc.ListEnabledHooksByProjectEventParams{
			ProjectID: projectID,
			Event:     event,
		})
		if err != nil {
			e.logger.Error("failed to list async hooks", "event", event, "error", err)
			return
		}

		payload.Event = event
		payload.ProjectID = projectID

		for i := range hooks {
			if _, err := e.executeOne(asyncCtx, q, &hooks[i], &payload); err != nil {
				e.logger.Warn("async hook execution failed",
					"hook_id", hooks[i].ID,
					"event", event,
					"error", err,
				)
			}
		}
	}()
}

// executeOne calls a single hook endpoint with HMAC signing and logs the result.
func (e *Engine) executeOne(ctx context.Context, q *sqlc.Queries, hook *sqlc.HookConfig, payload *Payload) (*Response, error) {
	start := time.Now()

	// Serialize payload.
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	// Decrypt signing key.
	signingKeyAAD := []byte("hook-signing-key:" + hook.ProjectID + ":" + hook.ID)
	signingKey, err := crypto.Decrypt(hook.SigningKeyEncrypted, e.kek, signingKeyAAD)
	if err != nil {
		return nil, fmt.Errorf("decrypt signing key: %w", err)
	}

	// Generate webhook-id (Standard Webhooks spec uses msg_ prefix).
	webhookID := fmt.Sprintf("msg_%s", uuid.Must(uuid.NewV7()).String())

	// Timestamp as Unix epoch seconds.
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Create HMAC-SHA256 signature: HMAC-SHA256(key, webhookID.timestamp.body).
	signature := computeSignature(signingKey, webhookID, timestamp, body)

	// Create request with timeout.
	timeoutDuration := time.Duration(hook.TimeoutMs) * time.Millisecond
	reqCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, hook.Url, bytes.NewReader(body))
	if err != nil {
		e.logHookExecution(ctx, q, hook, body, nil, nil, start, "error")
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", webhookID)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", "v1,"+signature)

	// Execute request.
	resp, err := e.client.Do(req)
	if err != nil {
		result := "error"
		if errors.Is(err, context.DeadlineExceeded) {
			result = "timeout"
		}
		e.logHookExecution(ctx, q, hook, body, nil, nil, start, result)

		if result == "timeout" {
			return nil, ErrHookTimeout
		}
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body (limited).
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		e.logHookExecution(ctx, q, hook, body, nil, nil, start, "error")
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Check HTTP status.
	statusCode := int32(resp.StatusCode) //nolint:gosec // HTTP status codes are always small
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		e.logHookExecution(ctx, q, hook, body, respBody, &statusCode, start, "error")
		return nil, fmt.Errorf("hook returned HTTP %d", resp.StatusCode)
	}

	// Verify response signature (bidirectional signing — required).
	respWebhookSig := resp.Header.Get("webhook-signature")
	if respWebhookSig == "" {
		e.logHookExecution(ctx, q, hook, body, respBody, &statusCode, start, "error")
		return nil, ErrInvalidSignature
	}

	respWebhookID := resp.Header.Get("webhook-id")
	respTimestamp := resp.Header.Get("webhook-timestamp")
	if respWebhookID == "" || respTimestamp == "" {
		e.logHookExecution(ctx, q, hook, body, respBody, &statusCode, start, "error")
		return nil, ErrInvalidSignature
	}

	// Replay protection: reject responses with timestamps outside tolerance window.
	if err := validateWebhookTimestamp(respTimestamp); err != nil {
		e.logHookExecution(ctx, q, hook, body, respBody, &statusCode, start, "error")
		return nil, err
	}

	expectedSig := computeSignature(signingKey, respWebhookID, respTimestamp, respBody)
	if !verifySignature(respWebhookSig, expectedSig) {
		e.logHookExecution(ctx, q, hook, body, respBody, &statusCode, start, "error")
		return nil, ErrInvalidSignature
	}

	// Parse response.
	var hookResp Response
	if err := json.Unmarshal(respBody, &hookResp); err != nil {
		e.logHookExecution(ctx, q, hook, body, respBody, &statusCode, start, "error")
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// Determine log result.
	logResult := "allow"
	if hookResp.Verdict == "deny" {
		logResult = "deny"
	}
	e.logHookExecution(ctx, q, hook, body, respBody, &statusCode, start, logResult)

	return &hookResp, nil
}

// logHookExecution records a hook execution in the hook_logs table (best-effort).
// PII fields (email) are stripped from the request body before storage.
func (e *Engine) logHookExecution(ctx context.Context, q *sqlc.Queries, hook *sqlc.HookConfig, reqBody, respBody []byte, respStatus *int32, start time.Time, result string) {
	latency := int32(time.Since(start).Milliseconds()) //nolint:gosec // latency in ms is always small

	sanitizedReqBody := sanitizePayloadForLog(reqBody)

	_, err := q.CreateHookLog(ctx, sqlc.CreateHookLogParams{
		ID:             id.New("hl_"),
		HookConfigID:   hook.ID,
		ProjectID:      hook.ProjectID,
		Event:          hook.Event,
		RequestBody:    sanitizedReqBody,
		ResponseBody:   respBody,
		ResponseStatus: respStatus,
		LatencyMs:      latency,
		Result:         result,
	})
	if err != nil {
		e.logger.Error("failed to log hook execution",
			"hook_id", hook.ID,
			"error", err,
		)
	}
}

// sanitizePayloadForLog strips PII fields from the hook payload before storing in hook_logs.
func sanitizePayloadForLog(body []byte) []byte {
	if len(body) == 0 {
		return body
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return body // can't parse, return as-is
	}

	// Strip PII from user object.
	if user, ok := data["user"].(map[string]any); ok {
		delete(user, "email")
		delete(user, "phone")
		delete(user, "name")
	}

	sanitized, err := json.Marshal(data)
	if err != nil {
		return body
	}
	return sanitized
}

// validateWebhookTimestamp checks that a webhook timestamp is within the tolerance window.
// This prevents replay attacks where old responses are re-sent.
func validateWebhookTimestamp(ts string) error {
	epoch, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrReplayedWebhook
	}
	t := time.Unix(epoch, 0)
	diff := time.Since(t)
	if diff < 0 {
		diff = -diff
	}
	if diff > webhookTimestampTolerance {
		return ErrReplayedWebhook
	}
	return nil
}

// computeSignature creates an HMAC-SHA256 signature per Standard Webhooks spec.
// Format: HMAC-SHA256(key, "webhookID.timestamp.body")
func computeSignature(key []byte, webhookID, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(webhookID))
	mac.Write([]byte("."))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// verifySignature checks if the response signature matches the expected one.
// The webhook-signature header format is "v1,{base64_sig}" and may contain multiple signatures.
func verifySignature(headerValue, expectedSig string) bool {
	parts := strings.Split(headerValue, " ")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "v1,") {
			continue
		}
		sig := strings.TrimPrefix(part, "v1,")
		if hmac.Equal([]byte(sig), []byte(expectedSig)) {
			return true
		}
	}
	return false
}

// GenerateSigningKey generates a new 256-bit signing key and encrypts it.
func GenerateSigningKey(kek []byte, projectID, hookID string) ([]byte, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	aad := []byte("hook-signing-key:" + projectID + ":" + hookID)
	encrypted, err := crypto.Encrypt(key, kek, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}

	return encrypted, nil
}

// ValidateHookURL validates a hook URL for SSRF protection.
func ValidateHookURL(rawURL string, devMode bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ErrInvalidURL
	}

	// Require HTTPS in production (allow HTTP in dev mode for localhost).
	if parsed.Scheme != "https" {
		if !devMode || parsed.Scheme != "http" {
			return ErrHTTPSRequired
		}
	}

	// Validate host is not empty.
	host := parsed.Hostname()
	if host == "" {
		return ErrInvalidURL
	}

	// Resolve hostname and check for private IPs.
	ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		return fmt.Errorf("%w: DNS resolution failed", ErrInvalidURL)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return ErrPrivateURL
		}
	}

	return nil
}

// privateRanges is the list of private/reserved IP ranges for SSRF prevention.
// Initialized once at package load time.
var privateRanges = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("169.254.0.0/16"),  // link-local
	mustParseCIDR("0.0.0.0/8"),       // current network
	mustParseCIDR("::1/128"),          // IPv6 loopback
	mustParseCIDR("fc00::/7"),         // IPv6 unique local
	mustParseCIDR("fe80::/10"),        // IPv6 link-local
}

// isPrivateIP checks if an IP address is in a private/reserved range.
func isPrivateIP(ip net.IP) bool {
	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR: %s", cidr))
	}
	return network
}

// newSSRFSafeTransport creates an http.Transport that blocks connections to private IPs
// at the dialer level, preventing DNS rebinding attacks (TOCTOU between DNS lookup and connect).
func newSSRFSafeTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   ssrfDialerControl,
		}).DialContext,
	}
}

// ssrfDialerControl is a net.Dialer.Control function that blocks connections to private IPs.
// This runs after DNS resolution at the actual connection level, eliminating DNS rebinding attacks.
func ssrfDialerControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip != nil && isPrivateIP(ip) {
		return ErrPrivateURL
	}
	return nil
}
