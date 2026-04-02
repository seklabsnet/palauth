package auth

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/palauth/palauth/internal/email"
)

// mockSender records email sends for assertions.
type mockSender struct {
	mu    sync.Mutex
	calls []mockSendCall
}

type mockSendCall struct {
	To       string
	Subject  string
	HTMLBody string
	TextBody string
}

func (m *mockSender) Send(_ context.Context, to, subject, htmlBody, textBody string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockSendCall{
		To:       to,
		Subject:  subject,
		HTMLBody: htmlBody,
		TextBody: textBody,
	})
	return nil
}

func (m *mockSender) getCalls() []mockSendCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]mockSendCall, len(m.calls))
	copy(result, m.calls)
	return result
}

func newTestServiceWithEmail(sender email.Sender, renderer *email.TemplateRenderer) *Service {
	return NewService(nil, nil, nil, nil, nil, nil, nil, sender, renderer, testPepper, nil, testLogger)
}

func TestSendVerificationEmail_LinkMethod(t *testing.T) {
	renderer, err := email.NewTemplateRenderer()
	require.NoError(t, err)

	sender := &mockSender{}
	svc := newTestServiceWithEmail(sender, renderer)

	svc.sendVerificationEmail(context.Background(), "user@example.com", "TestApp", "link", "token123", "")

	calls := sender.getCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "user@example.com", calls[0].To)
	assert.Equal(t, "Verify your email address", calls[0].Subject)
	assert.Contains(t, calls[0].HTMLBody, "TestApp")
	assert.Contains(t, calls[0].HTMLBody, "token123") // link placeholder
	assert.Contains(t, calls[0].TextBody, "TestApp")
	assert.Contains(t, calls[0].TextBody, "token123")
	assert.Contains(t, calls[0].TextBody, "1440") // expiry minutes
}

func TestSendVerificationEmail_CodeMethod(t *testing.T) {
	renderer, err := email.NewTemplateRenderer()
	require.NoError(t, err)

	sender := &mockSender{}
	svc := newTestServiceWithEmail(sender, renderer)

	svc.sendVerificationEmail(context.Background(), "user@example.com", "TestApp", "code", "", "654321")

	calls := sender.getCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "user@example.com", calls[0].To)
	assert.Equal(t, "Your verification code", calls[0].Subject)
	assert.Contains(t, calls[0].HTMLBody, "654321")
	assert.Contains(t, calls[0].HTMLBody, "TestApp")
	assert.Contains(t, calls[0].TextBody, "654321")
}

func TestSendVerificationEmail_OTPMethod(t *testing.T) {
	renderer, err := email.NewTemplateRenderer()
	require.NoError(t, err)

	sender := &mockSender{}
	svc := newTestServiceWithEmail(sender, renderer)

	// "otp" falls through to default (code) case.
	svc.sendVerificationEmail(context.Background(), "user@example.com", "TestApp", "otp", "", "999888")

	calls := sender.getCalls()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].HTMLBody, "999888")
}

func TestSendPasswordResetEmail(t *testing.T) {
	renderer, err := email.NewTemplateRenderer()
	require.NoError(t, err)

	sender := &mockSender{}
	svc := newTestServiceWithEmail(sender, renderer)

	svc.sendPasswordResetEmail(context.Background(), "user@example.com", "SecureApp", "reset-token-xyz")

	calls := sender.getCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "user@example.com", calls[0].To)
	assert.Equal(t, "Reset your password for SecureApp", calls[0].Subject)
	assert.Contains(t, calls[0].HTMLBody, "SecureApp")
	assert.Contains(t, calls[0].HTMLBody, "reset-token-xyz")
	assert.Contains(t, calls[0].TextBody, "SecureApp")
	assert.Contains(t, calls[0].TextBody, "reset-token-xyz")
	assert.Contains(t, calls[0].TextBody, "15") // expiry minutes
}

func TestSendVerificationEmail_NilSender(t *testing.T) {
	renderer, err := email.NewTemplateRenderer()
	require.NoError(t, err)

	svc := newTestServiceWithEmail(nil, renderer)

	// Should not panic with nil sender.
	svc.sendVerificationEmail(context.Background(), "user@example.com", "App", "code", "", "123456")
}

func TestSendVerificationEmail_NilRenderer(t *testing.T) {
	sender := &mockSender{}
	svc := newTestServiceWithEmail(sender, nil)

	// Should not panic with nil renderer.
	svc.sendVerificationEmail(context.Background(), "user@example.com", "App", "link", "token", "")

	// No emails should be sent.
	assert.Empty(t, sender.getCalls())
}

func TestSendPasswordResetEmail_NilSender(t *testing.T) {
	renderer, err := email.NewTemplateRenderer()
	require.NoError(t, err)

	svc := newTestServiceWithEmail(nil, renderer)

	// Should not panic.
	svc.sendPasswordResetEmail(context.Background(), "user@example.com", "App", "token")
}

func TestSendPasswordResetEmail_NilRenderer(t *testing.T) {
	sender := &mockSender{}
	svc := newTestServiceWithEmail(sender, nil)

	// Should not panic.
	svc.sendPasswordResetEmail(context.Background(), "user@example.com", "App", "token")

	assert.Empty(t, sender.getCalls())
}

func TestSendVerificationEmailForResend_NilSender(t *testing.T) {
	svc := newTestServiceWithEmail(nil, nil)

	// Should not panic with nil sender and nil renderer.
	svc.sendVerificationEmailForResend(context.Background(), nil, "prj_test", "App", "code", "", "123456")
}

func TestSendVerificationEmail_BothNil(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, testPepper, nil, testLogger)

	// All three methods should gracefully handle nil sender+renderer.
	svc.sendVerificationEmail(context.Background(), "user@example.com", "App", "code", "", "123456")
	svc.sendPasswordResetEmail(context.Background(), "user@example.com", "App", "token")
	svc.sendVerificationEmailForResend(context.Background(), nil, "prj_test", "App", "code", "", "123456")
}
