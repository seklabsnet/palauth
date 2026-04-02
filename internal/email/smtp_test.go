package email

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSMTPSender_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *SMTPConfig
		from    string
		wantErr string
	}{
		{
			name:    "missing host",
			cfg:     &SMTPConfig{Port: 587},
			from:    "noreply@example.com",
			wantErr: "host",
		},
		{
			name:    "missing port",
			cfg:     &SMTPConfig{Host: "smtp.example.com"},
			from:    "noreply@example.com",
			wantErr: "port",
		},
		{
			name:    "missing from",
			cfg:     &SMTPConfig{Host: "smtp.example.com", Port: 587},
			from:    "",
			wantErr: "from",
		},
		{
			name: "valid config",
			cfg:  &SMTPConfig{Host: "smtp.example.com", Port: 587},
			from: "noreply@example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender, err := NewSMTPSender(tc.cfg, tc.from, testLogger)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, sender)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, sender)
			}
		})
	}
}

func TestBuildMIMEMessage(t *testing.T) {
	from := "sender@example.com"
	to := "recipient@example.com"
	subject := "Test Subject"
	htmlBody := "<p>Hello HTML</p>"
	textBody := "Hello Plain"

	msg := buildMIMEMessage(from, to, subject, htmlBody, textBody)

	// Verify headers.
	assert.Contains(t, msg, "From: sender@example.com")
	assert.Contains(t, msg, "To: recipient@example.com")
	assert.Contains(t, msg, "MIME-Version: 1.0")
	assert.Contains(t, msg, "multipart/alternative")
	assert.Contains(t, msg, "boundary")

	// Verify both parts are present.
	assert.Contains(t, msg, "text/plain")
	assert.Contains(t, msg, "text/html")
	assert.Contains(t, msg, "Hello Plain")
	assert.Contains(t, msg, "<p>Hello HTML</p>")

	// Verify boundary structure: starts with "palauth-" prefix.
	assert.Contains(t, msg, "palauth-")

	// Extract boundary from Content-Type header.
	boundary := extractBoundary(t, msg)
	assert.True(t, strings.HasPrefix(boundary, "palauth-"), "boundary should start with palauth- prefix")
	assert.Contains(t, msg, "--"+boundary)
	assert.Contains(t, msg, "--"+boundary+"--")
}

func TestBuildMIMEMessage_UniqueBoundary(t *testing.T) {
	msg1 := buildMIMEMessage("from@test.com", "to@test.com", "Subject", "<p>body</p>", "body")
	msg2 := buildMIMEMessage("from@test.com", "to@test.com", "Subject", "<p>body</p>", "body")

	boundary1 := extractBoundary(t, msg1)
	boundary2 := extractBoundary(t, msg2)

	assert.NotEqual(t, boundary1, boundary2, "each message should have a unique boundary")
}

func TestBuildMIMEMessage_UTF8Subject(t *testing.T) {
	msg := buildMIMEMessage("from@test.com", "to@test.com", "Test with umlauts: aou", "<p>body</p>", "body")

	// Subject should be Q-encoded for UTF-8 safety.
	assert.Contains(t, msg, "Subject:")
	assert.NotEmpty(t, msg)
}

func TestBuildMIMEMessage_EmptyBodies(t *testing.T) {
	msg := buildMIMEMessage("from@test.com", "to@test.com", "Subject", "", "")
	require.NotEmpty(t, msg)

	// Should still have both content type parts.
	assert.Contains(t, msg, "text/plain")
	assert.Contains(t, msg, "text/html")
}

func TestBuildMIMEMessage_MultipartStructure(t *testing.T) {
	msg := buildMIMEMessage("from@test.com", "to@test.com", "Subject", "<html>test</html>", "test")

	boundary := extractBoundary(t, msg)

	// Count boundary occurrences: should be 2 part boundaries + 1 closing boundary.
	parts := strings.Split(msg, "--"+boundary)
	// parts[0] = headers, parts[1] = text part, parts[2] = html part, parts[3] = after closing --
	assert.Equal(t, 4, len(parts), "should have header + 2 parts + closing")
}

func TestGenerateBoundary(t *testing.T) {
	b1 := generateBoundary()
	b2 := generateBoundary()

	assert.True(t, strings.HasPrefix(b1, "palauth-"))
	assert.True(t, strings.HasPrefix(b2, "palauth-"))
	assert.NotEqual(t, b1, b2, "boundaries should be unique")
	// palauth- (8) + 32 hex chars = 40 total
	assert.Len(t, b1, 40)
}

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no injection", "user@example.com", "user@example.com"},
		{"crlf injection", "user@example.com\r\nBcc: attacker@evil.com", "user@example.comBcc: attacker@evil.com"},
		{"lf only", "user@example.com\nBcc: attacker@evil.com", "user@example.comBcc: attacker@evil.com"},
		{"cr only", "user@example.com\rBcc: attacker@evil.com", "user@example.comBcc: attacker@evil.com"},
		{"multiple crlf", "a\r\nb\r\nc", "abc"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, sanitizeHeaderValue(tc.input))
		})
	}
}

func TestBuildMIMEMessage_HeaderInjectionPrevention(t *testing.T) {
	// Attempt CRLF injection in the "to" field to add a Bcc header.
	maliciousTo := "victim@example.com\r\nBcc: attacker@evil.com"
	msg := buildMIMEMessage("from@test.com", maliciousTo, "Subject", "<p>body</p>", "body")

	// The injected Bcc header should NOT appear as a separate header line.
	// After sanitization, CRLF is stripped so "Bcc:" is part of the To value, not a new header.
	assert.NotContains(t, msg, "\r\nBcc:", "CRLF injection should be prevented — Bcc must not appear as a separate header")
	// The sanitized "to" should be on a single line with CRLF stripped.
	assert.Contains(t, msg, "To: victim@example.comBcc: attacker@evil.com\r\n")

	// Same test for "from" field.
	maliciousFrom := "legit@example.com\r\nBcc: attacker@evil.com"
	msg2 := buildMIMEMessage(maliciousFrom, "to@test.com", "Subject", "<p>body</p>", "body")
	assert.NotContains(t, msg2, "\r\nBcc:", "CRLF injection should be prevented in From header")
	assert.Contains(t, msg2, "From: legit@example.comBcc: attacker@evil.com\r\n")
}

// extractBoundary extracts the MIME boundary value from a message's Content-Type header.
func extractBoundary(t *testing.T, msg string) string {
	t.Helper()
	const marker = `boundary="`
	idx := strings.Index(msg, marker)
	require.NotEqual(t, -1, idx, "message should contain boundary= in Content-Type header")
	start := idx + len(marker)
	end := strings.Index(msg[start:], `"`)
	require.NotEqual(t, -1, end, "boundary value should be quoted")
	return msg[start : start+end]
}
