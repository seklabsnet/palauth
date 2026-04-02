package email

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsoleSender_Send(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sender := NewConsoleSender(logger)
	err := sender.Send(context.Background(), "user@example.com", "Test Subject", "<p>HTML</p>", "Plain text")
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "user@example.com")
	assert.Contains(t, output, "Test Subject")
	assert.Contains(t, output, "Plain text")
	assert.Contains(t, output, "email sent (console)")
}

func TestConsoleSender_Send_TruncatesLongBody(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sender := NewConsoleSender(logger)

	// Create a body longer than 200 chars.
	longBody := make([]byte, 300)
	for i := range longBody {
		longBody[i] = 'a'
	}

	err := sender.Send(context.Background(), "user@example.com", "Subject", "<p>HTML</p>", string(longBody))
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "...")
}

func TestConsoleSender_AlwaysReturnsNil(t *testing.T) {
	sender := NewConsoleSender(testLogger)

	// All calls should succeed regardless of input.
	tests := []struct {
		name    string
		to      string
		subject string
	}{
		{"empty to", "", "Subject"},
		{"empty subject", "user@example.com", ""},
		{"empty everything", "", ""},
		{"normal", "user@example.com", "Hello"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sender.Send(context.Background(), tc.to, tc.subject, "", "")
			assert.NoError(t, err)
		})
	}
}
