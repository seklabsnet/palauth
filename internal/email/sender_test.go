package email

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func TestNewSender_Console(t *testing.T) {
	cfg := &Config{Provider: "console"}
	sender, err := NewSender(cfg, testLogger)
	require.NoError(t, err)
	require.NotNil(t, sender)
	_, ok := sender.(*ConsoleSender)
	assert.True(t, ok, "should return ConsoleSender")
}

func TestNewSender_ConsoleDefault(t *testing.T) {
	cfg := &Config{Provider: ""}
	sender, err := NewSender(cfg, testLogger)
	require.NoError(t, err)
	require.NotNil(t, sender)
	_, ok := sender.(*ConsoleSender)
	assert.True(t, ok, "empty provider should default to ConsoleSender")
}

func TestNewSender_SMTP(t *testing.T) {
	cfg := &Config{
		Provider: "smtp",
		From:     "noreply@example.com",
		SMTP: SMTPConfig{
			Host: "smtp.example.com",
			Port: 587,
		},
	}
	sender, err := NewSender(cfg, testLogger)
	require.NoError(t, err)
	require.NotNil(t, sender)
	_, ok := sender.(*SMTPSender)
	assert.True(t, ok, "should return SMTPSender")
}

func TestNewSender_SMTP_MissingHost(t *testing.T) {
	cfg := &Config{
		Provider: "smtp",
		From:     "noreply@example.com",
		SMTP: SMTPConfig{
			Port: 587,
		},
	}
	_, err := NewSender(cfg, testLogger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "host")
}

func TestNewSender_SMTP_MissingPort(t *testing.T) {
	cfg := &Config{
		Provider: "smtp",
		From:     "noreply@example.com",
		SMTP: SMTPConfig{
			Host: "smtp.example.com",
		},
	}
	_, err := NewSender(cfg, testLogger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

func TestNewSender_SMTP_MissingFrom(t *testing.T) {
	cfg := &Config{
		Provider: "smtp",
		SMTP: SMTPConfig{
			Host: "smtp.example.com",
			Port: 587,
		},
	}
	_, err := NewSender(cfg, testLogger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "from")
}

func TestNewSender_UnsupportedProvider(t *testing.T) {
	cfg := &Config{Provider: "sendgrid"}
	_, err := NewSender(cfg, testLogger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}
