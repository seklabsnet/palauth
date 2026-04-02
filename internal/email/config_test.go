package email

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := &Config{}
	assert.Empty(t, cfg.Provider)
	assert.Empty(t, cfg.From)
	assert.Empty(t, cfg.SMTP.Host)
	assert.Zero(t, cfg.SMTP.Port)
}

func TestConfig_Fields(t *testing.T) {
	cfg := &Config{
		Provider: "smtp",
		From:     "noreply@example.com",
		SMTP: SMTPConfig{
			Host:     "smtp.example.com",
			Port:     587,
			Username: "user",
			Password: "pass",
		},
	}

	assert.Equal(t, "smtp", cfg.Provider)
	assert.Equal(t, "noreply@example.com", cfg.From)
	assert.Equal(t, "smtp.example.com", cfg.SMTP.Host)
	assert.Equal(t, 587, cfg.SMTP.Port)
	assert.Equal(t, "user", cfg.SMTP.Username)
	assert.Equal(t, "pass", cfg.SMTP.Password)
}
