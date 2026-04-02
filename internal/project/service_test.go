package project

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "code", cfg.EmailVerificationMethod)
	assert.Equal(t, 3600, cfg.EmailVerificationTTL)
	assert.Equal(t, 15, cfg.PasswordMinLength)
	assert.Equal(t, 64, cfg.PasswordMaxLength)
	assert.False(t, cfg.MFAEnabled)
	assert.Equal(t, 0, cfg.SessionIdleTimeout)
	assert.Equal(t, 2592000, cfg.SessionAbsTimeout)
}

func TestDefaultConfigJSON(t *testing.T) {
	cfg := DefaultConfig()
	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var parsed Config
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, cfg, parsed)
}

func TestToProject_EmptyConfig(t *testing.T) {
	// Verify that an empty JSON object deserializes to zero-value Config.
	data := []byte(`{}`)
	var cfg Config
	err := json.Unmarshal(data, &cfg)
	require.NoError(t, err)
	assert.Equal(t, "", cfg.EmailVerificationMethod)
}
