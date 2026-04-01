package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_MissingPepper(t *testing.T) {
	_, err := Load("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PALAUTH_PEPPER")
}

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("PALAUTH_AUTH_PEPPER", "test-pepper-at-least-32-bytes!!!")

	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, 3000, cfg.Server.Port)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 15, cfg.Auth.PasswordMinLen)
	assert.Equal(t, 64, cfg.Auth.PasswordMaxLen)
	assert.Equal(t, 1800, cfg.Auth.AccessTokenTTL)
	assert.Equal(t, 10, cfg.Auth.LockoutThreshold)
	assert.Equal(t, 5, cfg.Auth.MFALockout)
	assert.Equal(t, 90, cfg.Auth.InactiveDays)
	assert.Equal(t, "console", cfg.Email.Provider)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("PALAUTH_AUTH_PEPPER", "test-pepper-at-least-32-bytes!!!")
	t.Setenv("PALAUTH_SERVER_PORT", "8080")
	t.Setenv("PALAUTH_LOG_LEVEL", "debug")

	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "debug", cfg.Log.Level)
}

func TestLoad_YAMLConfig(t *testing.T) {
	content := []byte(`
server:
  port: 9090
auth:
  pepper: "yaml-pepper-at-least-32-bytes!!!"
log:
  level: warn
`)
	f, err := os.CreateTemp("", "palauth-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.Write(content)
	require.NoError(t, err)
	f.Close()

	cfg, err := Load(f.Name())
	require.NoError(t, err)

	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "warn", cfg.Log.Level)
}

func TestLoad_EnvOverridesYAML(t *testing.T) {
	content := []byte(`
server:
  port: 9090
auth:
  pepper: "yaml-pepper-at-least-32-bytes!!!"
`)
	f, err := os.CreateTemp("", "palauth-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.Write(content)
	require.NoError(t, err)
	f.Close()

	t.Setenv("PALAUTH_SERVER_PORT", "4000")

	cfg, err := Load(f.Name())
	require.NoError(t, err)

	assert.Equal(t, 4000, cfg.Server.Port)
}

func TestValidate_InvalidPort(t *testing.T) {
	cfg := &Config{
		Auth:   AuthConfig{Pepper: "test-pepper-at-least-32-bytes!!!"},
		Server: ServerConfig{Port: 99999},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid server port")
}

func TestValidate_PepperTooShort(t *testing.T) {
	cfg := &Config{
		Auth:   AuthConfig{Pepper: "short"},
		Server: ServerConfig{Port: 3000},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PALAUTH_PEPPER must be at least 32 bytes")
}

func TestValidate_CORSWildcardRejected(t *testing.T) {
	cfg := &Config{
		Auth:   AuthConfig{Pepper: "test-pepper-at-least-32-bytes!!!"},
		Server: ServerConfig{Port: 3000, CORSAllowedOrigins: []string{"*"}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard CORS origin")
}

func TestValidate_CORSWildcardAmongOthers(t *testing.T) {
	cfg := &Config{
		Auth:   AuthConfig{Pepper: "test-pepper-at-least-32-bytes!!!"},
		Server: ServerConfig{Port: 3000, CORSAllowedOrigins: []string{"http://localhost:3001", "*"}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard CORS origin")
}
