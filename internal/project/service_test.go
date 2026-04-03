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

func TestEncryptDecryptSocialSecrets(t *testing.T) {
	// 32-byte test KEK.
	kek := []byte("01234567890123456789012345678901")
	svc := &Service{kek: kek}

	cfg := &Config{
		SocialProviders: map[string]SocialProviderConfig{
			"google": {
				ClientID:     "google-id",
				ClientSecret: "google-secret",
				Enabled:      true,
			},
			"apple": {
				ClientID:   "apple-id",
				PrivateKey: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
				TeamID:     "TEAM123",
				KeyID:      "KEY456",
				Enabled:    true,
			},
		},
	}

	projectID := "prj_test_encrypt"

	// Encrypt.
	err := svc.encryptSocialSecrets(cfg, projectID)
	require.NoError(t, err)

	// After encryption, secrets should be different (base64-encoded ciphertext).
	assert.NotEqual(t, "google-secret", cfg.SocialProviders["google"].ClientSecret)
	assert.NotEqual(t, "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----", cfg.SocialProviders["apple"].PrivateKey)

	// Non-secret fields should be unchanged.
	assert.Equal(t, "google-id", cfg.SocialProviders["google"].ClientID)
	assert.Equal(t, "apple-id", cfg.SocialProviders["apple"].ClientID)
	assert.Equal(t, "TEAM123", cfg.SocialProviders["apple"].TeamID)
	assert.True(t, cfg.SocialProviders["google"].Enabled)

	// Decrypt.
	err = svc.decryptSocialSecrets(cfg, projectID)
	require.NoError(t, err)

	// After decryption, secrets should be restored.
	assert.Equal(t, "google-secret", cfg.SocialProviders["google"].ClientSecret)
	assert.Equal(t, "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----", cfg.SocialProviders["apple"].PrivateKey)
}

func TestEncryptSocialSecrets_NilKEK(t *testing.T) {
	svc := &Service{kek: nil}
	cfg := &Config{
		SocialProviders: map[string]SocialProviderConfig{
			"google": {ClientSecret: "secret"},
		},
	}

	// With nil KEK, encryption should be a no-op.
	err := svc.encryptSocialSecrets(cfg, "prj_test")
	require.NoError(t, err)
	assert.Equal(t, "secret", cfg.SocialProviders["google"].ClientSecret)
}

func TestEncryptSocialSecrets_NilProviders(t *testing.T) {
	kek := []byte("01234567890123456789012345678901")
	svc := &Service{kek: kek}
	cfg := &Config{}

	// With nil social providers, should be a no-op.
	err := svc.encryptSocialSecrets(cfg, "prj_test")
	require.NoError(t, err)
}

func TestDecryptSocialSecrets_WrongKEK(t *testing.T) {
	kek1 := []byte("01234567890123456789012345678901")
	kek2 := []byte("98765432109876543210987654321098")
	svc1 := &Service{kek: kek1}
	svc2 := &Service{kek: kek2}

	cfg := &Config{
		SocialProviders: map[string]SocialProviderConfig{
			"google": {ClientSecret: "secret"},
		},
	}

	projectID := "prj_test"
	err := svc1.encryptSocialSecrets(cfg, projectID)
	require.NoError(t, err)

	// Decrypting with wrong KEK should fail.
	err = svc2.decryptSocialSecrets(cfg, projectID)
	assert.Error(t, err)
}
