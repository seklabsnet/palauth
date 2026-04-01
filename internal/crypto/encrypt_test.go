package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("hello, world! this is sensitive data.")

	ciphertext, err := Encrypt(plaintext, key, nil)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext)

	decrypted, err := Decrypt(ciphertext, key, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncrypt_RandomNonce(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("same plaintext")

	ct1, err := Encrypt(plaintext, key, nil)
	require.NoError(t, err)

	ct2, err := Encrypt(plaintext, key, nil)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(ct1, ct2), "same plaintext must produce different ciphertexts (random nonce)")
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, err := GenerateKey()
	require.NoError(t, err)
	key2, err := GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("secret data")
	ciphertext, err := Encrypt(plaintext, key1, nil)
	require.NoError(t, err)

	_, err = Decrypt(ciphertext, key2, nil)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	tests := []struct {
		name   string
		keyLen int
	}{
		{"too short 16", 16},
		{"too short 24", 24},
		{"too long 48", 48},
		{"empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := Encrypt([]byte("data"), key, nil)
			assert.ErrorIs(t, err, ErrInvalidKeyLength)
		})
	}
}

func TestDecrypt_InvalidKeyLength(t *testing.T) {
	key := make([]byte, 16)
	_, err := Decrypt([]byte("some-ciphertext-data-here-1234567890"), key, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyLength)
}

func TestDecrypt_CiphertextTooShort(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	_, err = Decrypt([]byte("short"), key, nil)
	assert.ErrorIs(t, err, ErrCiphertextTooShort)
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("original data")
	ciphertext, err := Encrypt(plaintext, key, nil)
	require.NoError(t, err)

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xff

	_, err = Decrypt(ciphertext, key, nil)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestGenerateKey_Length(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestGenerateKey_Unique(t *testing.T) {
	key1, err := GenerateKey()
	require.NoError(t, err)
	key2, err := GenerateKey()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(key1, key2), "generated keys must be unique")
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	ciphertext, err := Encrypt([]byte{}, key, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt(ciphertext, key, nil)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestEncryptDecrypt_LargePlaintext(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	plaintext := bytes.Repeat([]byte("x"), 1024*1024) // 1MB
	ciphertext, err := Encrypt(plaintext, key, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt(ciphertext, key, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecrypt_WithAAD(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("sensitive user data")
	aad := []byte("usr_0192f5e0-7c1a-7b3e-8d4f-1a2b3c4d5e6f")

	ciphertext, err := Encrypt(plaintext, key, aad)
	require.NoError(t, err)

	// Decrypt with correct AAD
	decrypted, err := Decrypt(ciphertext, key, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecrypt_WrongAAD(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("sensitive user data")
	aad := []byte("usr_correct-id")

	ciphertext, err := Encrypt(plaintext, key, aad)
	require.NoError(t, err)

	// Decrypt with wrong AAD must fail
	_, err = Decrypt(ciphertext, key, []byte("usr_wrong-id"))
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecrypt_MissingAAD(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	plaintext := []byte("data")
	aad := []byte("context")

	ciphertext, err := Encrypt(plaintext, key, aad)
	require.NoError(t, err)

	// Decrypt without AAD when encrypted with AAD must fail
	_, err = Decrypt(ciphertext, key, nil)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

// Property-based tests using rapid

func TestRapid_EncryptDecryptRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key, err := GenerateKey()
		require.NoError(t, err)

		plaintext := rapid.SliceOfN(rapid.Byte(), 0, 4096).Draw(t, "plaintext")

		ciphertext, err := Encrypt(plaintext, key, nil)
		require.NoError(t, err)

		decrypted, err := Decrypt(ciphertext, key, nil)
		require.NoError(t, err)
		// GCM Open returns nil for empty plaintext; compare content not slice headers
		assert.Equal(t, len(plaintext), len(decrypted))
		assert.True(t, bytes.Equal(plaintext, decrypted))
	})
}

func TestRapid_EncryptDecryptWithAAD(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key, err := GenerateKey()
		require.NoError(t, err)

		plaintext := rapid.SliceOfN(rapid.Byte(), 0, 1024).Draw(t, "plaintext")
		aad := rapid.SliceOfN(rapid.Byte(), 1, 256).Draw(t, "aad")

		ciphertext, err := Encrypt(plaintext, key, aad)
		require.NoError(t, err)

		decrypted, err := Decrypt(ciphertext, key, aad)
		require.NoError(t, err)
		assert.Equal(t, len(plaintext), len(decrypted))
		assert.True(t, bytes.Equal(plaintext, decrypted))
	})
}
