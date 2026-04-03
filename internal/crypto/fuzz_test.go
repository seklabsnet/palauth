package crypto

import (
	"bytes"
	"testing"
)

func FuzzValidatePassword(f *testing.F) {
	f.Add("short")
	f.Add("exactly15chars!")
	f.Add("this-is-a-valid-password")
	f.Add("")
	f.Add("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 67 chars

	f.Fuzz(func(t *testing.T, password string) {
		// Should never panic.
		_ = ValidatePassword(password)
	})
}

func FuzzDeterministicHash(f *testing.F) {
	f.Add("test@example.com", []byte("key-material-32-bytes-long-ok!!"))
	f.Add("", []byte("key"))
	f.Add("hello", []byte{}) // Empty key: HMAC-SHA256 accepts any key length; tests zero-length edge case

	f.Fuzz(func(t *testing.T, input string, key []byte) {
		h1 := DeterministicHash(input, key)
		h2 := DeterministicHash(input, key)
		if h1 != h2 {
			t.Errorf("DeterministicHash not deterministic for input %q", input)
		}
	})
}

func FuzzEncryptDecryptRoundtrip(f *testing.F) {
	f.Add([]byte("hello world"), []byte("0123456789abcdef0123456789abcdef"), []byte("aad"))
	f.Add([]byte{}, []byte("0123456789abcdef0123456789abcdef"), []byte{})

	f.Fuzz(func(t *testing.T, plaintext, key, aad []byte) {
		// Key must be exactly 32 bytes for AES-256.
		if len(key) != 32 {
			return
		}
		ciphertext, err := Encrypt(plaintext, key, aad)
		if err != nil {
			return // invalid input is fine
		}
		decrypted, err := Decrypt(ciphertext, key, aad)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("roundtrip mismatch: got %q want %q", decrypted, plaintext)
		}
	})
}
