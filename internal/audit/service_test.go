package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeEventHash_Deterministic(t *testing.T) {
	input := computeHashInput{
		EventType:         "auth.login.success",
		ProjectID:         "prj_123",
		ActorEncrypted:    "abcdef0123456789",
		TargetType:        "user",
		TargetID:          "usr_456",
		Result:            "success",
		AuthMethod:        "password",
		MetadataEncrypted: "fedcba9876543210",
		PrevHash:          "",
	}

	hash1, err := computeEventHash(input, nil)
	require.NoError(t, err)

	hash2, err := computeEventHash(input, nil)
	require.NoError(t, err)

	assert.NotEmpty(t, hash1)
	assert.Equal(t, hash1, hash2)
}

func TestComputeEventHash_WithPrevHash(t *testing.T) {
	input := computeHashInput{
		EventType:         "auth.login.success",
		ProjectID:         "prj_123",
		ActorEncrypted:    "abcdef",
		TargetType:        "",
		TargetID:          "",
		Result:            "success",
		AuthMethod:        "",
		MetadataEncrypted: "fedcba",
		PrevHash:          "abc123",
	}

	prev := "abc123"
	hashWithPrev, err := computeEventHash(input, &prev)
	require.NoError(t, err)

	hashNoPrev, err := computeEventHash(input, nil)
	require.NoError(t, err)

	assert.NotEqual(t, hashWithPrev, hashNoPrev, "prev_hash should affect the event hash")
}

func TestComputeEventHash_ManualVerification(t *testing.T) {
	input := computeHashInput{
		EventType:         "auth.signup",
		ProjectID:         "prj_test",
		ActorEncrypted:    "encrypted_actor",
		TargetType:        "user",
		TargetID:          "usr_new",
		Result:            "success",
		AuthMethod:        "password",
		MetadataEncrypted: "encrypted_meta",
		PrevHash:          "",
	}

	canonical, err := CanonicalJSON(input)
	require.NoError(t, err)

	h := sha256.New()
	h.Write(canonical)
	expected := hex.EncodeToString(h.Sum(nil))

	actual, err := computeEventHash(input, nil)
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestComputeEventHash_ChainConsistency(t *testing.T) {
	// Simulate a chain of 3 events.
	event1Input := computeHashInput{
		EventType:         "auth.signup",
		ProjectID:         "prj_1",
		ActorEncrypted:    "actor1",
		Result:            "success",
		MetadataEncrypted: "meta1",
	}
	hash1, err := computeEventHash(event1Input, nil)
	require.NoError(t, err)
	require.NotEmpty(t, hash1)

	event2Input := computeHashInput{
		EventType:         "auth.login.success",
		ProjectID:         "prj_1",
		ActorEncrypted:    "actor2",
		Result:            "success",
		MetadataEncrypted: "meta2",
		PrevHash:          hash1,
	}
	hash2, err := computeEventHash(event2Input, &hash1)
	require.NoError(t, err)
	require.NotEmpty(t, hash2)

	event3Input := computeHashInput{
		EventType:         "auth.logout",
		ProjectID:         "prj_1",
		ActorEncrypted:    "actor3",
		Result:            "success",
		MetadataEncrypted: "meta3",
		PrevHash:          hash2,
	}
	hash3, err := computeEventHash(event3Input, &hash2)
	require.NoError(t, err)
	require.NotEmpty(t, hash3)

	// Verify the chain: re-compute each hash and confirm consistency.
	reHash1, err := computeEventHash(event1Input, nil)
	require.NoError(t, err)
	assert.Equal(t, hash1, reHash1)

	reHash2, err := computeEventHash(event2Input, &reHash1)
	require.NoError(t, err)
	assert.Equal(t, hash2, reHash2)

	reHash3, err := computeEventHash(event3Input, &reHash2)
	require.NoError(t, err)
	assert.Equal(t, hash3, reHash3)

	// If we tamper with event2, hash2 changes and hash3 no longer matches.
	tamperedInput := event2Input
	tamperedInput.Result = "failure"
	tamperedHash2, err := computeEventHash(tamperedInput, &hash1)
	require.NoError(t, err)
	assert.NotEqual(t, hash2, tamperedHash2)
}

func TestFrameWithUserID(t *testing.T) {
	tests := []struct {
		name       string
		userID     string
		ciphertext []byte
	}{
		{"normal user", "usr_abc123", []byte("encrypted-data")},
		{"empty user", "", []byte("data")},
		{"system user", "system", []byte("sys-data")},
		{"long user id", "usr_0192f5e0-7c1a-7b3e-8d4f-1a2b3c4d5e6f", []byte("long-data")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			framed := frameWithUserID(tt.userID, tt.ciphertext)

			extractedUID, extractedCT, err := extractUserIDAndCiphertext(framed)
			require.NoError(t, err)
			assert.Equal(t, tt.userID, extractedUID)
			assert.Equal(t, tt.ciphertext, extractedCT)
		})
	}
}

func TestExtractUserIDAndCiphertext_TooShort(t *testing.T) {
	_, _, err := extractUserIDAndCiphertext([]byte{0x00})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestExtractUserIDAndCiphertext_Truncated(t *testing.T) {
	// Claim userID is 100 bytes but only provide 2 bytes header.
	data := []byte{0x00, 0x64} // length = 100, but no data
	_, _, err := extractUserIDAndCiphertext(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated")
}

func TestNewService(t *testing.T) {
	kek := make([]byte, 32)
	svc := NewService(nil, kek, nil)
	assert.NotNil(t, svc)
}

func TestValidation(t *testing.T) {
	t.Run("empty project_id", func(t *testing.T) {
		assert.Equal(t, "project_id is required", ErrProjectIDRequired.Error())
	})
	t.Run("empty event_type", func(t *testing.T) {
		assert.Equal(t, "event_type is required", ErrEventTypeRequired.Error())
	})
	t.Run("empty result", func(t *testing.T) {
		assert.Equal(t, "result is required", ErrResultRequired.Error())
	})
}

func TestDerefStr(t *testing.T) {
	tests := []struct {
		name     string
		input    *string
		expected string
	}{
		{"nil", nil, ""},
		{"empty", strPtr(""), ""},
		{"value", strPtr("hello"), "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, derefStr(tt.input))
		})
	}
}

func TestTargetTypeStr(t *testing.T) {
	assert.Equal(t, "", targetTypeStr(nil))
	assert.Equal(t, "user", targetTypeStr(&TargetInfo{Type: "user", ID: "123"}))
}

func TestTargetIDStr(t *testing.T) {
	assert.Equal(t, "", targetIDStr(nil))
	assert.Equal(t, "123", targetIDStr(&TargetInfo{Type: "user", ID: "123"}))
}

func TestExportCSV(t *testing.T) {
	svc := &Service{}
	events := []DecryptedEvent{
		{
			ID:         "aud_1",
			ProjectID:  "prj_1",
			EventType:  "auth.signup",
			Actor:      &ActorInfo{UserID: "usr_1", Email: "test@example.com", IP: "1.2.3.4"},
			TargetType: "user",
			TargetID:   "usr_1",
			Result:     "success",
			AuthMethod: "password",
			EventHash:  "hash1",
		},
		{
			ID:        "aud_2",
			ProjectID: "prj_1",
			EventType: "auth.login.success",
			Actor:     nil, // Erased user — no actor
			Result:    "success",
			EventHash: "hash2",
			PrevHash:  "hash1",
		},
	}

	data, err := svc.exportCSV(events)
	require.NoError(t, err)

	csv := string(data)
	assert.Contains(t, csv, "id,project_id,trace_id,event_type")
	assert.Contains(t, csv, "aud_1")
	assert.Contains(t, csv, "test@example.com")
	assert.Contains(t, csv, "aud_2")
}

func TestAdvisoryLockKey(t *testing.T) {
	// Same project ID should always produce the same lock key.
	key1 := advisoryLockKey("prj_abc")
	key2 := advisoryLockKey("prj_abc")
	assert.Equal(t, key1, key2)

	// Different project IDs should produce different lock keys.
	key3 := advisoryLockKey("prj_xyz")
	assert.NotEqual(t, key1, key3)
}

func strPtr(s string) *string {
	return &s
}
