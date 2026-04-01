package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalJSON_SortedKeys(t *testing.T) {
	input := map[string]any{
		"zebra":  1,
		"apple":  2,
		"mango":  3,
		"banana": 4,
	}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	expected := `{"apple":2,"banana":4,"mango":3,"zebra":1}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_NestedObjects(t *testing.T) {
	input := map[string]any{
		"z": map[string]any{
			"b": 2,
			"a": 1,
		},
		"a": "first",
	}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	expected := `{"a":"first","z":{"a":1,"b":2}}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_DeeplyNested(t *testing.T) {
	input := map[string]any{
		"level1": map[string]any{
			"z_key": map[string]any{
				"c": 3,
				"a": 1,
				"b": 2,
			},
			"a_key": "value",
		},
	}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	expected := `{"level1":{"a_key":"value","z_key":{"a":1,"b":2,"c":3}}}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_Struct(t *testing.T) {
	input := ActorInfo{
		UserID: "usr_123",
		Email:  "test@example.com",
		IP:     "192.168.1.1",
	}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	expected := `{"email":"test@example.com","ip":"192.168.1.1","user_id":"usr_123"}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_EmptyMap(t *testing.T) {
	input := map[string]any{}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	assert.Equal(t, "{}", string(result))
}

func TestCanonicalJSON_ArrayValues(t *testing.T) {
	input := map[string]any{
		"b": []any{3, 2, 1},
		"a": "value",
	}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	expected := `{"a":"value","b":[3,2,1]}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_NullValue(t *testing.T) {
	input := map[string]any{
		"b": nil,
		"a": "value",
	}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	expected := `{"a":"value","b":null}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_Deterministic(t *testing.T) {
	input := map[string]any{
		"event_type":         "auth.login.success",
		"project_id":         "prj_123",
		"actor_encrypted":    "abcdef0123456789",
		"target_type":        "user",
		"target_id":          "usr_456",
		"result":             "success",
		"auth_method":        "password",
		"metadata_encrypted": "fedcba9876543210",
		"prev_hash":          "",
	}

	// Run 100 times — must always produce the same output.
	first, err := CanonicalJSON(input)
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		result, err := CanonicalJSON(input)
		require.NoError(t, err)
		assert.Equal(t, string(first), string(result), "iteration %d produced different output", i)
	}
}

func TestCanonicalJSON_ConsistentHashing(t *testing.T) {
	input := computeHashInput{
		EventType:         "auth.login.success",
		ProjectID:         "prj_123",
		ActorEncrypted:    "abcdef",
		TargetType:        "user",
		TargetID:          "usr_456",
		Result:            "success",
		AuthMethod:        "password",
		MetadataEncrypted: "fedcba",
		PrevHash:          "",
	}

	canonical1, err := CanonicalJSON(input)
	require.NoError(t, err)
	hash1 := sha256.Sum256(canonical1)

	canonical2, err := CanonicalJSON(input)
	require.NoError(t, err)
	hash2 := sha256.Sum256(canonical2)

	assert.Equal(t, hex.EncodeToString(hash1[:]), hex.EncodeToString(hash2[:]))
}

func TestCanonicalJSON_StructWithOmitempty(t *testing.T) {
	// When Email and IP are empty, omitempty should exclude them.
	input := ActorInfo{
		UserID: "usr_123",
	}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	expected := `{"user_id":"usr_123"}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_MapWithNestedArrayOfObjects(t *testing.T) {
	input := map[string]any{
		"items": []any{
			map[string]any{"z": 1, "a": 2},
			map[string]any{"c": 3, "b": 4},
		},
	}

	result, err := CanonicalJSON(input)
	require.NoError(t, err)

	expected := `{"items":[{"a":2,"z":1},{"b":4,"c":3}]}`
	assert.Equal(t, expected, string(result))
}
