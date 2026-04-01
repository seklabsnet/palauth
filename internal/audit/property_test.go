package audit

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestCanonicalJSON_Deterministic_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := genMap(t)

		result1, err := CanonicalJSON(m)
		require.NoError(t, err)

		result2, err := CanonicalJSON(m)
		require.NoError(t, err)

		assert.Equal(t, string(result1), string(result2),
			"CanonicalJSON must be deterministic: same input must produce same output")
	})
}

func TestComputeEventHash_Deterministic_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := computeHashInput{
			EventType:         rapid.StringMatching(`[a-z.]+`).Draw(t, "event_type"),
			ProjectID:         rapid.StringMatching(`prj_[a-z0-9]+`).Draw(t, "project_id"),
			ActorEncrypted:    rapid.StringMatching(`[0-9a-f]+`).Draw(t, "actor_encrypted"),
			TargetType:        rapid.StringMatching(`[a-z]*`).Draw(t, "target_type"),
			TargetID:          rapid.StringMatching(`[a-z0-9_]*`).Draw(t, "target_id"),
			Result:            rapid.SampledFrom([]string{"success", "failure"}).Draw(t, "result"),
			AuthMethod:        rapid.StringMatching(`[a-z]*`).Draw(t, "auth_method"),
			MetadataEncrypted: rapid.StringMatching(`[0-9a-f]+`).Draw(t, "metadata_encrypted"),
			PrevHash:          rapid.StringMatching(`[0-9a-f]*`).Draw(t, "prev_hash"),
		}

		var prevHash *string
		if input.PrevHash != "" {
			prevHash = &input.PrevHash
		}

		hash1, err := computeEventHash(input, prevHash)
		require.NoError(t, err)

		hash2, err := computeEventHash(input, prevHash)
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2,
			"computeEventHash must be deterministic: same input must produce same hash")
	})
}

func TestFrameRoundtrip_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		userID := rapid.String().Draw(t, "user_id")
		ciphertext := rapid.SliceOf(rapid.Byte()).Draw(t, "ciphertext")

		framed := frameWithUserID(userID, ciphertext)

		extractedUID, extractedCT, err := extractUserIDAndCiphertext(framed)
		require.NoError(t, err)

		assert.Equal(t, userID, extractedUID, "round-trip user_id must match")
		assert.Equal(t, ciphertext, extractedCT, "round-trip ciphertext must match")
	})
}

func TestCanonicalJSON_ValidJSON_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := genMap(t)

		result, err := CanonicalJSON(m)
		require.NoError(t, err)

		// Verify the result is valid JSON.
		var decoded any
		err = json.Unmarshal(result, &decoded)
		require.NoError(t, err, "canonical JSON must produce valid JSON")
	})
}

func TestComputeEventHash_DifferentInputsDifferentHashes_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input1 := computeHashInput{
			EventType:         rapid.StringMatching(`[a-z.]+`).Draw(t, "event_type1"),
			ProjectID:         rapid.StringMatching(`prj_[a-z0-9]+`).Draw(t, "project_id1"),
			ActorEncrypted:    rapid.StringMatching(`[0-9a-f]{8,}`).Draw(t, "actor1"),
			Result:            "success",
			MetadataEncrypted: rapid.StringMatching(`[0-9a-f]{8,}`).Draw(t, "meta1"),
		}
		input2 := input1
		input2.Result = "failure"

		hash1, err := computeEventHash(input1, nil)
		require.NoError(t, err)

		hash2, err := computeEventHash(input2, nil)
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2,
			"different inputs should produce different hashes")
	})
}

// genMap generates a random map[string]any for property testing.
func genMap(t *rapid.T) map[string]any {
	size := rapid.IntRange(0, 5).Draw(t, "map_size")
	m := make(map[string]any, size)
	for i := 0; i < size; i++ {
		key := rapid.StringMatching(`[a-z]{1,8}`).Draw(t, "key")
		m[key] = genValue(t, 0)
	}
	return m
}

// genValue generates a random JSON-compatible value.
func genValue(t *rapid.T, depth int) any {
	if depth > 2 {
		return rapid.IntRange(0, 100).Draw(t, "leaf_int")
	}

	kind := rapid.IntRange(0, 4).Draw(t, "kind")
	switch kind {
	case 0:
		return rapid.IntRange(-1000, 1000).Draw(t, "int_value")
	case 1:
		return rapid.StringMatching(`[a-zA-Z0-9 ]{0,20}`).Draw(t, "string_value")
	case 2:
		return rapid.Bool().Draw(t, "bool_value")
	case 3:
		return nil
	case 4:
		size := rapid.IntRange(0, 3).Draw(t, "nested_size")
		nested := make(map[string]any, size)
		for i := 0; i < size; i++ {
			k := rapid.StringMatching(`[a-z]{1,5}`).Draw(t, "nested_key")
			nested[k] = genValue(t, depth+1)
		}
		return nested
	}
	return nil
}
