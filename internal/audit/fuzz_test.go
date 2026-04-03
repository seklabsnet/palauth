package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzCanonicalJSON(f *testing.F) {
	f.Add(`{"a":1}`)
	f.Add(`{"b":"hello","a":42}`)
	f.Add(`{}`)
	f.Add(`{"nested":{"z":1,"a":2}}`)
	f.Add(`[1,2,3]`)
	f.Add(`"string"`)
	f.Add(`null`)
	f.Add(`123`)

	f.Fuzz(func(t *testing.T, input string) {
		var v any
		if json.Unmarshal([]byte(input), &v) == nil {
			b1, err1 := CanonicalJSON(v)
			b2, err2 := CanonicalJSON(v)
			if err1 != nil || err2 != nil {
				return // errors are acceptable
			}
			if !bytes.Equal(b1, b2) {
				t.Errorf("CanonicalJSON not deterministic for input %q: got %q and %q", input, b1, b2)
			}
		}
	})
}

func FuzzFrameRoundtrip(f *testing.F) {
	f.Add("usr_123", []byte("ciphertext-data"))
	f.Add("", []byte{})
	f.Add("a", []byte{0x00, 0xFF})

	f.Fuzz(func(t *testing.T, userID string, ciphertext []byte) {
		framed := frameWithUserID(userID, ciphertext)
		extractedUID, extractedCT, err := extractUserIDAndCiphertext(framed)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if extractedUID != userID {
			t.Errorf("userID mismatch: got %q want %q", extractedUID, userID)
		}
		if len(extractedCT) != len(ciphertext) {
			t.Errorf("ciphertext length mismatch: got %d want %d", len(extractedCT), len(ciphertext))
		}
	})
}
