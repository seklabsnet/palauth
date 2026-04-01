package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// DeterministicHash computes HMAC-SHA256 of data with the given key and returns
// the hex-encoded result. Used for deterministic email_hash column lookups.
func DeterministicHash(data string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
