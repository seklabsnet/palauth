package social

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// decodeJWTPayload decodes the payload portion of a JWT without verifying
// the signature. This is used when the token was obtained via a secure
// server-to-server exchange and signature verification is not needed.
func decodeJWTPayload(tokenStr string) (map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT payload: %w", err)
	}

	return claims, nil
}
