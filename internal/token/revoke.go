package token

import (
	"context"
	"fmt"
)

// Revoke revokes a token. For refresh tokens, it revokes the entire family.
// For access tokens (JWTs), revocation is a no-op since they are stateless
// and expire naturally. Per RFC 7009, this always succeeds (no error returned
// to the caller for invalid tokens).
func (s *RefreshService) Revoke(ctx context.Context, tokenStr, tokenTypeHint string) error {
	switch tokenTypeHint {
	case "refresh_token":
		return s.RevokeByHash(ctx, tokenStr)
	case "access_token":
		// Access tokens are stateless JWTs — we can't revoke them directly.
		// In a future phase, we could add a blocklist in Redis.
		return nil
	default:
		// Try as refresh token first, then ignore if not found.
		if err := s.RevokeByHash(ctx, tokenStr); err != nil {
			return fmt.Errorf("revoke token: %w", err)
		}
		return nil
	}
}
