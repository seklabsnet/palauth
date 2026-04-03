package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/palauth/palauth/internal/crypto"
)

const (
	// MFATokenTTL is 5 minutes (PSD2 RTS max 5dk auth code lifetime).
	MFATokenTTL = 5 * time.Minute

	// MFATokenBytes is the number of random bytes for the token (256-bit).
	MFATokenBytes = 32
)

// TokenData contains the data stored with an MFA token in Redis.
type TokenData struct {
	UserID    string `json:"user_id"`
	ProjectID string `json:"project_id"`
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// IssueMFAToken creates an opaque MFA token and stores it in Redis with 5min TTL.
func (s *Service) IssueMFAToken(ctx context.Context, data *TokenData) (string, error) {
	token, err := crypto.GenerateToken(MFATokenBytes)
	if err != nil {
		return "", fmt.Errorf("generate mfa token: %w", err)
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal mfa token data: %w", err)
	}

	key := mfaTokenKey(token)
	if err := s.rdb.Set(ctx, key, payload, MFATokenTTL).Err(); err != nil {
		return "", fmt.Errorf("store mfa token: %w", err)
	}

	return token, nil
}

// ValidateMFAToken retrieves and validates an MFA token from Redis without consuming it.
func (s *Service) ValidateMFAToken(ctx context.Context, token string) (*TokenData, error) {
	key := mfaTokenKey(token)

	payload, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrMFATokenInvalid
		}
		return nil, fmt.Errorf("get mfa token: %w", err)
	}

	var data TokenData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal mfa token data: %w", err)
	}

	return &data, nil
}

// ConsumeMFAToken atomically retrieves and deletes an MFA token from Redis (single-use).
// Uses GETDEL to prevent TOCTOU race conditions where two concurrent requests
// could both validate the same token before either deletes it.
func (s *Service) ConsumeMFAToken(ctx context.Context, token string) (*TokenData, error) {
	key := mfaTokenKey(token)

	payload, err := s.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrMFATokenInvalid
		}
		return nil, fmt.Errorf("consume mfa token: %w", err)
	}

	var data TokenData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal mfa token data: %w", err)
	}

	return &data, nil
}

func mfaTokenKey(token string) string {
	return fmt.Sprintf("palauth:mfa_token:%s", token)
}
