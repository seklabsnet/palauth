package social

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
	stateKeyPrefix = "palauth:oauth:state:"
	stateTTL       = 10 * time.Minute
)

// OAuthState holds the state stored in Redis during the OAuth flow.
type OAuthState struct {
	ProjectID    string `json:"project_id"`
	Provider     string `json:"provider"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

// GenerateState creates a new OAuth state token and stores it in Redis.
func GenerateState(ctx context.Context, rdb *redis.Client, state *OAuthState) (string, error) {
	token, err := crypto.GenerateToken(32)
	if err != nil {
		return "", fmt.Errorf("generate state token: %w", err)
	}

	data, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}

	key := stateKeyPrefix + token
	if err := rdb.Set(ctx, key, data, stateTTL).Err(); err != nil {
		return "", fmt.Errorf("store state in redis: %w", err)
	}

	return token, nil
}

// ConsumeState retrieves and deletes an OAuth state from Redis (single-use).
func ConsumeState(ctx context.Context, rdb *redis.Client, token string) (*OAuthState, error) {
	key := stateKeyPrefix + token

	// Get and delete atomically.
	data, err := rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrInvalidState
		}
		return nil, fmt.Errorf("consume state from redis: %w", err)
	}

	var state OAuthState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	return &state, nil
}
