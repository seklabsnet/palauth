package apikey

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

var (
	ErrKeyNotFound     = errors.New("api key not found")
	ErrKeyRevoked      = errors.New("api key has been revoked")
	ErrInvalidKeyType  = errors.New("invalid key type")
	ErrInvalidKey      = errors.New("invalid api key format")
)

// Valid key types.
const (
	KeyTypePublicTest = "public_test"
	KeyTypeSecretTest = "secret_test"
	KeyTypePublicLive = "public_live"
	KeyTypeSecretLive = "secret_live"
)

// Key prefixes mapped to key types.
var keyPrefixes = map[string]string{
	KeyTypePublicTest: "pk_test_",
	KeyTypeSecretTest: "sk_test_",
	KeyTypePublicLive: "pk_live_",
	KeyTypeSecretLive: "sk_live_",
}

// AllKeyTypes returns all valid key types in order.
var AllKeyTypes = []string{
	KeyTypePublicTest,
	KeyTypeSecretTest,
	KeyTypePublicLive,
	KeyTypeSecretLive,
}

// KeyInfo contains information about a verified API key.
type KeyInfo struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	KeyType   string `json:"key_type"`
	KeyPrefix string `json:"key_prefix"`
}

// KeySummary is a non-sensitive view of an API key for listing.
type KeySummary struct {
	ID        string  `json:"id"`
	ProjectID string  `json:"project_id"`
	KeyPrefix string  `json:"key_prefix"`
	KeyType   string  `json:"key_type"`
	Name      *string `json:"name,omitempty"`
	LastUsed  string  `json:"last_used,omitempty"`
	CreatedAt string  `json:"created_at"`
	Revoked   bool    `json:"revoked"`
}

// APIKeys holds all 4 API keys for a project (only returned on creation).
type APIKeys struct {
	PublicTest string `json:"public_test"`
	SecretTest string `json:"secret_test"`
	PublicLive string `json:"public_live"`
	SecretLive string `json:"secret_live"`
}

// Service manages API key operations.
type Service struct {
	db     *pgxpool.Pool
	logger *slog.Logger
}

// NewService creates a new API key service.
func NewService(db *pgxpool.Pool, logger *slog.Logger) *Service {
	return &Service{db: db, logger: logger}
}

// Generate creates a new API key for a project with the given type.
func (s *Service) Generate(ctx context.Context, projectID, keyType string) (plainKey string, err error) {
	prefix, ok := keyPrefixes[keyType]
	if !ok {
		return "", ErrInvalidKeyType
	}

	// Generate 32 random bytes → 64 hex chars
	randomPart, err := crypto.GenerateToken(32)
	if err != nil {
		return "", fmt.Errorf("generate random: %w", err)
	}

	plainKey = prefix + randomPart
	hash := HashKey(plainKey)

	q := sqlc.New(s.db)
	_, err = q.CreateAPIKey(ctx, sqlc.CreateAPIKeyParams{
		ID:        id.New("key_"),
		ProjectID: projectID,
		KeyHash:   hash,
		KeyPrefix: prefix,
		KeyType:   keyType,
	})
	if err != nil {
		return "", fmt.Errorf("create api key: %w", err)
	}

	return plainKey, nil
}

// GenerateAllForProject generates all 4 API key types for a project.
func (s *Service) GenerateAllForProject(ctx context.Context, projectID string) (*APIKeys, error) {
	keys := &APIKeys{}

	for _, keyType := range AllKeyTypes {
		plainKey, err := s.Generate(ctx, projectID, keyType)
		if err != nil {
			return nil, fmt.Errorf("generate %s: %w", keyType, err)
		}
		switch keyType {
		case KeyTypePublicTest:
			keys.PublicTest = plainKey
		case KeyTypeSecretTest:
			keys.SecretTest = plainKey
		case KeyTypePublicLive:
			keys.PublicLive = plainKey
		case KeyTypeSecretLive:
			keys.SecretLive = plainKey
		}
	}

	return keys, nil
}

// Verify checks an API key and returns its info if valid.
func (s *Service) Verify(ctx context.Context, key string) (*KeyInfo, error) {
	if len(key) < 8 {
		return nil, ErrInvalidKey
	}

	hash := HashKey(key)

	q := sqlc.New(s.db)
	// Use grace period query so recently rotated keys still work for 30s.
	row, err := q.GetAPIKeyByHashWithGrace(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("get api key: %w", err)
	}

	// Update last_used in a fire-and-forget goroutine with a timeout.
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bgQ := sqlc.New(s.db)
		if err := bgQ.UpdateAPIKeyLastUsed(bgCtx, row.ID); err != nil {
			s.logger.Warn("failed to update api key last_used", "key_id", row.ID, "error", err)
		}
	}()

	return &KeyInfo{
		ID:        row.ID,
		ProjectID: row.ProjectID,
		KeyType:   row.KeyType,
		KeyPrefix: row.KeyPrefix,
	}, nil
}

// Rotate generates a new key and marks the old key for grace-period revocation.
func (s *Service) Rotate(ctx context.Context, projectID, keyType string) (newPlainKey string, err error) {
	prefix, ok := keyPrefixes[keyType]
	if !ok {
		return "", ErrInvalidKeyType
	}

	// Find existing active keys of this type for the project.
	q := sqlc.New(s.db)
	existingKeys, err := q.ListAPIKeys(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("list keys: %w", err)
	}

	// Mark existing keys of this type with grace period revocation.
	for _, k := range existingKeys {
		if k.KeyType == keyType && !k.RevokedAt.Valid {
			if err := q.RevokeAPIKeyWithGrace(ctx, k.ID); err != nil {
				return "", fmt.Errorf("revoke old key: %w", err)
			}
		}
	}

	// Generate new key.
	randomPart, err := crypto.GenerateToken(32)
	if err != nil {
		return "", fmt.Errorf("generate random: %w", err)
	}

	newPlainKey = prefix + randomPart
	hash := HashKey(newPlainKey)

	_, err = q.CreateAPIKey(ctx, sqlc.CreateAPIKeyParams{
		ID:        id.New("key_"),
		ProjectID: projectID,
		KeyHash:   hash,
		KeyPrefix: prefix,
		KeyType:   keyType,
	})
	if err != nil {
		return "", fmt.Errorf("create new key: %w", err)
	}

	return newPlainKey, nil
}

// Revoke immediately revokes an API key.
func (s *Service) Revoke(ctx context.Context, keyID string) error {
	q := sqlc.New(s.db)
	if err := q.RevokeAPIKey(ctx, keyID); err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	return nil
}

// List returns all API keys for a project (without sensitive data).
func (s *Service) List(ctx context.Context, projectID string) ([]KeySummary, error) {
	q := sqlc.New(s.db)
	rows, err := q.ListAPIKeys(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}

	summaries := make([]KeySummary, 0, len(rows))
	for _, row := range rows {
		ks := KeySummary{
			ID:        row.ID,
			ProjectID: row.ProjectID,
			KeyPrefix: row.KeyPrefix,
			KeyType:   row.KeyType,
			Name:      row.Name,
			Revoked:   row.RevokedAt.Valid,
		}
		if row.LastUsed.Valid {
			ks.LastUsed = row.LastUsed.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		if row.CreatedAt.Valid {
			ks.CreatedAt = row.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		summaries = append(summaries, ks)
	}

	return summaries, nil
}

// HashKey computes SHA-256 of the plain key.
func HashKey(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

// KeyPrefix returns the prefix string for a given key type.
func KeyPrefix(keyType string) string {
	return keyPrefixes[keyType]
}
