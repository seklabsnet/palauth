package token

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	palredis "github.com/palauth/palauth/internal/redis"
)

// Custom token constants.
const (
	MaxCustomTokenTTL     = 1 * time.Hour
	DefaultCustomTokenTTL = 1 * time.Hour
	customTokenJTIPrefix  = "custom_jti:"
)

// Errors for custom token operations.
var (
	ErrCustomTokenTTLExceeded = errors.New("custom token TTL exceeds maximum of 1 hour")
	ErrCustomTokenAlreadyUsed = errors.New("custom token has already been used")
	ErrUserIDRequired         = errors.New("user_id is required")
)

// CustomTokenService handles custom token creation and exchange.
type CustomTokenService struct {
	jwt    *JWTService
	redis  *palredis.Client
	logger *slog.Logger
}

// NewCustomTokenService creates a new custom token service.
func NewCustomTokenService(jwtSvc *JWTService, rdb *palredis.Client, logger *slog.Logger) *CustomTokenService {
	return &CustomTokenService{
		jwt:    jwtSvc,
		redis:  rdb,
		logger: logger,
	}
}

// CreateCustomTokenParams contains the parameters for creating a custom token.
type CreateCustomTokenParams struct {
	UserID       string
	ProjectID    string
	Issuer       string
	Claims       map[string]any
	ExpiresIn    time.Duration
}

// CreateCustomToken generates a JWT with custom claims for admin use.
// The token is single-use: its jti is tracked in Redis.
func (s *CustomTokenService) CreateCustomToken(params CreateCustomTokenParams) (string, error) {
	if params.UserID == "" {
		return "", ErrUserIDRequired
	}

	ttl := params.ExpiresIn
	if ttl == 0 {
		ttl = DefaultCustomTokenTTL
	}
	if ttl > MaxCustomTokenTTL {
		return "", ErrCustomTokenTTLExceeded
	}

	token, err := s.jwt.Issue(&IssueParams{
		UserID:       params.UserID,
		ProjectID:    params.ProjectID,
		Issuer:       params.Issuer,
		AuthTime:     time.Now(),
		TTL:          ttl,
		CustomClaims: params.Claims,
	})
	if err != nil {
		return "", fmt.Errorf("issue custom token: %w", err)
	}

	return token, nil
}

// ExchangeCustomToken validates a custom token, ensures it's single-use,
// and returns the parsed claims. The caller is responsible for creating
// a session and issuing normal tokens.
func (s *CustomTokenService) ExchangeCustomToken(ctx context.Context, tokenStr string) (*Claims, error) {
	claims, err := s.jwt.Verify(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("verify custom token: %w", err)
	}

	// Single-use check via Redis: try to SET NX the jti.
	jtiKey := customTokenJTIPrefix + claims.JWTID
	ttl := time.Until(claims.ExpiresAt)
	if ttl <= 0 {
		return nil, ErrCustomTokenExpired
	}

	result, err := s.redis.Unwrap().SetArgs(ctx, jtiKey, "1", redis.SetArgs{
		TTL:  ttl,
		Mode: "NX",
	}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Key already exists — token was already used.
			return nil, ErrCustomTokenAlreadyUsed
		}
		// If Redis is down, we must reject (fail-closed for security).
		return nil, fmt.Errorf("redis single-use check: %w", err)
	}
	if result == "" {
		// SetArgs with NX returns empty string if key already exists.
		return nil, ErrCustomTokenAlreadyUsed
	}

	return claims, nil
}

// IsCustomTokenUsed checks if a custom token's jti has already been consumed.
func (s *CustomTokenService) IsCustomTokenUsed(ctx context.Context, jti string) (bool, error) {
	jtiKey := customTokenJTIPrefix + jti
	_, err := s.redis.Unwrap().Get(ctx, jtiKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, fmt.Errorf("redis check: %w", err)
	}
	return true, nil
}
