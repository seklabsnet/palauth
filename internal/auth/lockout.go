package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// DefaultLockoutThreshold is the number of failed attempts before lockout (PCI DSS Req 8.3.4).
	DefaultLockoutThreshold = 10

	// DefaultLockoutDuration is the lockout duration (PCI DSS Req 8.3.4: 30 minutes).
	DefaultLockoutDuration = 30 * time.Minute
)

// LockoutService tracks failed login attempts and enforces account lockout via Redis.
type LockoutService struct {
	rdb       *redis.Client
	logger    *slog.Logger
	threshold int
	duration  time.Duration
}

// NewLockoutService creates a new lockout service.
func NewLockoutService(rdb *redis.Client, logger *slog.Logger) *LockoutService {
	return &LockoutService{
		rdb:       rdb,
		logger:    logger,
		threshold: DefaultLockoutThreshold,
		duration:  DefaultLockoutDuration,
	}
}

// Check returns whether the account is currently locked out and the remaining duration.
// Redis down → fail-open (log warning, return not locked).
func (l *LockoutService) Check(ctx context.Context, projectID, userID string) (locked bool, retryAfter time.Duration, err error) {
	lockedKey := lockoutLockedKey(projectID, userID)

	ttl, err := l.rdb.TTL(ctx, lockedKey).Result()
	if err != nil {
		l.logger.Warn("lockout check: redis error, failing open", "error", err, "project_id", projectID, "user_id", userID)
		return false, 0, nil
	}

	// Key doesn't exist or has no TTL → not locked.
	if ttl <= 0 {
		return false, 0, nil
	}

	return true, ttl, nil
}

// RecordFailure increments the failed attempt counter and locks the account if threshold is reached.
// Redis down → fail-open (log warning, return not locked).
func (l *LockoutService) RecordFailure(ctx context.Context, projectID, userID string) (locked bool, err error) {
	countKey := lockoutCountKey(projectID, userID)
	lockedKey := lockoutLockedKey(projectID, userID)

	count, err := l.rdb.Incr(ctx, countKey).Result()
	if err != nil {
		l.logger.Warn("lockout record failure: redis incr error, failing open", "error", err, "project_id", projectID, "user_id", userID)
		return false, nil
	}

	// Set TTL on count key if this is the first failure (the window starts now).
	if count == 1 {
		if err := l.rdb.Expire(ctx, countKey, l.duration).Err(); err != nil {
			l.logger.Warn("lockout record failure: redis expire error", "error", err)
		}
	}

	if int(count) >= l.threshold {
		// Lock the account.
		if err := l.rdb.Set(ctx, lockedKey, "1", l.duration).Err(); err != nil {
			l.logger.Warn("lockout record failure: redis set locked error, failing open", "error", err)
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

// Reset clears the failed attempt counter on successful login.
// Redis down → fail-open (log warning).
func (l *LockoutService) Reset(ctx context.Context, projectID, userID string) error {
	countKey := lockoutCountKey(projectID, userID)
	lockedKey := lockoutLockedKey(projectID, userID)

	pipe := l.rdb.Pipeline()
	pipe.Del(ctx, countKey)
	pipe.Del(ctx, lockedKey)

	if _, err := pipe.Exec(ctx); err != nil {
		l.logger.Warn("lockout reset: redis error, failing open", "error", err, "project_id", projectID, "user_id", userID)
	}
	return nil
}

func lockoutCountKey(projectID, userID string) string {
	return fmt.Sprintf("palauth:lockout:%s:%s:count", projectID, userID)
}

func lockoutLockedKey(projectID, userID string) string {
	return fmt.Sprintf("palauth:lockout:%s:%s:locked", projectID, userID)
}
