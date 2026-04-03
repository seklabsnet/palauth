package mfa

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// MFALockoutThreshold is 5 failed MFA attempts (PSD2 RTS + PCI DSS).
	MFALockoutThreshold = 5

	// MFALockoutDuration is 30 minutes lockout after threshold.
	MFALockoutDuration = 30 * time.Minute
)

// LockoutService tracks failed MFA attempts separately from password lockout.
type LockoutService struct {
	rdb       *redis.Client
	logger    *slog.Logger
	threshold int
	duration  time.Duration
}

// NewLockoutService creates a new MFA lockout service.
func NewLockoutService(rdb *redis.Client, logger *slog.Logger) *LockoutService {
	return &LockoutService{
		rdb:       rdb,
		logger:    logger,
		threshold: MFALockoutThreshold,
		duration:  MFALockoutDuration,
	}
}

// Check returns whether the MFA is currently locked out.
// Redis down -> fail-open.
func (l *LockoutService) Check(ctx context.Context, projectID, userID string) (locked bool, retryAfter time.Duration, err error) {
	lockedKey := mfaLockedKey(projectID, userID)

	ttl, err := l.rdb.TTL(ctx, lockedKey).Result()
	if err != nil {
		l.logger.Warn("mfa lockout check: redis error, failing open", "error", err, "project_id", projectID, "user_id", userID)
		return false, 0, nil
	}

	if ttl <= 0 {
		return false, 0, nil
	}

	return true, ttl, nil
}

// RecordFailure increments the MFA failed attempt counter.
// Redis down -> fail-open.
func (l *LockoutService) RecordFailure(ctx context.Context, projectID, userID string) (locked bool, err error) {
	countKey := mfaCountKey(projectID, userID)
	lockedKey := mfaLockedKey(projectID, userID)

	count, err := l.rdb.Incr(ctx, countKey).Result()
	if err != nil {
		l.logger.Warn("mfa lockout record failure: redis incr error, failing open", "error", err, "project_id", projectID, "user_id", userID)
		return false, nil
	}

	if count == 1 {
		if err := l.rdb.Expire(ctx, countKey, l.duration).Err(); err != nil {
			l.logger.Warn("mfa lockout record failure: redis expire error", "error", err)
		}
	}

	if int(count) >= l.threshold {
		if err := l.rdb.Set(ctx, lockedKey, "1", l.duration).Err(); err != nil {
			l.logger.Warn("mfa lockout record failure: redis set locked error, failing open", "error", err)
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

// Reset clears the MFA failed attempt counter.
// Redis down -> fail-open.
func (l *LockoutService) Reset(ctx context.Context, projectID, userID string) {
	countKey := mfaCountKey(projectID, userID)
	lockedKey := mfaLockedKey(projectID, userID)

	pipe := l.rdb.Pipeline()
	pipe.Del(ctx, countKey)
	pipe.Del(ctx, lockedKey)

	if _, err := pipe.Exec(ctx); err != nil {
		l.logger.Warn("mfa lockout reset: redis error, failing open", "error", err, "project_id", projectID, "user_id", userID)
	}
}

func mfaCountKey(projectID, userID string) string {
	return fmt.Sprintf("palauth:mfa_lockout:%s:%s:count", projectID, userID)
}

func mfaLockedKey(projectID, userID string) string {
	return fmt.Sprintf("palauth:mfa_lockout:%s:%s:locked", projectID, userID)
}
