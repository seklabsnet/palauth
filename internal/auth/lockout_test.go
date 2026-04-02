package auth

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRedis connects to a test Redis. Skips if unavailable.
// Integration tests with testcontainers provide the real Redis instance.
func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping lockout unit test")
	}
	t.Cleanup(func() { rdb.Close() })
	return rdb
}

func TestLockoutService_Check_NotLocked(t *testing.T) {
	rdb := newTestRedis(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewLockoutService(rdb, logger)

	ctx := context.Background()
	locked, retryAfter, err := svc.Check(ctx, "prj_test", "usr_test_not_locked")
	require.NoError(t, err)
	assert.False(t, locked)
	assert.Equal(t, time.Duration(0), retryAfter)
}

func TestLockoutService_RecordFailure_BelowThreshold(t *testing.T) {
	rdb := newTestRedis(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewLockoutService(rdb, logger)

	ctx := context.Background()
	userID := "usr_test_below_threshold_" + time.Now().Format("150405.000")

	// Clean up
	t.Cleanup(func() {
		rdb.Del(ctx, lockoutCountKey("prj_test", userID))
		rdb.Del(ctx, lockoutLockedKey("prj_test", userID))
	})

	// Record 5 failures — should not lock.
	for i := 0; i < 5; i++ {
		locked, err := svc.RecordFailure(ctx, "prj_test", userID)
		require.NoError(t, err)
		assert.False(t, locked, "should not be locked after %d failures", i+1)
	}

	locked, _, err := svc.Check(ctx, "prj_test", userID)
	require.NoError(t, err)
	assert.False(t, locked)
}

func TestLockoutService_RecordFailure_AtThreshold(t *testing.T) {
	rdb := newTestRedis(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewLockoutService(rdb, logger)

	ctx := context.Background()
	userID := "usr_test_at_threshold_" + time.Now().Format("150405.000")

	t.Cleanup(func() {
		rdb.Del(ctx, lockoutCountKey("prj_test", userID))
		rdb.Del(ctx, lockoutLockedKey("prj_test", userID))
	})

	// Record 10 failures — should lock on the 10th.
	for i := 0; i < 9; i++ {
		locked, err := svc.RecordFailure(ctx, "prj_test", userID)
		require.NoError(t, err)
		assert.False(t, locked, "should not be locked after %d failures", i+1)
	}

	locked, err := svc.RecordFailure(ctx, "prj_test", userID)
	require.NoError(t, err)
	assert.True(t, locked, "should be locked after 10 failures")

	// Verify Check returns locked.
	isLocked, retryAfter, err := svc.Check(ctx, "prj_test", userID)
	require.NoError(t, err)
	assert.True(t, isLocked)
	assert.True(t, retryAfter > 0, "retry_after should be positive")
}

func TestLockoutService_Reset(t *testing.T) {
	rdb := newTestRedis(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewLockoutService(rdb, logger)

	ctx := context.Background()
	userID := "usr_test_reset_" + time.Now().Format("150405.000")

	t.Cleanup(func() {
		rdb.Del(ctx, lockoutCountKey("prj_test", userID))
		rdb.Del(ctx, lockoutLockedKey("prj_test", userID))
	})

	// Record 10 failures to trigger lockout.
	for i := 0; i < 10; i++ {
		_, _ = svc.RecordFailure(ctx, "prj_test", userID)
	}

	// Verify locked.
	locked, _, err := svc.Check(ctx, "prj_test", userID)
	require.NoError(t, err)
	assert.True(t, locked)

	// Reset.
	err = svc.Reset(ctx, "prj_test", userID)
	require.NoError(t, err)

	// Verify no longer locked.
	locked, _, err = svc.Check(ctx, "prj_test", userID)
	require.NoError(t, err)
	assert.False(t, locked)
}

func TestLockoutService_IsolationByProject(t *testing.T) {
	rdb := newTestRedis(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewLockoutService(rdb, logger)

	ctx := context.Background()
	userID := "usr_test_isolation_" + time.Now().Format("150405.000")

	t.Cleanup(func() {
		rdb.Del(ctx, lockoutCountKey("prj_a", userID))
		rdb.Del(ctx, lockoutLockedKey("prj_a", userID))
		rdb.Del(ctx, lockoutCountKey("prj_b", userID))
		rdb.Del(ctx, lockoutLockedKey("prj_b", userID))
	})

	// Lock in project A.
	for i := 0; i < 10; i++ {
		_, _ = svc.RecordFailure(ctx, "prj_a", userID)
	}

	locked, _, err := svc.Check(ctx, "prj_a", userID)
	require.NoError(t, err)
	assert.True(t, locked, "prj_a should be locked")

	// Project B should not be locked.
	locked, _, err = svc.Check(ctx, "prj_b", userID)
	require.NoError(t, err)
	assert.False(t, locked, "prj_b should not be locked")
}

func TestLockoutKeyFormats(t *testing.T) {
	assert.Equal(t, "palauth:lockout:prj_1:usr_1:count", lockoutCountKey("prj_1", "usr_1"))
	assert.Equal(t, "palauth:lockout:prj_1:usr_1:locked", lockoutLockedKey("prj_1", "usr_1"))
}
