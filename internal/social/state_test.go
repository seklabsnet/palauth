package social

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests require a running Redis instance. They are guarded by the
// integration build tag or will be skipped when Redis is not available.

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 15})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	t.Cleanup(func() {
		rdb.FlushDB(context.Background())
		rdb.Close()
	})
	return rdb
}

func TestGenerateAndConsumeState(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()

	state := &OAuthState{
		ProjectID:    "prj_test-123",
		Provider:     "google",
		CodeVerifier: "test-verifier",
		RedirectURI:  "http://localhost/callback",
	}

	token, err := GenerateState(ctx, rdb, state)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Len(t, token, 64) // 32 bytes hex

	// Consume should return the same state.
	consumed, err := ConsumeState(ctx, rdb, token)
	require.NoError(t, err)
	assert.Equal(t, state.ProjectID, consumed.ProjectID)
	assert.Equal(t, state.Provider, consumed.Provider)
	assert.Equal(t, state.CodeVerifier, consumed.CodeVerifier)
	assert.Equal(t, state.RedirectURI, consumed.RedirectURI)

	// Second consume should fail (single-use).
	_, err = ConsumeState(ctx, rdb, token)
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestConsumeState_InvalidToken(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()

	_, err := ConsumeState(ctx, rdb, "nonexistent-token")
	assert.ErrorIs(t, err, ErrInvalidState)
}

func TestConsumeState_EmptyToken(t *testing.T) {
	rdb := newTestRedis(t)
	ctx := context.Background()

	_, err := ConsumeState(ctx, rdb, "")
	assert.ErrorIs(t, err, ErrInvalidState)
}
