package redis

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/palauth/palauth/internal/config"
)

func startRedisContainer(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	container, err := redis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, container.Terminate(ctx))
	})

	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)
	return connStr
}

func TestNew_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	connStr := startRedisContainer(t)
	logger := slog.Default()

	client, err := New(context.Background(), &config.RedisConfig{URL: connStr}, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Ping(context.Background())
	assert.NoError(t, err)
}

func TestNew_InvalidURL(t *testing.T) {
	logger := slog.Default()

	_, err := New(context.Background(), &config.RedisConfig{URL: "not-a-valid-url"}, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing redis URL")
}

func TestNew_Unreachable(t *testing.T) {
	logger := slog.Default()

	_, err := New(context.Background(), &config.RedisConfig{URL: "redis://127.0.0.1:59999"}, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pinging redis")
}

func TestUnwrap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	connStr := startRedisContainer(t)
	logger := slog.Default()

	client, err := New(context.Background(), &config.RedisConfig{URL: connStr}, logger)
	require.NoError(t, err)
	defer client.Close()

	rdb := client.Unwrap()
	assert.NotNil(t, rdb)

	// Verify the unwrapped client works
	err = rdb.Ping(context.Background()).Err()
	assert.NoError(t, err)
}

func TestClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	connStr := startRedisContainer(t)
	logger := slog.Default()

	client, err := New(context.Background(), &config.RedisConfig{URL: connStr}, logger)
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)

	// After close, ping should fail
	err = client.Ping(context.Background())
	assert.Error(t, err)
}
