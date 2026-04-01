package redis

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/palauth/palauth/internal/config"
)

// Client wraps go-redis with health check and graceful close.
type Client struct {
	rdb    *redis.Client
	logger *slog.Logger
}

// New creates a Redis client from config. It pings Redis to verify the connection.
func New(ctx context.Context, cfg *config.RedisConfig, logger *slog.Logger) (*Client, error) {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}

	opts.PoolSize = cfg.PoolSize
	if opts.PoolSize == 0 {
		opts.PoolSize = 10
	}
	opts.MinIdleConns = cfg.MinIdleConns
	if opts.MinIdleConns == 0 {
		opts.MinIdleConns = 2
	}
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second

	rdb := redis.NewClient(opts)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := rdb.Ping(pingCtx).Err(); err != nil {
		rdb.Close()
		return nil, fmt.Errorf("pinging redis: %w", err)
	}

	return &Client{rdb: rdb, logger: logger}, nil
}

// Ping checks if Redis is reachable.
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// Close gracefully closes the Redis connection.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Unwrap returns the underlying go-redis client for use by libraries like httprate-redis.
func (c *Client) Unwrap() *redis.Client {
	return c.rdb
}
