package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/palauth/palauth/internal/config"
	"github.com/palauth/palauth/internal/database"
	palredis "github.com/palauth/palauth/internal/redis"
	"github.com/palauth/palauth/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Handle healthz subcommand for Docker healthcheck (no config needed)
	if len(os.Args) > 1 && os.Args[1] == "healthz" {
		return runHealthcheck()
	}

	configPath := flag.String("config", "", "path to YAML config file")
	migrate := flag.Bool("migrate", false, "run database migrations and exit")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logger := setupLogger(cfg)

	// Run migrations if flag is set
	if *migrate {
		logger.Info("running database migrations")
		if err := database.RunMigrations(cfg.Database.URL, "migrations"); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
		logger.Info("migrations completed successfully")
		return nil
	}

	logger.Info("palauth server starting",
		"port", cfg.Server.Port,
		"log_level", cfg.Log.Level,
		"fips", cfg.FIPS,
	)

	// Connect to database
	ctx := context.Background()
	db, err := database.NewPool(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer db.Close()
	logger.Info("database connected")

	// Connect to Redis (optional — if URL is empty, rate limiting uses in-memory)
	var rdb *palredis.Client
	if cfg.Redis.URL != "" {
		rdb, err = palredis.New(ctx, &cfg.Redis, logger)
		if err != nil {
			return fmt.Errorf("connecting to redis: %w", err)
		}
		defer rdb.Close()
		logger.Info("redis connected")
	} else {
		logger.Warn("redis URL not configured — rate limiting will use in-memory counters")
	}

	srv := server.New(cfg, logger, db, rdb)
	return srv.Start()
}

func setupLogger(cfg *config.Config) *slog.Logger {
	level := parseLogLevel(cfg.Log.Level)
	var handler slog.Handler
	switch cfg.Log.Format {
	case "text":
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	default:
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	return slog.New(handler)
}

func runHealthcheck() error {
	port := os.Getenv("PALAUTH_SERVER_PORT")
	if port == "" {
		port = "3000"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%s/healthz", port))
	if err != nil {
		return fmt.Errorf("healthcheck failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned status %d", resp.StatusCode)
	}
	return nil
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
