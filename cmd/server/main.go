package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/palauth/palauth/internal/config"
	"github.com/palauth/palauth/internal/database"
	"github.com/palauth/palauth/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
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

	srv := server.New(cfg, logger, db)
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
