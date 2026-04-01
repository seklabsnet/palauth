package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/palauth/palauth/internal/config"
	"github.com/palauth/palauth/internal/server"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := setupLogger(cfg)
	slog.SetDefault(logger)

	logger.Info("palauth server starting",
		"port", cfg.Server.Port,
		"log_level", cfg.Log.Level,
		"fips", cfg.FIPS,
	)

	srv := server.New(cfg, logger)
	if err := srv.Start(); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
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
