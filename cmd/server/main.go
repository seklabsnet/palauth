package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/palauth/palauth/internal/config"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Setup structured logger
	var handler slog.Handler
	switch cfg.Log.Format {
	case "text":
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: parseLogLevel(cfg.Log.Level),
		})
	default:
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: parseLogLevel(cfg.Log.Level),
		})
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	logger.Info("palauth server starting",
		"port", cfg.Server.Port,
		"log_level", cfg.Log.Level,
		"fips", cfg.FIPS,
	)

	// TODO(T0.2): HTTP server + router + middleware
	logger.Info("server ready", "addr", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port))
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
