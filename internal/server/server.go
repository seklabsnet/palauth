package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"

	"github.com/palauth/palauth/internal/config"
)

type Server struct {
	cfg    *config.Config
	router *chi.Mux
	logger *slog.Logger
	http   *http.Server
}

func New(cfg *config.Config, logger *slog.Logger) *Server {
	r := chi.NewRouter()

	s := &Server{
		cfg:    cfg,
		router: r,
		logger: logger,
	}

	s.setupMiddleware()
	s.setupRoutes()

	s.http = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return s
}

func (s *Server) setupMiddleware() {
	s.router.Use(RequestID)
	s.router.Use(StructuredLogger(s.logger))
	s.router.Use(Recovery(s.logger))
	s.router.Use(SecurityHeaders)
	s.router.Use(MaxBodySize)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3001"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	s.router.Use(c.Handler)
}

func (s *Server) setupRoutes() {
	s.router.Get("/healthz", s.handleHealthz)
	s.router.Get("/readyz", s.handleReadyz)
	s.router.Get("/metrics", promhttp.Handler().ServeHTTP)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	// TODO(T0.3): Check DB connection
	// TODO(T0.4): Check Redis connection
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Router returns the chi router for testing.
func (s *Server) Router() *chi.Mux {
	return s.router
}

func (s *Server) Start() error {
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server listening", "addr", s.http.Addr)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		s.logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	s.logger.Info("graceful shutdown starting")
	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}
	s.logger.Info("server stopped")
	return nil
}
