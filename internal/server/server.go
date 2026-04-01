package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"

	"github.com/palauth/palauth/internal/admin"
	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/config"
	"github.com/palauth/palauth/internal/project"
	palredis "github.com/palauth/palauth/internal/redis"
)

type Server struct {
	cfg        *config.Config
	router     *chi.Mux
	logger     *slog.Logger
	http       *http.Server
	db         *pgxpool.Pool
	redis      *palredis.Client
	adminSvc   *admin.Service
	projectSvc *project.Service
	apikeySvc  *apikey.Service
}

func New(cfg *config.Config, logger *slog.Logger, db *pgxpool.Pool, rdb *palredis.Client) *Server {
	r := chi.NewRouter()

	projectSvc := project.NewService(db, logger)
	apikeySvc := apikey.NewService(db, logger)

	// Derive admin JWT signing key from pepper via HMAC-SHA256 for key separation.
	// In T0.8 this moves to go-jose with proper key management.
	mac := hmac.New(sha256.New, []byte(cfg.Auth.Pepper))
	mac.Write([]byte("admin-jwt-signing"))
	signingKey := mac.Sum(nil)
	adminSvc := admin.NewService(db, cfg.Auth.Pepper, signingKey, logger)

	s := &Server{
		cfg:        cfg,
		router:     r,
		logger:     logger,
		db:         db,
		redis:      rdb,
		adminSvc:   adminSvc,
		projectSvc: projectSvc,
		apikeySvc:  apikeySvc,
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
		AllowedOrigins:   s.cfg.Server.CORSAllowedOrigins,
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

	// Admin setup and login (no auth required, but cache-control is required).
	s.router.Group(func(r chi.Router) {
		r.Use(CacheControl)
		r.Post("/admin/setup", s.handleAdminSetup)
		r.Post("/admin/login", s.handleAdminLogin)
	})

	// Admin-protected routes.
	s.router.Route("/admin", func(r chi.Router) {
		r.Use(CacheControl)
		r.Use(s.adminSvc.AuthMiddleware())
		r.Post("/projects", s.handleCreateProject)
		r.Get("/projects", s.handleListProjects)
		r.Route("/projects/{id}", func(r chi.Router) {
			r.Get("/", s.handleGetProject)
			r.Put("/config", s.handleUpdateProject)
			r.Delete("/", s.handleDeleteProject)
			r.Post("/keys/rotate", s.handleRotateKeys)
			r.Get("/keys", s.handleListKeys)
		})
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.db != nil {
		if err := s.db.Ping(r.Context()); err != nil {
			s.WriteError(w, r, http.StatusServiceUnavailable, "database_unavailable", "Database is not reachable")
			return
		}
	}
	if s.redis != nil {
		if err := s.redis.Ping(r.Context()); err != nil {
			s.WriteError(w, r, http.StatusServiceUnavailable, "redis_unavailable", "Redis is not reachable")
			return
		}
	}
	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
