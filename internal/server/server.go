package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"

	"github.com/palauth/palauth/internal/admin"
	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/auth"
	"github.com/palauth/palauth/internal/config"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/email"
	"github.com/palauth/palauth/internal/hook"
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/mfa"
	"github.com/palauth/palauth/internal/project"
	"github.com/palauth/palauth/internal/ratelimit"
	palredis "github.com/palauth/palauth/internal/redis"
	"github.com/palauth/palauth/internal/session"
	"github.com/palauth/palauth/internal/social"
	"github.com/palauth/palauth/internal/token"
)

type Server struct {
	cfg          *config.Config
	router       *chi.Mux
	logger       *slog.Logger
	http         *http.Server
	db           *pgxpool.Pool
	redis        *palredis.Client
	adminSvc     *admin.Service
	adminUserSvc *admin.UserService
	projectSvc   *project.Service
	apikeySvc    *apikey.Service
	auditSvc     *audit.Service
	jwtSvc       *token.JWTService
	refreshSvc   *token.RefreshService
	customSvc    *token.CustomTokenService
	sessionSvc   *session.Service
	authSvc      *auth.Service
	mfaSvc       *mfa.Service
	socialSvc    *social.Service
	hookEngine   *hook.Engine
	rl           *ratelimit.RouteMiddlewares
}

func New(cfg *config.Config, logger *slog.Logger, db *pgxpool.Pool, rdb *palredis.Client) *Server {
	r := chi.NewRouter()

	apikeySvc := apikey.NewService(db, logger)

	// Derive audit KEK from pepper via HMAC-SHA256 for key separation.
	auditMac := hmac.New(sha256.New, []byte(cfg.Auth.Pepper))
	auditMac.Write([]byte("audit-log-kek"))
	auditKEK := auditMac.Sum(nil)
	auditSvc := audit.NewService(db, auditKEK, logger)

	// Derive admin JWT signing key from pepper via HMAC-SHA256 for key separation.
	// In T0.8 this moves to go-jose with proper key management.
	mac := hmac.New(sha256.New, []byte(cfg.Auth.Pepper))
	mac.Write([]byte("admin-jwt-signing"))
	signingKey := mac.Sum(nil)
	adminSvc := admin.NewService(db, cfg.Auth.Pepper, signingKey, auditSvc, logger)

	// Token services.
	jwtAlg := token.AlgPS256
	if cfg.FIPS {
		jwtAlg = token.AlgPS256 // FIPS: PS256 is approved
	}
	jwtSvc, err := token.NewJWTService(token.JWTConfig{
		Algorithm: jwtAlg,
		FAPI:      false, // TODO: read from project config
		Logger:    logger,
	})
	if err != nil {
		logger.Error("failed to initialize JWT service", "error", err)
		panic(fmt.Sprintf("jwt service init: %v", err))
	}

	var refreshTTL time.Duration
	if cfg.Auth.RefreshTokenTTL > 0 {
		refreshTTL = time.Duration(cfg.Auth.RefreshTokenTTL) * time.Second
	}
	refreshSvc := token.NewRefreshService(db, jwtSvc, refreshTTL, logger)
	customSvc := token.NewCustomTokenService(jwtSvc, rdb, logger)

	// Auth KEK: derived from pepper for email encryption key management.
	authKEKMac := hmac.New(sha256.New, []byte(cfg.Auth.Pepper))
	authKEKMac.Write([]byte("auth-email-kek"))
	authKEK := authKEKMac.Sum(nil)

	projectSvc := project.NewService(db, authKEK, logger)

	var breachChecker *crypto.BreachChecker
	if cfg.Auth.HIBPBaseURL != "" {
		breachChecker = crypto.NewBreachCheckerWithURL(cfg.Auth.HIBPBaseURL)
	} else {
		breachChecker = crypto.NewBreachChecker()
	}

	// Email service.
	emailSender, err := email.NewSender(&cfg.Email, logger)
	if err != nil {
		logger.Error("failed to initialize email sender", "error", err)
		panic(fmt.Sprintf("email sender init: %v", err))
	}
	emailRenderer, err := email.NewTemplateRenderer()
	if err != nil {
		logger.Error("failed to initialize email template renderer", "error", err)
		panic(fmt.Sprintf("email renderer init: %v", err))
	}

	var lockoutSvc *auth.LockoutService
	if rdb != nil {
		lockoutSvc = auth.NewLockoutService(rdb.Unwrap(), logger)
	}
	sessionSvc := session.NewService(db, auditSvc, logger)
	authSvc := auth.NewService(db, projectSvc, jwtSvc, refreshSvc, auditSvc, breachChecker, lockoutSvc, emailSender, emailRenderer, cfg.Auth.Pepper, authKEK, logger)

	// MFA service.
	var mfaSvc *mfa.Service
	if rdb != nil {
		mfaSvc = mfa.NewService(db, rdb.Unwrap(), authKEK, cfg.Auth.Pepper, auditSvc, sessionSvc, emailSender, emailRenderer, logger)
		authSvc.SetMFAChecker(mfaSvc)
		adminSvc.SetMFAChecker(mfaSvc)
	}

	// Admin user management service.
	adminUserSvc := admin.NewUserService(db, auditSvc, sessionSvc, breachChecker, emailSender, emailRenderer, cfg.Auth.Pepper, authKEK, logger)

	// Social login service.
	var socialSvc *social.Service
	if rdb != nil {
		socialSvc = social.NewService(db, rdb.Unwrap(), jwtSvc, refreshSvc, auditSvc, cfg.Auth.Pepper, authKEK, logger)
		socialSvc.SetRedirectURIValidator(projectSvc)
		if mfaSvc != nil {
			socialSvc.SetMFAChecker(mfaSvc)
		}
	}

	// Hook engine: derive KEK from pepper for signing key encryption.
	var hookEngine *hook.Engine
	if db != nil {
		hookKEKMac := hmac.New(sha256.New, []byte(cfg.Auth.Pepper))
		hookKEKMac.Write([]byte("hook-signing-kek"))
		hookKEK := hookKEKMac.Sum(nil)
		hookEngine = hook.NewEngine(db, hookKEK, logger, cfg.DevMode)

		// Wire hook engine into all services.
		authSvc.SetHookCaller(hookEngine)
		jwtSvc.SetHookCaller(hookEngine)
		refreshSvc.SetHookCaller(hookEngine)
		sessionSvc.SetHookCaller(hookEngine)
		if mfaSvc != nil {
			mfaSvc.SetHookCaller(hookEngine)
		}
		if socialSvc != nil {
			socialSvc.SetHookCaller(hookEngine)
		}
	}

	// Rate limit middlewares.
	var rl *ratelimit.RouteMiddlewares
	if rdb != nil {
		rl = ratelimit.NewRouteMiddlewares(rdb.Unwrap(), logger)
	}

	s := &Server{
		cfg:          cfg,
		router:       r,
		logger:       logger,
		db:           db,
		redis:        rdb,
		adminSvc:     adminSvc,
		adminUserSvc: adminUserSvc,
		projectSvc:   projectSvc,
		apikeySvc:    apikeySvc,
		auditSvc:     auditSvc,
		sessionSvc:   sessionSvc,
		jwtSvc:       jwtSvc,
		refreshSvc:   refreshSvc,
		customSvc:    customSvc,
		authSvc:      authSvc,
		mfaSvc:       mfaSvc,
		socialSvc:    socialSvc,
		hookEngine:   hookEngine,
		rl:           rl,
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

		// Admin MFA routes (no admin auth required — uses MFA token from login).
		if s.mfaSvc != nil {
			r.Post("/admin/mfa/enroll", s.handleAdminMFAEnroll)
			r.Post("/admin/mfa/verify", s.handleAdminMFAVerifyEnrollment)
			r.Post("/admin/mfa/challenge", s.handleAdminMFAChallenge)
		}
	})

	// JWKS endpoint (public, no auth).
	s.router.Get("/.well-known/jwks.json", s.handleJWKS)

	// Public auth routes (API key required).
	s.router.Route("/auth", func(r chi.Router) {
		r.Use(CacheControl)
		r.Use(s.apikeySvc.Middleware(s.logger))
		r.Post("/signup", s.handleSignup)
		if s.rl != nil {
			r.With(s.rl.LoginByIP).Post("/login", s.handleLogin)
		} else {
			r.Post("/login", s.handleLogin)
		}
		r.Post("/verify-email", s.handleVerifyEmail)
		r.Post("/resend-verification", s.handleResendVerification)
		if s.rl != nil {
			r.With(s.rl.PasswordByAccount).Post("/password/reset", s.handlePasswordResetRequest)
		} else {
			r.Post("/password/reset", s.handlePasswordResetRequest)
		}
		r.Post("/password/reset/confirm", s.handlePasswordResetConfirm)
		r.Post("/password/change", s.handlePasswordChange)
		r.Post("/token/refresh", s.handleRefreshToken)
		r.Post("/token/exchange", s.handleExchangeCustomToken)

		// OAuth social login routes.
		r.Get("/oauth/{provider}/authorize", s.handleOAuthAuthorize)
		r.Get("/oauth/{provider}/callback", s.handleOAuthCallback)
		r.Post("/oauth/credential", s.handleCredentialExchange)

		// MFA routes (require mfa_token, no session).
		if s.mfaSvc != nil {
			r.Post("/mfa/challenge", s.handleMFAChallenge)
			r.Post("/mfa/recovery", s.handleMFARecovery)
			r.Post("/mfa/email/challenge", s.handleMFAEmailChallenge)
			r.Post("/mfa/email/verify", s.handleMFAEmailVerify)
		}

		// Authenticated routes (require valid session).
		r.Group(func(r chi.Router) {
			r.Use(s.sessionMiddleware)
			r.Get("/sessions", s.handleListSessions)
			r.Delete("/sessions/{id}", s.handleRevokeSession)
			r.Delete("/sessions", s.handleRevokeAllSessions)
			r.Post("/logout", s.handleLogout)

			// Social identity management routes (require session).
			r.Get("/identities", s.handleListIdentities)
			r.Post("/identities/link", s.handleLinkIdentity)
			r.Delete("/identities/{id}", s.handleUnlinkIdentity)

			// MFA management routes (require session).
			if s.mfaSvc != nil {
				r.Post("/mfa/enroll", s.handleMFAEnroll)
				r.Post("/mfa/verify", s.handleMFAVerifyEnrollment)
				r.Get("/mfa/factors", s.handleMFAFactors)
				r.Delete("/mfa/factors/{id}", s.handleMFARemoveFactor)
				r.Post("/mfa/recovery-codes/regenerate", s.handleMFARegenerateRecoveryCodes)
				r.Post("/mfa/email/enroll", s.handleMFAEmailEnroll)
			}
		})
	})

	// Admin custom token endpoint.
	s.router.Route("/admin/token", func(r chi.Router) {
		r.Use(CacheControl)
		r.Use(s.adminSvc.AuthMiddleware())
		r.Use(s.apikeySvc.Middleware(s.logger))
		r.Post("/custom", s.handleCreateCustomToken)
	})

	// OAuth endpoints (API key auth required).
	s.router.Route("/oauth", func(r chi.Router) {
		r.Use(CacheControl)
		r.Use(s.apikeySvc.Middleware(s.logger))
		r.Post("/introspect", s.handleIntrospect)
		r.Post("/revoke", s.handleRevoke)
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
			r.Get("/audit-logs", s.handleListAuditLogs)
			r.Post("/audit-logs/verify", s.handleVerifyAuditLogs)
			r.Get("/audit-logs/export", s.handleExportAuditLogs)

			// User CRUD.
			r.Post("/users", s.handleAdminCreateUser)
			r.Get("/users", s.handleAdminListUsers)
			r.Get("/users/{uid}", s.handleAdminGetUser)
			r.Put("/users/{uid}", s.handleAdminUpdateUser)
			r.Delete("/users/{uid}", s.handleAdminDeleteUser)
			r.Post("/users/{uid}/ban", s.handleAdminBanUser)
			r.Post("/users/{uid}/unban", s.handleAdminUnbanUser)
			r.Post("/users/{uid}/reset-password", s.handleAdminResetPassword)

			// Hook management.
			r.Get("/hooks", s.handleListHooks)
			r.Post("/hooks", s.handleCreateHook)
			r.Put("/hooks/{hid}", s.handleUpdateHook)
			r.Delete("/hooks/{hid}", s.handleDeleteHook)
			r.Post("/hooks/{hid}/test", s.handleTestHook)
			r.Get("/hooks/{hid}/logs", s.handleHookLogs)

			// Analytics.
			r.Get("/analytics", s.handleProjectAnalytics)
		})

		// Admin invite (not project-scoped).
		r.Post("/users/invite", s.handleAdminInvite)

		// Inactive deactivation (cron endpoint).
		r.Post("/deactivate-inactive", s.handleDeactivateInactive)
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

// newQueries creates a new sqlc.Queries instance.
func (s *Server) newQueries() *sqlc.Queries {
	return sqlc.New(s.db)
}

// createSessionParams builds session creation parameters using AAL-based timeouts.
func (s *Server) createSessionParams(projectID, userID string, ip, userAgent *string, acr string, amr []string, authTime time.Time) (sqlc.CreateSessionParams, error) {
	amrJSON, err := json.Marshal(amr)
	if err != nil {
		return sqlc.CreateSessionParams{}, fmt.Errorf("marshal amr: %w", err)
	}

	idleTimeout, absTimeout := session.AALTimeouts(acr)

	var idleTimeoutAt pgtype.Timestamptz
	if idleTimeout > 0 {
		idleTimeoutAt = pgtype.Timestamptz{Time: authTime.Add(idleTimeout), Valid: true}
	}

	return sqlc.CreateSessionParams{
		ID:            id.New("sess_"),
		ProjectID:     projectID,
		UserID:        userID,
		Ip:            ip,
		UserAgent:     userAgent,
		Acr:           acr,
		Amr:           amrJSON,
		IdleTimeoutAt: idleTimeoutAt,
		AbsTimeoutAt:  pgtype.Timestamptz{Time: authTime.Add(absTimeout), Valid: true},
	}, nil
}

// JWTService returns the JWT service for testing and external use.
func (s *Server) JWTService() *token.JWTService {
	return s.jwtSvc
}

// SessionService returns the session service for testing and external use.
func (s *Server) SessionService() *session.Service {
	return s.sessionSvc
}
