package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/email"
	"github.com/palauth/palauth/internal/project"
	"github.com/palauth/palauth/internal/token"
)

var (
	ErrEmailRequired    = errors.New("email is required")
	ErrPasswordRequired = errors.New("password is required")
	ErrTokenRequired    = errors.New("verification token is required")
	ErrTokenUsed        = errors.New("verification token has already been used")
	ErrTokenExpired     = errors.New("verification token has expired")
	ErrTokenNotFound    = errors.New("verification token not found")
	ErrSignupFailed     = errors.New("signup failed")
	ErrHIBPUnavailable  = errors.New("password breach check unavailable, please retry")
	ErrOTPMaxAttempts   = errors.New("maximum verification attempts exceeded")
)

// MFAChecker checks if a user has MFA enrolled and issues MFA tokens.
type MFAChecker interface {
	HasMFA(ctx context.Context, projectID, userID string) (bool, []string, error)
	IssueMFATokenForLogin(ctx context.Context, userID, projectID, ip, userAgent string) (string, error)
}

// Service handles authentication operations: signup, login, email verification, resend.
type Service struct {
	db             *pgxpool.Pool
	projectSvc     *project.Service
	jwtSvc         *token.JWTService
	refreshSvc     *token.RefreshService
	auditSvc       *audit.Service
	breachChecker  *crypto.BreachChecker
	lockoutSvc     *LockoutService
	mfaChecker     MFAChecker
	emailSender    email.Sender
	emailRenderer  *email.TemplateRenderer
	pepper         string
	kek            []byte
	emailHashKey   []byte
	logger         *slog.Logger
}

// NewService creates a new auth service.
func NewService(
	db *pgxpool.Pool,
	projectSvc *project.Service,
	jwtSvc *token.JWTService,
	refreshSvc *token.RefreshService,
	auditSvc *audit.Service,
	breachChecker *crypto.BreachChecker,
	lockoutSvc *LockoutService,
	emailSender email.Sender,
	emailRenderer *email.TemplateRenderer,
	pepper string,
	kek []byte,
	logger *slog.Logger,
) *Service {
	// Derive email hash key from pepper via HMAC-SHA256 for key separation.
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte("email-hash-key"))
	emailHashKey := mac.Sum(nil)

	return &Service{
		db:            db,
		projectSvc:    projectSvc,
		jwtSvc:        jwtSvc,
		refreshSvc:    refreshSvc,
		auditSvc:      auditSvc,
		breachChecker: breachChecker,
		lockoutSvc:    lockoutSvc,
		emailSender:   emailSender,
		emailRenderer: emailRenderer,
		pepper:        pepper,
		kek:           kek,
		emailHashKey:  emailHashKey,
		logger:        logger,
	}
}

// SetMFAChecker sets the MFA checker on the service. This is called after
// construction to break the circular dependency between auth and mfa packages.
func (s *Service) SetMFAChecker(checker MFAChecker) {
	s.mfaChecker = checker
}

// normalizeEmail lowercases and trims whitespace from an email address.
func normalizeEmail(addr string) string {
	return strings.ToLower(strings.TrimSpace(addr))
}

// auditLog safely logs an audit event, handling nil auditSvc for unit tests.
func (s *Service) auditLog(ctx context.Context, event *audit.Event) {
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, event) //nolint:errcheck // best-effort audit
	}
}
