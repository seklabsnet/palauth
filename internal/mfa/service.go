package mfa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/email"
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/session"
)

var (
	ErrMFANotEnrolled      = errors.New("MFA is not enrolled")
	ErrMFAAlreadyVerified  = errors.New("MFA enrollment is already verified")
	ErrInvalidCode         = errors.New("invalid code")
	ErrMFALockout          = errors.New("MFA is locked due to too many failed attempts")
	ErrMFATokenExpired     = errors.New("MFA token has expired")
	ErrMFATokenInvalid     = errors.New("MFA token is invalid")
	ErrReplayDetected      = errors.New("code has already been used")
	ErrMaxOTPAttempts      = errors.New("maximum OTP attempts exceeded, request a new code")
	ErrNoRecoveryCodesLeft = errors.New("no recovery codes remaining")
	ErrReauthRequired      = errors.New("re-authentication is required")
	ErrEmailNotVerified    = errors.New("email must be verified before enrolling email OTP")
)

// Service handles MFA operations: TOTP, Email OTP, and Recovery Codes.
type Service struct {
	db            *pgxpool.Pool
	rdb           *redis.Client
	kek           []byte
	pepper        string
	auditSvc      *audit.Service
	sessionSvc    *session.Service
	emailSender   email.Sender
	emailRenderer *email.TemplateRenderer
	lockoutSvc    *LockoutService
	logger        *slog.Logger
}

// NewService creates a new MFA service.
func NewService(
	db *pgxpool.Pool,
	rdb *redis.Client,
	kek []byte,
	pepper string,
	auditSvc *audit.Service,
	sessionSvc *session.Service,
	emailSender email.Sender,
	emailRenderer *email.TemplateRenderer,
	logger *slog.Logger,
) *Service {
	var lockoutSvc *LockoutService
	if rdb != nil {
		lockoutSvc = NewLockoutService(rdb, logger)
	}

	return &Service{
		db:            db,
		rdb:           rdb,
		kek:           kek,
		pepper:        pepper,
		auditSvc:      auditSvc,
		sessionSvc:    sessionSvc,
		emailSender:   emailSender,
		emailRenderer: emailRenderer,
		lockoutSvc:    lockoutSvc,
		logger:        logger,
	}
}

// HasMFA checks if a user has any verified MFA enrollments and returns factor types.
// Implements auth.MFAChecker interface.
func (s *Service) HasMFA(ctx context.Context, projectID, userID string) (hasMFA bool, factorTypes []string, err error) {
	q := sqlc.New(s.db)

	enrollments, err := q.ListVerifiedMFAEnrollments(ctx, sqlc.ListVerifiedMFAEnrollmentsParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return false, nil, fmt.Errorf("list mfa enrollments: %w", err)
	}

	if len(enrollments) == 0 {
		return false, nil, nil
	}

	factors := make([]string, 0, len(enrollments))
	for i := range enrollments {
		factors = append(factors, enrollments[i].Type)
	}

	return true, factors, nil
}

// IssueMFATokenForLogin issues an MFA token for the login flow.
// Implements auth.MFAChecker interface.
func (s *Service) IssueMFATokenForLogin(ctx context.Context, userID, projectID, ip, userAgent string) (string, error) {
	return s.IssueMFAToken(ctx, &TokenData{
		UserID:    userID,
		ProjectID: projectID,
		IP:        ip,
		UserAgent: userAgent,
	})
}

// GetDecryptedEmail decrypts a user's email using the project DEK.
func (s *Service) GetDecryptedEmail(ctx context.Context, projectID, userID string) (string, error) {
	q := sqlc.New(s.db)

	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		return "", fmt.Errorf("get user: %w", err)
	}

	projectDEK, err := s.getOrCreateProjectDEK(ctx, q, projectID)
	if err != nil {
		return "", fmt.Errorf("get project DEK: %w", err)
	}

	emailAAD := []byte("email:" + projectID)
	decryptedEmail, err := crypto.Decrypt(user.EmailEncrypted, projectDEK, emailAAD)
	if err != nil {
		return "", fmt.Errorf("decrypt email: %w", err)
	}

	return string(decryptedEmail), nil
}

// getOrCreateProjectDEK retrieves or creates a per-project data encryption key.
func (s *Service) getOrCreateProjectDEK(ctx context.Context, q *sqlc.Queries, projectID string) ([]byte, error) {
	dekAAD := []byte("project-dek:" + projectID)

	ek, err := q.GetProjectDEK(ctx, &projectID)
	if err == nil {
		return crypto.Decrypt(ek.EncryptedKey, s.kek, dekAAD)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get project DEK: %w", err)
	}

	dek, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}

	encryptedDEK, err := crypto.Encrypt(dek, s.kek, dekAAD)
	if err != nil {
		return nil, fmt.Errorf("encrypt DEK: %w", err)
	}

	_, err = q.CreateEncryptionKey(ctx, sqlc.CreateEncryptionKeyParams{
		ID:           id.New("ek_"),
		ProjectID:    &projectID,
		EncryptedKey: encryptedDEK,
		KeyType:      "project_dek",
	})
	if err != nil {
		return nil, fmt.Errorf("create encryption key: %w", err)
	}

	return dek, nil
}

// auditLog safely logs an audit event, handling nil auditSvc.
func (s *Service) auditLog(ctx context.Context, event *audit.Event) {
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, event) //nolint:errcheck // best-effort audit
	}
}
