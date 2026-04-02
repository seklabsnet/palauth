package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
)

// VerifyEmailByToken verifies a user's email using a link-based verification token.
func (s *Service) VerifyEmailByToken(ctx context.Context, plainToken, projectID string) error {
	if plainToken == "" {
		return ErrTokenRequired
	}

	q := sqlc.New(s.db)

	// Hash the token and look up in DB (project_id filter for multi-tenant isolation).
	tokenHash := sha256Hash(plainToken)
	vt, err := q.GetVerificationTokenByHash(ctx, sqlc.GetVerificationTokenByHashParams{
		TokenHash: tokenHash,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenNotFound
		}
		return fmt.Errorf("get verification token: %w", err)
	}

	// Check expiry.
	if vt.ExpiresAt.Valid && time.Now().After(vt.ExpiresAt.Time) {
		return ErrTokenExpired
	}

	// Check already used (belt-and-suspenders; query already filters used=false).
	if vt.Used {
		return ErrTokenUsed
	}

	// Mark token as used.
	if err := q.MarkVerificationTokenUsed(ctx, vt.ID); err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}

	// Update user email_verified.
	if err := q.UpdateUserEmailVerified(ctx, vt.UserID); err != nil {
		return fmt.Errorf("update email verified: %w", err)
	}

	// Audit log.
	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventAuthEmailVerify,
		Actor:      audit.ActorInfo{UserID: vt.UserID},
		Target:     &audit.TargetInfo{Type: "user", ID: vt.UserID},
		Result:     "success",
		AuthMethod: "email_link",
		ProjectID:  projectID,
	})

	return nil
}

// maxOTPAttempts is the maximum number of failed OTP verification attempts
// before the token is invalidated (PSD2 RTS Art. 4(3)(d)).
const maxOTPAttempts = 5

// VerifyEmailByCode verifies a user's email using an OTP code.
func (s *Service) VerifyEmailByCode(ctx context.Context, code, email, projectID string) error {
	if code == "" {
		return ErrTokenRequired
	}
	if email == "" {
		return ErrEmailRequired
	}

	// Normalize email: lowercase + trim whitespace.
	email = normalizeEmail(email)

	q := sqlc.New(s.db)

	// Look up user by email hash.
	emailHash, err := s.emailHashBytes(email)
	if err != nil {
		return err
	}

	user, err := q.GetUserByEmailHash(ctx, sqlc.GetUserByEmailHashParams{
		ProjectID: projectID,
		EmailHash: emailHash,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}

	// Look up latest OTP verification token for this user (project_id filter).
	vt, err := q.GetVerificationTokenByUserAndType(ctx, sqlc.GetVerificationTokenByUserAndTypeParams{
		UserID:    user.ID,
		Type:      "email_verify_otp",
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenNotFound
		}
		return fmt.Errorf("get verification token: %w", err)
	}

	// Check if max attempts exceeded (PSD2 RTS — max 5 failed attempts).
	if vt.FailedAttempts >= maxOTPAttempts {
		return ErrOTPMaxAttempts
	}

	// Check expiry.
	if vt.ExpiresAt.Valid && time.Now().After(vt.ExpiresAt.Time) {
		return ErrTokenExpired
	}

	// Constant-time comparison of code hashes.
	codeHash := sha256Hash(code)
	if !constantTimeTokenCompare(codeHash, vt.TokenHash) {
		// Increment failed attempts; invalidate token if max reached.
		attempts, incErr := q.IncrementVerificationFailedAttempts(ctx, vt.ID)
		if incErr != nil {
			s.logger.Error("failed to increment OTP attempts", "error", incErr)
		}
		if attempts >= maxOTPAttempts {
			_ = q.MarkVerificationTokenUsed(ctx, vt.ID)
			return ErrOTPMaxAttempts
		}
		return ErrTokenNotFound
	}

	// Mark token as used.
	if err := q.MarkVerificationTokenUsed(ctx, vt.ID); err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}

	// Update user email_verified.
	if err := q.UpdateUserEmailVerified(ctx, user.ID); err != nil {
		return fmt.Errorf("update email verified: %w", err)
	}

	// Audit log.
	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventAuthEmailVerify,
		Actor:      audit.ActorInfo{UserID: user.ID},
		Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
		Result:     "success",
		AuthMethod: "email_otp",
		ProjectID:  projectID,
	})

	return nil
}

// emailHashBytes computes the deterministic email hash and returns raw bytes.
func (s *Service) emailHashBytes(email string) ([]byte, error) {
	emailHash := crypto.DeterministicHash(email, s.emailHashKey)
	b, err := hex.DecodeString(emailHash)
	if err != nil {
		return nil, fmt.Errorf("decode email hash: %w", err)
	}
	return b, nil
}
