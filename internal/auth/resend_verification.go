package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

// ResendResult contains the result of a resend verification request.
type ResendResult struct {
	VerificationToken string `json:"verification_token,omitempty"`
	VerificationCode  string `json:"verification_code,omitempty"`
}

// ResendVerification generates and stores a new verification token/code for the user.
// Always returns success to prevent user enumeration.
func (s *Service) ResendVerification(ctx context.Context, email, projectID string) (*ResendResult, error) {
	if email == "" {
		return nil, ErrEmailRequired
	}

	// Normalize email: lowercase + trim whitespace.
	email = normalizeEmail(email)

	q := sqlc.New(s.db)

	// Look up user by email hash.
	emailHash, err := s.emailHashBytes(email)
	if err != nil {
		return nil, err
	}

	user, err := q.GetUserByEmailHash(ctx, sqlc.GetUserByEmailHashParams{
		ProjectID: projectID,
		EmailHash: emailHash,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// User not found — return success to prevent enumeration.
			return &ResendResult{}, nil
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Already verified — return success silently.
	if user.EmailVerified {
		return &ResendResult{}, nil
	}

	// Get project config for verification method.
	proj, err := s.projectSvc.Get(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("get project config: %w", err)
	}

	result := &ResendResult{}
	verificationMethod := proj.Config.EmailVerificationMethod
	if verificationMethod == "" {
		verificationMethod = "code"
	}

	switch verificationMethod {
	case "link":
		// Invalidate any previous link-based verification tokens for this user.
		if err := q.InvalidateVerificationTokens(ctx, sqlc.InvalidateVerificationTokensParams{
			UserID:    user.ID,
			Type:      "email_verify",
			ProjectID: projectID,
		}); err != nil {
			return nil, fmt.Errorf("invalidate previous tokens: %w", err)
		}

		plainToken, genErr := crypto.GenerateToken(32)
		if genErr != nil {
			return nil, fmt.Errorf("generate verification token: %w", genErr)
		}
		tokenHash := sha256Hash(plainToken)
		_, err = q.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
			ID:        id.New("vt_"),
			ProjectID: projectID,
			UserID:    user.ID,
			TokenHash: tokenHash,
			Type:      "email_verify",
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
		})
		if err != nil {
			return nil, fmt.Errorf("create verification token: %w", err)
		}
		result.VerificationToken = plainToken
	default: // "code" or "otp"
		// Invalidate any previous OTP verification tokens for this user.
		if err := q.InvalidateVerificationTokens(ctx, sqlc.InvalidateVerificationTokensParams{
			UserID:    user.ID,
			Type:      "email_verify_otp",
			ProjectID: projectID,
		}); err != nil {
			return nil, fmt.Errorf("invalidate previous tokens: %w", err)
		}

		otp, genErr := crypto.GenerateOTP(6)
		if genErr != nil {
			return nil, fmt.Errorf("generate OTP: %w", genErr)
		}
		otpHash := sha256Hash(otp)
		_, err = q.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
			ID:        id.New("vt_"),
			ProjectID: projectID,
			UserID:    user.ID,
			TokenHash: otpHash,
			Type:      "email_verify_otp",
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(5 * time.Minute), Valid: true},
		})
		if err != nil {
			return nil, fmt.Errorf("create verification OTP: %w", err)
		}
		result.VerificationCode = otp
	}

	return result, nil
}
