package mfa

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

const (
	// EmailOTPDigits is the number of digits in the email OTP.
	EmailOTPDigits = 6

	// EmailOTPTTL is the OTP expiry time (PSD2 RTS max 5dk).
	EmailOTPTTL = 5 * time.Minute

	// EmailOTPMaxAttempts is the max failed attempts before requiring a new OTP.
	EmailOTPMaxAttempts = 3

	emailOTPSubject = "Your verification code"
)

// EnrollEmail creates an email OTP enrollment for a user.
// The user must have a verified email address.
func (s *Service) EnrollEmail(ctx context.Context, projectID, userID string) error {
	q := sqlc.New(s.db)

	// Check if user already has an email enrollment.
	existing, err := q.GetMFAEnrollmentByUserAndType(ctx, sqlc.GetMFAEnrollmentByUserAndTypeParams{
		UserID:    userID,
		ProjectID: projectID,
		Type:      "email",
	})
	if err == nil {
		if existing.Verified {
			return ErrMFAAlreadyVerified
		}
		// Delete unverified enrollment so user can re-enroll.
		if err := q.DeleteMFAEnrollment(ctx, sqlc.DeleteMFAEnrollmentParams{
			ID:        existing.ID,
			ProjectID: projectID,
		}); err != nil {
			return fmt.Errorf("delete unverified enrollment: %w", err)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check existing enrollment: %w", err)
	}

	// Check that user has verified email.
	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !user.EmailVerified {
		return ErrEmailNotVerified
	}

	enrollmentID := id.New("mfa_")
	_, err = q.CreateMFAEnrollment(ctx, sqlc.CreateMFAEnrollmentParams{
		ID:        enrollmentID,
		ProjectID: projectID,
		UserID:    userID,
		Type:      "email",
		Verified:  true, // Email OTP is immediately verified since email is already verified.
	})
	if err != nil {
		return fmt.Errorf("create mfa enrollment: %w", err)
	}

	// Set has_mfa=true on user.
	if err := q.UpdateUserHasMFA(ctx, sqlc.UpdateUserHasMFAParams{
		ID:        userID,
		HasMfa:    true,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("update user has_mfa: %w", err)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventMFAEnroll,
		Actor:     audit.ActorInfo{UserID: userID},
		Target:    &audit.TargetInfo{Type: "mfa_enrollment", ID: enrollmentID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"type": "email"},
	})

	return nil
}

// SendEmailChallenge generates and sends an email OTP for MFA challenge.
func (s *Service) SendEmailChallenge(ctx context.Context, projectID, userID, userEmail string) error {
	q := sqlc.New(s.db)

	// Verify user has email MFA enrolled.
	_, err := q.GetVerifiedMFAEnrollmentByUserAndType(ctx, sqlc.GetVerifiedMFAEnrollmentByUserAndTypeParams{
		UserID:    userID,
		ProjectID: projectID,
		Type:      "email",
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get enrollment: %w", err)
	}

	// Generate OTP.
	code, err := crypto.GenerateOTP(EmailOTPDigits)
	if err != nil {
		return fmt.Errorf("generate otp: %w", err)
	}

	// Store SHA-256 hash of OTP in Redis (not plaintext) for defense-in-depth.
	otpKey := emailOTPKey(projectID, userID)
	otpHash := sha256.Sum256([]byte(code))
	if err := s.rdb.Set(ctx, otpKey, hex.EncodeToString(otpHash[:]), EmailOTPTTL).Err(); err != nil {
		return fmt.Errorf("store email otp: %w", err)
	}

	// Reset attempt counter.
	attemptsKey := emailOTPAttemptsKey(projectID, userID)
	if err := s.rdb.Set(ctx, attemptsKey, 0, EmailOTPTTL).Err(); err != nil {
		s.logger.Warn("failed to reset email otp attempts", "error", err)
	}

	// Send email.
	htmlBody := fmt.Sprintf(
		"<p>Your verification code is: <strong>%s</strong></p><p>This code expires in 5 minutes.</p>",
		code,
	)
	textBody := fmt.Sprintf("Your verification code is: %s\nThis code expires in 5 minutes.", code)

	if err := s.emailSender.Send(ctx, userEmail, emailOTPSubject, htmlBody, textBody); err != nil {
		return fmt.Errorf("send email otp: %w", err)
	}

	return nil
}

// VerifyEmailChallenge verifies an email OTP during MFA challenge.
func (s *Service) VerifyEmailChallenge(ctx context.Context, projectID, userID, code string) error {
	// Check lockout.
	if s.lockoutSvc != nil {
		locked, _, err := s.lockoutSvc.Check(ctx, projectID, userID)
		if err != nil {
			return fmt.Errorf("check mfa lockout: %w", err)
		}
		if locked {
			return ErrMFALockout
		}
	}

	otpKey := emailOTPKey(projectID, userID)
	attemptsKey := emailOTPAttemptsKey(projectID, userID)

	// Get stored OTP hash.
	storedHash, err := s.rdb.Get(ctx, otpKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrMFATokenExpired
		}
		return fmt.Errorf("get email otp: %w", err)
	}

	// Increment and check attempts.
	attempts, err := s.rdb.Incr(ctx, attemptsKey).Result()
	if err != nil {
		s.logger.Warn("failed to increment email otp attempts", "error", err)
	}

	if int(attempts) > EmailOTPMaxAttempts {
		// Delete the OTP — user must request a new one.
		s.rdb.Del(ctx, otpKey)
		s.rdb.Del(ctx, attemptsKey)
		return ErrMaxOTPAttempts
	}

	// Hash submitted code and compare with stored hash (constant-time).
	submittedHash := sha256.Sum256([]byte(code))
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(hex.EncodeToString(submittedHash[:]))) != 1 {
		if s.lockoutSvc != nil {
			locked, _ := s.lockoutSvc.RecordFailure(ctx, projectID, userID)
			if locked {
				s.logger.Warn("MFA locked after failed email OTP attempts",
					"user_id", userID,
					"project_id", projectID,
				)
			}
		}

		s.auditLog(ctx, &audit.Event{
			EventType: audit.EventMFAVerifyFailure,
			Actor:     audit.ActorInfo{UserID: userID},
			Result:    "failure",
			ProjectID: projectID,
			Metadata:  map[string]any{"type": "email", "reason": "invalid_code"},
		})

		return ErrInvalidCode
	}

	// Delete OTP after successful verification (single-use).
	s.rdb.Del(ctx, otpKey)
	s.rdb.Del(ctx, attemptsKey)

	// Reset lockout on success.
	if s.lockoutSvc != nil {
		s.lockoutSvc.Reset(ctx, projectID, userID)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventMFAVerifySuccess,
		Actor:     audit.ActorInfo{UserID: userID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"type": "email"},
	})

	return nil
}

func emailOTPKey(projectID, userID string) string {
	return fmt.Sprintf("palauth:email_otp:%s:%s:code", projectID, userID)
}

func emailOTPAttemptsKey(projectID, userID string) string {
	return fmt.Sprintf("palauth:email_otp:%s:%s:attempts", projectID, userID)
}
