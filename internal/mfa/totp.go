package mfa

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

const (
	// TOTPIssuer is the issuer name shown in authenticator apps.
	TOTPIssuer = "PalAuth"

	// TOTPPeriod is the TOTP time step in seconds (RFC 6238).
	TOTPPeriod = 30

	// TOTPDigits is the number of digits in the TOTP code.
	TOTPDigits = 6

	// TOTPSkew is the number of periods to allow for clock drift (±1 period = ±30s).
	// A skew of 1 allows current period ± 1 period = ±30s drift.
	// For ±60s we use skew=2 which allows current period ± 2 = ±60s.
	TOTPSkew = 2

	// replayWindowSec is how long we block a TOTP code from being reused.
	replayWindowSec = 90 // 30s period * 3 to cover the full skew window
)

// TOTPEnrollmentResult contains the result of a TOTP enrollment.
type TOTPEnrollmentResult struct {
	EnrollmentID string `json:"enrollment_id"`
	Secret       string `json:"secret"`
	OTPURL       string `json:"otp_url"`
	QRCode       string `json:"qr_code"` // base64-encoded PNG
}

// EnrollTOTP creates a new TOTP enrollment for a user.
func (s *Service) EnrollTOTP(ctx context.Context, projectID, userID, userEmail string) (*TOTPEnrollmentResult, error) {
	q := sqlc.New(s.db)

	// Check if user already has a TOTP enrollment (verified or not).
	existing, err := q.GetMFAEnrollmentByUserAndType(ctx, sqlc.GetMFAEnrollmentByUserAndTypeParams{
		UserID:    userID,
		ProjectID: projectID,
		Type:      "totp",
	})
	if err == nil {
		if existing.Verified {
			return nil, ErrMFAAlreadyVerified
		}
		// Delete unverified enrollment so user can re-enroll.
		if err := q.DeleteMFAEnrollment(ctx, sqlc.DeleteMFAEnrollmentParams{
			ID:        existing.ID,
			ProjectID: projectID,
		}); err != nil {
			return nil, fmt.Errorf("delete unverified enrollment: %w", err)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check existing enrollment: %w", err)
	}

	// Generate TOTP key.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: userEmail,
		Period:      TOTPPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	// Encrypt secret with per-user DEK.
	userDEK, err := s.getOrCreateMFADEK(ctx, q, userID, projectID)
	if err != nil {
		return nil, fmt.Errorf("get user DEK: %w", err)
	}

	secretAAD := []byte("totp-secret:" + projectID + ":" + userID)
	encryptedSecret, err := crypto.Encrypt([]byte(key.Secret()), userDEK, secretAAD)
	if err != nil {
		return nil, fmt.Errorf("encrypt totp secret: %w", err)
	}

	enrollmentID := id.New("mfa_")
	_, err = q.CreateMFAEnrollment(ctx, sqlc.CreateMFAEnrollmentParams{
		ID:              enrollmentID,
		ProjectID:       projectID,
		UserID:          userID,
		Type:            "totp",
		SecretEncrypted: encryptedSecret,
		Verified:        false,
	})
	if err != nil {
		return nil, fmt.Errorf("create mfa enrollment: %w", err)
	}

	// Generate QR code.
	qrPNG, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("generate qr code: %w", err)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventMFAEnroll,
		Actor:     audit.ActorInfo{UserID: userID},
		Target:    &audit.TargetInfo{Type: "mfa_enrollment", ID: enrollmentID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"type": "totp"},
	})

	return &TOTPEnrollmentResult{
		EnrollmentID: enrollmentID,
		Secret:       key.Secret(),
		OTPURL:       key.URL(),
		QRCode:       base64.StdEncoding.EncodeToString(qrPNG),
	}, nil
}

// VerifyTOTPEnrollment verifies a TOTP enrollment by checking the code.
// This completes the enrollment process and sets has_mfa=true.
func (s *Service) VerifyTOTPEnrollment(ctx context.Context, projectID, userID, code string) error {
	q := sqlc.New(s.db)

	enrollment, err := q.GetMFAEnrollmentByUserAndType(ctx, sqlc.GetMFAEnrollmentByUserAndTypeParams{
		UserID:    userID,
		ProjectID: projectID,
		Type:      "totp",
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get enrollment: %w", err)
	}

	if enrollment.Verified {
		return ErrMFAAlreadyVerified
	}

	// Decrypt secret.
	userDEK, err := s.getOrCreateMFADEK(ctx, q, userID, projectID)
	if err != nil {
		return fmt.Errorf("get user DEK: %w", err)
	}

	secretAAD := []byte("totp-secret:" + projectID + ":" + userID)
	secret, err := crypto.Decrypt(enrollment.SecretEncrypted, userDEK, secretAAD)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	// Validate code with explicit opts matching enrollment params.
	valid, _ := totp.ValidateCustom(code, string(secret), time.Now(), totp.ValidateOpts{
		Period:    TOTPPeriod,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Skew:      TOTPSkew,
	})

	if !valid {
		s.auditLog(ctx, &audit.Event{
			EventType: audit.EventMFAVerifyFailure,
			Actor:     audit.ActorInfo{UserID: userID},
			Target:    &audit.TargetInfo{Type: "mfa_enrollment", ID: enrollment.ID},
			Result:    "failure",
			ProjectID: projectID,
			Metadata:  map[string]any{"type": "totp", "reason": "invalid_code"},
		})
		return ErrInvalidCode
	}

	// Mark enrollment as verified.
	if err := q.VerifyMFAEnrollment(ctx, sqlc.VerifyMFAEnrollmentParams{
		ID:        enrollment.ID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("verify enrollment: %w", err)
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
		EventType: audit.EventMFAVerifySuccess,
		Actor:     audit.ActorInfo{UserID: userID},
		Target:    &audit.TargetInfo{Type: "mfa_enrollment", ID: enrollment.ID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"type": "totp"},
	})

	return nil
}

// ValidateTOTPChallenge validates a TOTP code during MFA challenge (login flow).
// Includes lockout checking and replay protection.
func (s *Service) ValidateTOTPChallenge(ctx context.Context, projectID, userID, code string) error {
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

	q := sqlc.New(s.db)

	enrollment, err := q.GetVerifiedMFAEnrollmentByUserAndType(ctx, sqlc.GetVerifiedMFAEnrollmentByUserAndTypeParams{
		UserID:    userID,
		ProjectID: projectID,
		Type:      "totp",
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get enrollment: %w", err)
	}

	// Decrypt secret.
	userDEK, err := s.getOrCreateMFADEK(ctx, q, userID, projectID)
	if err != nil {
		return fmt.Errorf("get user DEK: %w", err)
	}

	secretAAD := []byte("totp-secret:" + projectID + ":" + userID)
	secret, err := crypto.Decrypt(enrollment.SecretEncrypted, userDEK, secretAAD)
	if err != nil {
		return fmt.Errorf("decrypt totp secret: %w", err)
	}

	// Validate with extended skew for clock drift (±60s).
	valid, err := totp.ValidateCustom(code, string(secret), time.Now(), totp.ValidateOpts{
		Period:    TOTPPeriod,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Skew:      TOTPSkew,
	})
	if err != nil {
		return fmt.Errorf("validate totp: %w", err)
	}

	if !valid {
		// Record failure.
		if s.lockoutSvc != nil {
			locked, _ := s.lockoutSvc.RecordFailure(ctx, projectID, userID)
			if locked {
				s.logger.Warn("MFA locked after failed attempts",
					"user_id", userID,
					"project_id", projectID,
				)
			}
		}

		s.auditLog(ctx, &audit.Event{
			EventType: audit.EventMFAVerifyFailure,
			Actor:     audit.ActorInfo{UserID: userID},
			Target:    &audit.TargetInfo{Type: "mfa_enrollment", ID: enrollment.ID},
			Result:    "failure",
			ProjectID: projectID,
			Metadata:  map[string]any{"type": "totp", "reason": "invalid_code"},
		})

		return ErrInvalidCode
	}

	// Replay protection: atomic check-and-set using SET with NX option.
	// The key includes the code itself, so if the key already exists the code was already used.
	if s.rdb != nil {
		replayKey := fmt.Sprintf("palauth:totp_replay:%s:%s:%s", projectID, userID, code)
		_, err := s.rdb.SetArgs(ctx, replayKey, "1", redis.SetArgs{
			Mode: "NX",
			TTL:  time.Duration(replayWindowSec) * time.Second,
		}).Result()
		if errors.Is(err, redis.Nil) {
			// Key already exists — code was recently used.
			return ErrReplayDetected
		}
		if err != nil {
			s.logger.Warn("failed to check totp replay", "error", err)
		}
	}

	// Reset lockout on success.
	if s.lockoutSvc != nil {
		s.lockoutSvc.Reset(ctx, projectID, userID)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventMFAVerifySuccess,
		Actor:     audit.ActorInfo{UserID: userID},
		Target:    &audit.TargetInfo{Type: "mfa_enrollment", ID: enrollment.ID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"type": "totp"},
	})

	return nil
}

// RemoveTOTP removes a TOTP enrollment. The caller must ensure re-authentication has occurred.
func (s *Service) RemoveTOTP(ctx context.Context, projectID, userID string) error {
	q := sqlc.New(s.db)

	enrollment, err := q.GetMFAEnrollmentByUserAndType(ctx, sqlc.GetMFAEnrollmentByUserAndTypeParams{
		UserID:    userID,
		ProjectID: projectID,
		Type:      "totp",
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get enrollment: %w", err)
	}

	if err := q.DeleteMFAEnrollment(ctx, sqlc.DeleteMFAEnrollmentParams{
		ID:        enrollment.ID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("delete enrollment: %w", err)
	}

	// Check if user still has any verified MFA enrollments.
	remaining, err := q.ListVerifiedMFAEnrollments(ctx, sqlc.ListVerifiedMFAEnrollmentsParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("list remaining enrollments: %w", err)
	}

	if len(remaining) == 0 {
		if err := q.UpdateUserHasMFA(ctx, sqlc.UpdateUserHasMFAParams{
			ID:        userID,
			HasMfa:    false,
			ProjectID: projectID,
		}); err != nil {
			return fmt.Errorf("update user has_mfa: %w", err)
		}
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventMFARemove,
		Actor:     audit.ActorInfo{UserID: userID},
		Target:    &audit.TargetInfo{Type: "mfa_enrollment", ID: enrollment.ID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"type": "totp"},
	})

	return nil
}

// ListFactors returns all MFA enrollments for a user.
func (s *Service) ListFactors(ctx context.Context, projectID, userID string) ([]Factor, error) {
	q := sqlc.New(s.db)

	enrollments, err := q.ListMFAEnrollments(ctx, sqlc.ListMFAEnrollmentsParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, fmt.Errorf("list enrollments: %w", err)
	}

	factors := make([]Factor, 0, len(enrollments))
	for i := range enrollments {
		factors = append(factors, Factor{
			ID:        enrollments[i].ID,
			Type:      enrollments[i].Type,
			Verified:  enrollments[i].Verified,
			CreatedAt: enrollments[i].CreatedAt.Time.UTC().Format(time.RFC3339),
		})
	}

	return factors, nil
}

// RemoveFactor removes an MFA enrollment by ID.
func (s *Service) RemoveFactor(ctx context.Context, projectID, userID, enrollmentID string) error {
	q := sqlc.New(s.db)

	enrollment, err := q.GetMFAEnrollment(ctx, sqlc.GetMFAEnrollmentParams{
		ID:        enrollmentID,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get enrollment: %w", err)
	}

	// Verify ownership.
	if enrollment.UserID != userID {
		return ErrMFANotEnrolled
	}

	if err := q.DeleteMFAEnrollment(ctx, sqlc.DeleteMFAEnrollmentParams{
		ID:        enrollmentID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("delete enrollment: %w", err)
	}

	// Check if user still has any verified MFA enrollments.
	remaining, err := q.ListVerifiedMFAEnrollments(ctx, sqlc.ListVerifiedMFAEnrollmentsParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("list remaining enrollments: %w", err)
	}

	if len(remaining) == 0 {
		if err := q.UpdateUserHasMFA(ctx, sqlc.UpdateUserHasMFAParams{
			ID:        userID,
			HasMfa:    false,
			ProjectID: projectID,
		}); err != nil {
			return fmt.Errorf("update user has_mfa: %w", err)
		}

		// Also delete recovery codes since MFA is fully disabled.
		if err := q.DeleteRecoveryCodesByUser(ctx, sqlc.DeleteRecoveryCodesByUserParams{
			UserID:    userID,
			ProjectID: projectID,
		}); err != nil {
			return fmt.Errorf("delete recovery codes: %w", err)
		}
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventMFARemove,
		Actor:     audit.ActorInfo{UserID: userID},
		Target:    &audit.TargetInfo{Type: "mfa_enrollment", ID: enrollmentID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"type": enrollment.Type},
	})

	return nil
}

// Factor represents a user's MFA enrollment for API responses.
type Factor struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
}

// getOrCreateMFADEK retrieves or creates a per-user MFA data encryption key.
// Uses a separate key_type "mfa_user_dek" to avoid conflicts with audit/auth user DEKs
// which use different KEKs.
func (s *Service) getOrCreateMFADEK(ctx context.Context, q *sqlc.Queries, userID, projectID string) ([]byte, error) {
	dekAAD := []byte("mfa-dek:" + projectID + ":" + userID)

	// Look for existing MFA DEK.
	ek, err := q.GetEncryptionKeyByTypeAndUser(ctx, sqlc.GetEncryptionKeyByTypeAndUserParams{
		UserID:    &userID,
		ProjectID: &projectID,
		KeyType:   "mfa_user_dek",
	})
	if err == nil {
		return crypto.Decrypt(ek.EncryptedKey, s.kek, dekAAD)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get mfa DEK: %w", err)
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
		UserID:       &userID,
		EncryptedKey: encryptedDEK,
		KeyType:      "mfa_user_dek",
	})
	if err != nil {
		return nil, fmt.Errorf("create encryption key: %w", err)
	}

	return dek, nil
}
