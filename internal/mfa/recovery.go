package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/palauth/palauth/internal/audit"
	pcrypto "github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

const (
	// RecoveryCodeCount is the number of recovery codes to generate.
	RecoveryCodeCount = 10

	// RecoveryCodeLength is the byte length of each recovery code.
	// 5 bytes = 8 base32 chars.
	RecoveryCodeLength = 5
)

// GenerateRecoveryCodes generates recovery codes, hashes them, and stores in DB.
// Returns plaintext codes that should only be shown once.
func (s *Service) GenerateRecoveryCodes(ctx context.Context, projectID, userID string) ([]string, error) {
	q := sqlc.New(s.db)

	// Delete any existing recovery codes.
	if err := q.DeleteRecoveryCodesByUser(ctx, sqlc.DeleteRecoveryCodesByUserParams{
		UserID:    userID,
		ProjectID: projectID,
	}); err != nil {
		return nil, fmt.Errorf("delete existing recovery codes: %w", err)
	}

	codes := make([]string, 0, RecoveryCodeCount)

	for i := 0; i < RecoveryCodeCount; i++ {
		// Generate random bytes.
		b := make([]byte, RecoveryCodeLength)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}

		// Encode as base32, lowercase, no padding.
		code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))

		// Hash with Argon2id.
		hash, err := pcrypto.Hash(padRecoveryCode(code), s.pepper)
		if err != nil {
			return nil, fmt.Errorf("hash recovery code: %w", err)
		}

		_, err = q.CreateRecoveryCode(ctx, sqlc.CreateRecoveryCodeParams{
			ID:        id.New("rc_"),
			UserID:    userID,
			ProjectID: projectID,
			CodeHash:  hash,
		})
		if err != nil {
			return nil, fmt.Errorf("store recovery code: %w", err)
		}

		codes = append(codes, code)
	}

	return codes, nil
}

// UseRecoveryCode attempts to use a recovery code for MFA bypass.
// On success: marks code as used, revokes all other sessions, sets has_mfa=false.
func (s *Service) UseRecoveryCode(ctx context.Context, projectID, userID, code string) error {
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

	// Get all unused recovery codes.
	codes, err := q.ListUnusedRecoveryCodes(ctx, sqlc.ListUnusedRecoveryCodesParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("list recovery codes: %w", err)
	}

	if len(codes) == 0 {
		return ErrNoRecoveryCodesLeft
	}

	// Try to match the code against all hashes (constant-time per comparison).
	paddedCode := padRecoveryCode(code)
	var matchedID string
	for i := range codes {
		match, err := pcrypto.Verify(paddedCode, codes[i].CodeHash, s.pepper)
		if err != nil {
			continue
		}
		if match {
			matchedID = codes[i].ID
			break
		}
	}

	if matchedID == "" {
		// Record failure.
		if s.lockoutSvc != nil {
			locked, _ := s.lockoutSvc.RecordFailure(ctx, projectID, userID)
			if locked {
				s.logger.Warn("MFA locked after failed recovery code attempts",
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
			Metadata:  map[string]any{"type": "recovery", "reason": "invalid_code"},
		})

		return ErrInvalidCode
	}

	// Mark code as used.
	if err := q.MarkRecoveryCodeUsed(ctx, sqlc.MarkRecoveryCodeUsedParams{
		ID:        matchedID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("mark recovery code used: %w", err)
	}

	// Revoke all other sessions (spec Section 11.2).
	if s.sessionSvc != nil {
		if err := s.sessionSvc.RevokeAll(ctx, userID, projectID); err != nil {
			s.logger.Error("failed to revoke sessions after recovery code use", "error", err)
		}
	}

	// Set has_mfa=false — user must re-enroll (spec Section 11.2).
	if err := q.UpdateUserHasMFA(ctx, sqlc.UpdateUserHasMFAParams{
		ID:        userID,
		HasMfa:    false,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("update user has_mfa: %w", err)
	}

	// Delete all MFA enrollments.
	if err := q.DeleteMFAEnrollmentsByUser(ctx, sqlc.DeleteMFAEnrollmentsByUserParams{
		UserID:    userID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("delete mfa enrollments: %w", err)
	}

	// Reset lockout on success.
	if s.lockoutSvc != nil {
		s.lockoutSvc.Reset(ctx, projectID, userID)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventMFARecoveryUsed,
		Actor:     audit.ActorInfo{UserID: userID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"type": "recovery"},
	})

	return nil
}

// RegenerateRecoveryCodes generates new recovery codes, replacing the old ones.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, projectID, userID string) ([]string, error) {
	return s.GenerateRecoveryCodes(ctx, projectID, userID)
}

// padRecoveryCode pads a recovery code to meet the minimum password length for Argon2id.
// Recovery codes are 8 chars but Argon2id requires 15+ chars.
func padRecoveryCode(code string) string {
	return "palauth-rc:" + code
}
