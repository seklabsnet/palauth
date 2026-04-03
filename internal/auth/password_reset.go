package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/hook"
	"github.com/palauth/palauth/internal/id"
)

// RequestReset initiates a password reset by generating a token.
// Always returns nil to prevent user enumeration.
func (s *Service) RequestReset(ctx context.Context, projectID, email string) error {
	if email == "" {
		return nil // enumeration prevention: always 200
	}

	email = normalizeEmail(email)

	// Compute email hash for lookup.
	emailHash := crypto.DeterministicHash(email, s.emailHashKey)
	emailHashBytes, err := hex.DecodeString(emailHash)
	if err != nil {
		return nil // enumeration prevention
	}

	q := sqlc.New(s.db)

	user, err := q.GetUserByEmailHash(ctx, sqlc.GetUserByEmailHashParams{
		ProjectID: projectID,
		EmailHash: emailHashBytes,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// User not found — do NOT reveal this. Log and return success.
			s.logger.Debug("password reset requested for non-existing email", "project_id", projectID)
			return nil
		}
		s.logger.Error("password reset lookup failed", "error", err)
		return nil // enumeration prevention
	}

	// Execute before.password.reset hook — deny blocks reset.
	if s.hookCaller != nil {
		hookPayload := hook.Payload{
			User: &hook.UserInfo{ID: user.ID},
		}
		_, hookErr := s.hookCaller.ExecuteBlocking(ctx, projectID, hook.EventBeforePasswordReset, hookPayload)
		if hookErr != nil {
			s.logger.Info("password reset denied by hook", "user_id", user.ID, "project_id", projectID)
			return nil // enumeration prevention: always return nil
		}
	}

	// Generate 256-bit token.
	plainToken, err := crypto.GenerateToken(32)
	if err != nil {
		s.logger.Error("failed to generate reset token", "error", err)
		return nil
	}

	// SHA-256 hash the token for storage.
	tokenHash := sha256Hash(plainToken)

	// Store verification token with 15min expiry.
	_, err = q.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
		ID:        id.New("vt_"),
		ProjectID: projectID,
		UserID:    user.ID,
		TokenHash: tokenHash,
		Type:      "password_reset",
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(15 * time.Minute), Valid: true},
	})
	if err != nil {
		s.logger.Error("failed to create reset token", "error", err)
		return nil
	}

	// Send password reset email (best-effort).
	proj, projErr := s.projectSvc.Get(ctx, projectID)
	if projErr != nil {
		s.logger.Error("failed to get project for reset email", "error", projErr)
	} else {
		// Decrypt user email for sending.
		projectDEK, dekErr := s.getOrCreateProjectDEK(ctx, sqlc.New(s.db), projectID)
		if dekErr != nil {
			s.logger.Error("failed to get project DEK for reset email", "error", dekErr)
		} else {
			emailAAD := []byte("email:" + projectID)
			decryptedEmail, decErr := crypto.Decrypt(user.EmailEncrypted, projectDEK, emailAAD)
			if decErr != nil {
				s.logger.Error("failed to decrypt email for reset", "error", decErr)
			} else {
				s.sendPasswordResetEmail(ctx, string(decryptedEmail), proj.Name, plainToken)
			}
		}
	}

	// Audit log.
	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventAuthPasswordResetReq,
		Actor:      audit.ActorInfo{UserID: user.ID},
		Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
		Result:     "success",
		AuthMethod: "password",
		ProjectID:  projectID,
	})

	return nil
}

// ConfirmReset validates a reset token and sets a new password.
func (s *Service) ConfirmReset(ctx context.Context, projectID, plainToken, newPassword string) error {
	if plainToken == "" {
		return ErrTokenRequired
	}

	// SHA-256 hash the incoming token.
	tokenHash := sha256Hash(plainToken)

	q := sqlc.New(s.db)

	// Lookup the verification token.
	vt, err := q.GetVerificationTokenByHash(ctx, sqlc.GetVerificationTokenByHashParams{
		TokenHash: tokenHash,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No audit log here — we have no user context for DEK-based PII encryption.
			// The token_not_found case is logged at the handler level via structured logging.
			return ErrTokenNotFound
		}
		return fmt.Errorf("lookup reset token: %w", err)
	}

	// Check type.
	if vt.Type != "password_reset" {
		s.auditLog(ctx, &audit.Event{
			EventType: audit.EventAuthPasswordResetDone,
			Actor:     audit.ActorInfo{UserID: vt.UserID},
			Target:    &audit.TargetInfo{Type: "user", ID: vt.UserID},
			Result:    "failure",
			ProjectID: projectID,
			Metadata:  map[string]any{"reason": "wrong_token_type"},
		})
		return ErrTokenNotFound
	}

	// Check if already used.
	if vt.Used {
		s.auditLog(ctx, &audit.Event{
			EventType: audit.EventAuthPasswordResetDone,
			Actor:     audit.ActorInfo{UserID: vt.UserID},
			Target:    &audit.TargetInfo{Type: "user", ID: vt.UserID},
			Result:    "failure",
			ProjectID: projectID,
			Metadata:  map[string]any{"reason": "token_used"},
		})
		return ErrTokenUsed
	}

	// Check expiry.
	if vt.ExpiresAt.Valid && time.Now().After(vt.ExpiresAt.Time) {
		s.auditLog(ctx, &audit.Event{
			EventType: audit.EventAuthPasswordResetDone,
			Actor:     audit.ActorInfo{UserID: vt.UserID},
			Target:    &audit.TargetInfo{Type: "user", ID: vt.UserID},
			Result:    "failure",
			ProjectID: projectID,
			Metadata:  map[string]any{"reason": "token_expired"},
		})
		return ErrTokenExpired
	}

	// Validate new password.
	if err := crypto.ValidatePassword(newPassword); err != nil {
		s.auditLog(ctx, &audit.Event{
			EventType:  audit.EventAuthPasswordResetDone,
			Actor:      audit.ActorInfo{UserID: vt.UserID},
			Target:     &audit.TargetInfo{Type: "user", ID: vt.UserID},
			Result:     "failure",
			AuthMethod: "password",
			ProjectID:  projectID,
			Metadata:   map[string]any{"reason": "weak_password"},
		})
		return err
	}

	// HIBP check.
	breached, err := s.breachChecker.Check(ctx, newPassword)
	if err != nil {
		s.logger.Error("HIBP check failed during password reset", "error", err)
		return ErrHIBPUnavailable
	}
	if breached {
		s.auditLog(ctx, &audit.Event{
			EventType:  audit.EventAuthPasswordResetDone,
			Actor:      audit.ActorInfo{UserID: vt.UserID},
			Target:     &audit.TargetInfo{Type: "user", ID: vt.UserID},
			Result:     "failure",
			AuthMethod: "password",
			ProjectID:  projectID,
			Metadata:   map[string]any{"reason": "password_breached"},
		})
		return crypto.ErrPasswordBreached
	}

	// Get user.
	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        vt.UserID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("get user for reset: %w", err)
	}

	// Check password history (last 4).
	recentHashes, err := q.GetRecentPasswords(ctx, sqlc.GetRecentPasswordsParams{
		UserID: user.ID,
		Limit:  4,
	})
	if err != nil {
		return fmt.Errorf("get password history: %w", err)
	}
	if err := crypto.CheckPasswordHistory(newPassword, recentHashes, s.pepper); err != nil {
		s.auditLog(ctx, &audit.Event{
			EventType:  audit.EventAuthPasswordResetDone,
			Actor:      audit.ActorInfo{UserID: user.ID},
			Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
			Result:     "failure",
			AuthMethod: "password",
			ProjectID:  projectID,
			Metadata:   map[string]any{"reason": "password_reused"},
		})
		return err
	}

	// Hash new password.
	passwordHash, err := crypto.Hash(newPassword, s.pepper)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// Begin transaction for password update + token mark + session revoke.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	txq := sqlc.New(tx)

	// Update password.
	if err := txq.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		ID:           user.ID,
		PasswordHash: &passwordHash,
		ProjectID:    projectID,
	}); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Store in password history.
	if err := txq.CreatePasswordHistory(ctx, sqlc.CreatePasswordHistoryParams{
		ID:     id.New("ph_"),
		UserID: user.ID,
		Hash:   passwordHash,
	}); err != nil {
		return fmt.Errorf("create password history: %w", err)
	}

	// Mark token used.
	if err := txq.MarkVerificationTokenUsed(ctx, sqlc.MarkVerificationTokenUsedParams{
		ID:        vt.ID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}

	// Revoke all user sessions for this project.
	if err := txq.RevokeUserSessionsByProject(ctx, sqlc.RevokeUserSessionsByProjectParams{
		UserID:    user.ID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	// Audit log.
	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventAuthPasswordResetDone,
		Actor:      audit.ActorInfo{UserID: user.ID},
		Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
		Result:     "success",
		AuthMethod: "password",
		ProjectID:  projectID,
	})

	return nil
}
