package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

var (
	ErrCurrentPasswordRequired = errors.New("current password is required")
	ErrNewPasswordRequired     = errors.New("new password is required")
	ErrUserNotFound            = errors.New("user not found")
)

// ChangePassword changes a user's password after verifying the current one.
func (s *Service) ChangePassword(ctx context.Context, projectID, userID, currentPassword, newPassword string) error {
	if currentPassword == "" {
		return ErrCurrentPasswordRequired
	}
	if newPassword == "" {
		return ErrNewPasswordRequired
	}

	q := sqlc.New(s.db)

	// Get user.
	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Verify current password.
	if user.PasswordHash == nil {
		return ErrInvalidCredentials
	}

	match, err := crypto.Verify(currentPassword, *user.PasswordHash, s.pepper)
	if err != nil {
		return fmt.Errorf("verify current password: %w", err)
	}
	if !match {
		s.auditLog(ctx, &audit.Event{
			EventType:  audit.EventAuthPasswordChange,
			Actor:      audit.ActorInfo{UserID: userID},
			Target:     &audit.TargetInfo{Type: "user", ID: userID},
			Result:     "failure",
			AuthMethod: "password",
			ProjectID:  projectID,
			Metadata:   map[string]any{"reason": "invalid_current_password"},
		})
		return ErrInvalidCredentials
	}

	// Validate new password.
	if err := crypto.ValidatePassword(newPassword); err != nil {
		return err
	}

	// HIBP check.
	breached, err := s.breachChecker.Check(ctx, newPassword)
	if err != nil {
		s.logger.Error("HIBP check failed during password change", "error", err)
		return ErrHIBPUnavailable
	}
	if breached {
		return crypto.ErrPasswordBreached
	}

	// Check password history (last 4).
	recentHashes, err := q.GetRecentPasswords(ctx, sqlc.GetRecentPasswordsParams{
		UserID: userID,
		Limit:  4,
	})
	if err != nil {
		return fmt.Errorf("get password history: %w", err)
	}
	if err := crypto.CheckPasswordHistory(newPassword, recentHashes, s.pepper); err != nil {
		return err
	}

	// Hash new password.
	passwordHash, err := crypto.Hash(newPassword, s.pepper)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// Begin transaction for atomic password update + history insert.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	txq := sqlc.New(tx)

	// Update password.
	if err := txq.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		ID:           userID,
		PasswordHash: &passwordHash,
		ProjectID:    projectID,
	}); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Store in password history.
	if err := txq.CreatePasswordHistory(ctx, sqlc.CreatePasswordHistoryParams{
		ID:     id.New("ph_"),
		UserID: userID,
		Hash:   passwordHash,
	}); err != nil {
		return fmt.Errorf("create password history: %w", err)
	}

	// Revoke all user sessions for this project.
	// An attacker with a stolen session should not remain authenticated after password change.
	if err := txq.RevokeUserSessionsByProject(ctx, sqlc.RevokeUserSessionsByProjectParams{
		UserID:    userID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	// Audit log.
	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventAuthPasswordChange,
		Actor:      audit.ActorInfo{UserID: userID},
		Target:     &audit.TargetInfo{Type: "user", ID: userID},
		Result:     "success",
		AuthMethod: "password",
		ProjectID:  projectID,
	})

	return nil
}

// VerifyPassword checks if the given password matches the user's stored password.
// Used for re-authentication (e.g., before removing MFA).
func (s *Service) VerifyPassword(ctx context.Context, projectID, userID, password string) error {
	q := sqlc.New(s.db)

	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	if user.PasswordHash == nil {
		return ErrInvalidCredentials
	}

	match, err := crypto.Verify(password, *user.PasswordHash, s.pepper)
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	if !match {
		return ErrInvalidCredentials
	}

	return nil
}
