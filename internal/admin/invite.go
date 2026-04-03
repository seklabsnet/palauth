package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

var (
	ErrAdminEmailExists = errors.New("admin with this email already exists")
	ErrInvalidRole      = errors.New("invalid role: must be 'owner' or 'admin'")
)

// InviteResult contains the result of an admin invitation.
type InviteResult struct {
	Admin           *User  `json:"admin"`
	TemporaryPassword string `json:"temporary_password"`
}

// InviteAdmin creates a new admin user with a temporary password.
// callerRole is the role of the admin performing the invitation.
// An admin can only invite at their own level or below (owner can invite owner or admin; admin can only invite admin).
func (s *Service) InviteAdmin(ctx context.Context, emailAddr, role, callerID, callerRole string) (*InviteResult, error) {
	if emailAddr == "" {
		return nil, ErrEmailRequired
	}
	if role != "owner" && role != "admin" {
		return nil, ErrInvalidRole
	}

	// Privilege check: admin can only invite at their own level or below.
	if callerRole == "admin" && role == "owner" {
		return nil, ErrInsufficientPrivilege
	}

	q := sqlc.New(s.db)

	// Check if admin with this email already exists.
	_, err := q.GetAdminByEmail(ctx, emailAddr)
	if err == nil {
		return nil, ErrAdminEmailExists
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check existing admin: %w", err)
	}

	// Generate a temporary password.
	tempPassword, err := crypto.GenerateToken(16) // 32 hex chars
	if err != nil {
		return nil, fmt.Errorf("generate temporary password: %w", err)
	}

	hash, err := crypto.Hash(tempPassword, s.pepper)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	adminRow, err := q.CreateAdminUser(ctx, sqlc.CreateAdminUserParams{
		ID:           id.New("adm_"),
		Email:        emailAddr,
		PasswordHash: hash,
		Role:         role,
	})
	if err != nil {
		return nil, fmt.Errorf("create admin: %w", err)
	}

	// Audit log for admin invitation.
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, &audit.Event{ //nolint:errcheck // best-effort audit
			EventType: audit.EventAdminInvite,
			Actor:     audit.ActorInfo{UserID: callerID},
			Target:    &audit.TargetInfo{Type: "admin", ID: adminRow.ID},
			Result:    "success",
			Metadata:  map[string]any{"role": role, "email": emailAddr},
		})
	}

	return &InviteResult{
		Admin:           toAdminUser(&adminRow),
		TemporaryPassword: tempPassword,
	}, nil
}
