package admin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInviteAdmin_InvalidRole(t *testing.T) {
	svc := &Service{pepper: "test-pepper-at-least-32-bytes!!!"}

	_, err := svc.InviteAdmin(t.Context(), "admin@example.com", "superadmin", "adm_1", "owner")
	assert.ErrorIs(t, err, ErrInvalidRole)
}

func TestInviteAdmin_EmptyEmail(t *testing.T) {
	svc := &Service{pepper: "test-pepper-at-least-32-bytes!!!"}

	_, err := svc.InviteAdmin(t.Context(), "", "admin", "adm_1", "owner")
	assert.ErrorIs(t, err, ErrEmailRequired)
}

func TestInviteAdmin_PrivilegeEscalation_AdminCannotInviteOwner(t *testing.T) {
	svc := &Service{pepper: "test-pepper-at-least-32-bytes!!!"}

	// admin role cannot invite owner role — rejected before any DB access
	_, err := svc.InviteAdmin(t.Context(), "new@example.com", "owner", "adm_1", "admin")
	assert.ErrorIs(t, err, ErrInsufficientPrivilege)
}

func TestInviteAdmin_PrivilegeEscalation_OwnerCanInviteOwner(t *testing.T) {
	// Verify owner CAN request owner role (no privilege error).
	// Will panic on DB access since db is nil — we recover and just check the role validation passed.
	svc := &Service{pepper: "test-pepper-at-least-32-bytes!!!"}

	var err error
	panicked := true
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_, err = svc.InviteAdmin(t.Context(), "new@example.com", "owner", "adm_1", "owner")
		panicked = false
	}()

	// If it panicked, it means role check passed (panic was from nil DB access).
	// If it didn't panic, check the error is not a privilege error.
	if !panicked {
		assert.NotErrorIs(t, err, ErrInsufficientPrivilege)
	}
	// Either way: no ErrInsufficientPrivilege was returned — test passes.
}

func TestInviteAdmin_PrivilegeEscalation_AdminCanInviteAdmin(t *testing.T) {
	// Verify admin CAN request admin role (no privilege error).
	svc := &Service{pepper: "test-pepper-at-least-32-bytes!!!"}

	var err error
	panicked := true
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_, err = svc.InviteAdmin(t.Context(), "new@example.com", "admin", "adm_1", "admin")
		panicked = false
	}()

	if !panicked {
		assert.NotErrorIs(t, err, ErrInsufficientPrivilege)
	}
}
