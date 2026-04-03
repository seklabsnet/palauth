package admin

import (
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"

	"github.com/palauth/palauth/internal/database/sqlc"
)

func TestToUserDetail(t *testing.T) {
	svc := &UserService{}

	user := &sqlc.User{
		ID:            "usr_123",
		ProjectID:     "prj_456",
		EmailVerified: true,
		Banned:        false,
		Metadata:      []byte(`{"key":"value"}`),
		CreatedAt:     pgtype.Timestamptz{Valid: true},
		UpdatedAt:     pgtype.Timestamptz{Valid: true},
	}

	detail := svc.toUserDetail(user, "test@example.com", 3)

	assert.Equal(t, "usr_123", detail.ID)
	assert.Equal(t, "prj_456", detail.ProjectID)
	assert.Equal(t, "test@example.com", detail.Email)
	assert.True(t, detail.EmailVerified)
	assert.False(t, detail.Banned)
	assert.Empty(t, detail.BanReason)
	assert.Equal(t, int64(3), detail.ActiveSessions)
	assert.Equal(t, json.RawMessage(`{"key":"value"}`), detail.Metadata)
}

func TestToUserDetail_WithBanReason(t *testing.T) {
	svc := &UserService{}
	reason := "violation"
	user := &sqlc.User{
		ID:        "usr_123",
		ProjectID: "prj_456",
		Banned:    true,
		BanReason: &reason,
		Metadata:  []byte("{}"),
		CreatedAt: pgtype.Timestamptz{Valid: true},
	}

	detail := svc.toUserDetail(user, "test@example.com", 0)

	assert.True(t, detail.Banned)
	assert.Equal(t, "violation", detail.BanReason)
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "Test@Example.COM", "test@example.com"},
		{"trim spaces", "  user@test.com  ", "user@test.com"},
		{"already normalized", "user@test.com", "user@test.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeEmail(tt.input))
		})
	}
}

func TestSha256Hash_Deterministic(t *testing.T) {
	h1 := sha256Hash("test-input")
	h2 := sha256Hash("test-input")
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 32) // SHA-256 produces 32 bytes
}

func TestSha256Hash_Different(t *testing.T) {
	h1 := sha256Hash("input-a")
	h2 := sha256Hash("input-b")
	assert.NotEqual(t, h1, h2)
}
