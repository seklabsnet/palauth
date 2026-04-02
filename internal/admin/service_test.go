package admin

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/palauth/palauth/internal/database/sqlc"
)

func TestSignAndValidateToken(t *testing.T) {
	svc := &Service{
		signingKey: []byte("test-signing-key-at-least-32-bytes!"),
	}

	claims := Claims{
		Sub:  "adm_test-123",
		Role: "owner",
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(24 * time.Hour).Unix(),
	}

	token, err := svc.signToken(claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parts := strings.SplitN(token, ".", 3)
	assert.Len(t, parts, 3)

	parsed, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, claims.Sub, parsed.Sub)
	assert.Equal(t, claims.Role, parsed.Role)
	assert.Equal(t, claims.Iat, parsed.Iat)
	assert.Equal(t, claims.Exp, parsed.Exp)
}

func TestValidateToken_Expired(t *testing.T) {
	svc := &Service{
		signingKey: []byte("test-signing-key-at-least-32-bytes!"),
	}

	claims := Claims{
		Sub:  "adm_test-123",
		Role: "owner",
		Iat:  time.Now().Add(-2 * time.Hour).Unix(),
		Exp:  time.Now().Add(-1 * time.Hour).Unix(),
	}

	token, err := svc.signToken(claims)
	require.NoError(t, err)

	_, err = svc.ValidateToken(token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	svc1 := &Service{
		signingKey: []byte("key-one-at-least-32-bytes-long!!"),
	}
	svc2 := &Service{
		signingKey: []byte("key-two-at-least-32-bytes-long!!"),
	}

	claims := Claims{
		Sub:  "adm_test-123",
		Role: "owner",
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(24 * time.Hour).Unix(),
	}

	token, err := svc1.signToken(claims)
	require.NoError(t, err)

	_, err = svc2.ValidateToken(token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_Malformed(t *testing.T) {
	svc := &Service{
		signingKey: []byte("test-signing-key-at-least-32-bytes!"),
	}

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "nodots"},
		{"one dot", "one.dot"},
		{"garbage", "abc.def.ghi"},
		{"bad base64 payload", "eyJhbGciOiJIUzI1NiJ9.!!!invalid!!!.sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateToken(tt.token)
			assert.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}

func TestValidateToken_TamperedPayload(t *testing.T) {
	svc := &Service{
		signingKey: []byte("test-signing-key-at-least-32-bytes!"),
	}

	claims := Claims{
		Sub:  "adm_test-123",
		Role: "owner",
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(24 * time.Hour).Unix(),
	}

	token, err := svc.signToken(claims)
	require.NoError(t, err)

	parts := strings.SplitN(token, ".", 3)
	tamperedClaims := Claims{
		Sub:  "adm_test-123",
		Role: "admin",
		Iat:  claims.Iat,
		Exp:  claims.Exp,
	}
	tamperedJSON, _ := json.Marshal(tamperedClaims)
	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedJSON)
	tamperedToken := strings.Join(parts, ".")

	_, err = svc.ValidateToken(tamperedToken)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestSignToken_HeaderIsHS256(t *testing.T) {
	svc := &Service{
		signingKey: []byte("test-signing-key-at-least-32-bytes!"),
	}

	claims := Claims{
		Sub:  "adm_test",
		Role: "owner",
		Iat:  time.Now().Unix(),
		Exp:  time.Now().Add(time.Hour).Unix(),
	}

	token, err := svc.signToken(claims)
	require.NoError(t, err)

	parts := strings.SplitN(token, ".", 3)
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var header map[string]string
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	assert.Equal(t, "HS256", header["alg"])
	assert.Equal(t, "JWT", header["typ"])
}

func TestSignToken_Property_RoundTrip(t *testing.T) {
	svc := &Service{
		signingKey: []byte("property-test-key-at-least-32-bytes!"),
	}

	rapid.Check(t, func(t *rapid.T) {
		sub := rapid.StringMatching(`adm_[a-z0-9]{5,10}`).Draw(t, "sub")
		role := rapid.SampledFrom([]string{"owner", "admin", "developer"}).Draw(t, "role")

		claims := Claims{
			Sub:  sub,
			Role: role,
			Iat:  time.Now().Unix(),
			Exp:  time.Now().Add(24 * time.Hour).Unix(),
		}

		token, err := svc.signToken(claims)
		require.NoError(t, err)

		parsed, err := svc.ValidateToken(token)
		require.NoError(t, err)
		assert.Equal(t, claims.Sub, parsed.Sub)
		assert.Equal(t, claims.Role, parsed.Role)
	})
}

func TestToAdminUser(t *testing.T) {
	now := time.Now()
	row := sqlc.AdminUser{
		ID:           "adm_test-123",
		Email:        "admin@example.com",
		PasswordHash: "hash",
		Role:         "owner",
		CreatedAt:    pgtype.Timestamptz{Time: now, Valid: true},
	}

	admin := toAdminUser(&row)
	assert.Equal(t, "adm_test-123", admin.ID)
	assert.Equal(t, "admin@example.com", admin.Email)
	assert.Equal(t, "owner", admin.Role)
	assert.NotEmpty(t, admin.CreatedAt)
}

func TestToAdminUser_InvalidTimestamp(t *testing.T) {
	row := sqlc.AdminUser{
		ID:           "adm_test-456",
		Email:        "test@example.com",
		PasswordHash: "hash",
		Role:         "admin",
		CreatedAt:    pgtype.Timestamptz{Valid: false},
	}

	admin := toAdminUser(&row)
	assert.Equal(t, "", admin.CreatedAt)
}
