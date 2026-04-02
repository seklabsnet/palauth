package token

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateCustomToken_Success(t *testing.T) {
	jwtSvc := newTestJWTService(t, AlgPS256)

	// CustomTokenService needs Redis, but we test creation without exchange.
	// CreateCustomToken only uses the JWT service, no Redis.
	svc := &CustomTokenService{
		jwt:    jwtSvc,
		logger: slog.Default(),
	}

	tokenStr, err := svc.CreateCustomToken(CreateCustomTokenParams{
		UserID:    "usr_test-123",
		ProjectID: "prj_test-456",
		Issuer:    "palauth-test",
		Claims:    map[string]any{"role": "admin"},
		ExpiresIn: 30 * time.Minute,
	})
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	// Verify the token.
	claims, err := jwtSvc.Verify(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "usr_test-123", claims.Subject)
	assert.Equal(t, "prj_test-456", claims.ProjectID)
	assert.Equal(t, "admin", claims.CustomClaims["role"])
}

func TestCreateCustomToken_MaxTTL(t *testing.T) {
	jwtSvc := newTestJWTService(t, AlgPS256)
	svc := &CustomTokenService{
		jwt:    jwtSvc,
		logger: slog.Default(),
	}

	_, err := svc.CreateCustomToken(CreateCustomTokenParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
		ExpiresIn: 2 * time.Hour, // Exceeds max 1 hour.
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCustomTokenTTLExceeded)
}

func TestCreateCustomToken_DefaultTTL(t *testing.T) {
	jwtSvc := newTestJWTService(t, AlgPS256)
	svc := &CustomTokenService{
		jwt:    jwtSvc,
		logger: slog.Default(),
	}

	tokenStr, err := svc.CreateCustomToken(CreateCustomTokenParams{
		UserID:    "usr_test",
		ProjectID: "prj_test",
	})
	require.NoError(t, err)

	claims, err := jwtSvc.Verify(tokenStr)
	require.NoError(t, err)
	// Default TTL is 1 hour.
	expectedExpiry := time.Now().Add(1 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt, 5*time.Second)
}

func TestCreateCustomToken_UserIDRequired(t *testing.T) {
	jwtSvc := newTestJWTService(t, AlgPS256)
	svc := &CustomTokenService{
		jwt:    jwtSvc,
		logger: slog.Default(),
	}

	_, err := svc.CreateCustomToken(CreateCustomTokenParams{
		ProjectID: "prj_test",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserIDRequired)
}

func TestCreateCustomToken_TableDriven(t *testing.T) {
	jwtSvc := newTestJWTService(t, AlgES256)
	svc := &CustomTokenService{
		jwt:    jwtSvc,
		logger: slog.Default(),
	}

	tests := []struct {
		name    string
		params  CreateCustomTokenParams
		wantErr error
	}{
		{
			name: "valid with claims",
			params: CreateCustomTokenParams{
				UserID:    "usr_abc",
				ProjectID: "prj_abc",
				Claims:    map[string]any{"x": "y"},
				ExpiresIn: 10 * time.Minute,
			},
			wantErr: nil,
		},
		{
			name: "valid without claims",
			params: CreateCustomTokenParams{
				UserID:    "usr_abc",
				ProjectID: "prj_abc",
			},
			wantErr: nil,
		},
		{
			name: "missing user_id",
			params: CreateCustomTokenParams{
				ProjectID: "prj_abc",
			},
			wantErr: ErrUserIDRequired,
		},
		{
			name: "TTL too long",
			params: CreateCustomTokenParams{
				UserID:    "usr_abc",
				ProjectID: "prj_abc",
				ExpiresIn: 90 * time.Minute,
			},
			wantErr: ErrCustomTokenTTLExceeded,
		},
		{
			name: "exact max TTL",
			params: CreateCustomTokenParams{
				UserID:    "usr_abc",
				ProjectID: "prj_abc",
				ExpiresIn: 1 * time.Hour,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateCustomToken(tt.params)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
