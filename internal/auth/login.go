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
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/session"
	"github.com/palauth/palauth/internal/token"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserBanned         = errors.New("user is banned")
	ErrAccountLocked      = errors.New("account is locked")
)

// MFARequiredError is returned when MFA verification is needed to complete login.
type MFARequiredError struct {
	MFAToken string
	Factors  []string
}

func (e *MFARequiredError) Error() string {
	return "MFA verification required"
}

// LoginResult contains the result of a successful login.
type LoginResult struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	User         UserInfo `json:"user"`
}

// LoginParams contains the parameters for a login attempt.
type LoginParams struct {
	Email     string
	Password  string
	ProjectID string
	IP        *string
	UserAgent *string
}

// Login authenticates a user with email and password.
func (s *Service) Login(ctx context.Context, params *LoginParams) (*LoginResult, time.Duration, error) {
	if params.Email == "" {
		return nil, 0, ErrEmailRequired
	}
	if params.Password == "" {
		return nil, 0, ErrPasswordRequired
	}

	email := normalizeEmail(params.Email)

	// Compute email hash for lookup.
	emailHash := crypto.DeterministicHash(email, s.emailHashKey)
	emailHashBytes, err := hex.DecodeString(emailHash)
	if err != nil {
		return nil, 0, fmt.Errorf("decode email hash: %w", err)
	}

	q := sqlc.New(s.db)

	// Lookup user by email hash. If not found, do a dummy hash to equalize timing.
	user, err := q.GetUserByEmailHash(ctx, sqlc.GetUserByEmailHashParams{
		ProjectID: params.ProjectID,
		EmailHash: emailHashBytes,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// User not found — do dummy password hash for timing equalization.
			_, _ = crypto.Hash("dummy-password-for-timing", s.pepper)

			s.auditLog(ctx, &audit.Event{
				EventType:  audit.EventAuthLoginFailure,
				Actor:      audit.ActorInfo{Email: email},
				Result:     "failure",
				AuthMethod: "password",
				ProjectID:  params.ProjectID,
				Metadata:   map[string]any{"reason": "user_not_found"},
			})

			return nil, 0, ErrInvalidCredentials
		}
		return nil, 0, fmt.Errorf("lookup user: %w", err)
	}

	// Check lockout (if lockout service is available).
	// Done before password verify to avoid wasting Argon2id compute on locked accounts.
	if s.lockoutSvc != nil {
		locked, retryAfter, err := s.lockoutSvc.Check(ctx, params.ProjectID, user.ID)
		if err != nil {
			return nil, 0, fmt.Errorf("check lockout: %w", err)
		}
		if locked {
			// Still do a dummy hash for timing equalization.
			_, _ = crypto.Hash("dummy-password-for-timing", s.pepper)

			s.auditLog(ctx, &audit.Event{
				EventType:  audit.EventAuthLoginFailure,
				Actor:      audit.ActorInfo{UserID: user.ID},
				Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
				Result:     "failure",
				AuthMethod: "password",
				ProjectID:  params.ProjectID,
				Metadata:   map[string]any{"reason": "account_locked"},
			})

			return nil, retryAfter, ErrAccountLocked
		}
	}

	// Verify password.
	if user.PasswordHash == nil {
		return nil, 0, ErrInvalidCredentials
	}

	match, err := crypto.Verify(params.Password, *user.PasswordHash, s.pepper)
	if err != nil {
		return nil, 0, fmt.Errorf("verify password: %w", err)
	}

	if !match {
		// Increment failed counter.
		if s.lockoutSvc != nil {
			locked, _ := s.lockoutSvc.RecordFailure(ctx, params.ProjectID, user.ID)
			if locked {
				s.logger.Warn("account locked after failed login attempts",
					"user_id", user.ID,
					"project_id", params.ProjectID,
				)

				s.auditLog(ctx, &audit.Event{
					EventType:  audit.EventAuthLoginFailure,
					Actor:      audit.ActorInfo{UserID: user.ID, Email: email},
					Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
					Result:     "failure",
					AuthMethod: "password",
					ProjectID:  params.ProjectID,
					Metadata:   map[string]any{"reason": "account_locked_triggered"},
				})
			}
		}

		s.auditLog(ctx, &audit.Event{
			EventType:  audit.EventAuthLoginFailure,
			Actor:      audit.ActorInfo{UserID: user.ID, Email: email},
			Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
			Result:     "failure",
			AuthMethod: "password",
			ProjectID:  params.ProjectID,
			Metadata:   map[string]any{"reason": "invalid_password"},
		})

		return nil, 0, ErrInvalidCredentials
	}

	// Password correct — check if user is banned.
	// Banned check is AFTER password verification to prevent email enumeration:
	// an attacker cannot probe which emails are banned without knowing the password.
	if user.Banned {
		s.auditLog(ctx, &audit.Event{
			EventType:  audit.EventAuthLoginFailure,
			Actor:      audit.ActorInfo{UserID: user.ID, Email: email},
			Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
			Result:     "failure",
			AuthMethod: "password",
			ProjectID:  params.ProjectID,
			Metadata:   map[string]any{"reason": "user_banned"},
		})
		return nil, 0, ErrUserBanned
	}

	// Password correct — reset failed counter.
	if s.lockoutSvc != nil {
		_ = s.lockoutSvc.Reset(ctx, params.ProjectID, user.ID)
	}

	// Check MFA: if user has MFA enrolled, return MFA token instead of access token.
	if s.mfaChecker != nil && user.HasMfa {
		hasMFA, factors, err := s.mfaChecker.HasMFA(ctx, params.ProjectID, user.ID)
		if err != nil {
			return nil, 0, fmt.Errorf("check mfa: %w", err)
		}
		if hasMFA && len(factors) > 0 {
			ip := ""
			ua := ""
			if params.IP != nil {
				ip = *params.IP
			}
			if params.UserAgent != nil {
				ua = *params.UserAgent
			}

			mfaToken, err := s.mfaChecker.IssueMFATokenForLogin(ctx, user.ID, params.ProjectID, ip, ua)
			if err != nil {
				return nil, 0, fmt.Errorf("issue mfa token: %w", err)
			}

			return nil, 0, &MFARequiredError{
				MFAToken: mfaToken,
				Factors:  factors,
			}
		}
	}

	// Update last_login_at.
	if err := q.UpdateUserLastLogin(ctx, sqlc.UpdateUserLastLoginParams{
		ID:        user.ID,
		ProjectID: params.ProjectID,
	}); err != nil {
		return nil, 0, fmt.Errorf("update last login: %w", err)
	}

	// Create session.
	now := time.Now()
	sessionID := id.New("sess_")
	idleTimeout, absTimeout := session.AALTimeouts("aal1")

	var idleTimeoutAt pgtype.Timestamptz
	if idleTimeout > 0 {
		idleTimeoutAt = pgtype.Timestamptz{Time: now.Add(idleTimeout), Valid: true}
	}

	_, err = q.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:            sessionID,
		ProjectID:     params.ProjectID,
		UserID:        user.ID,
		Ip:            params.IP,
		UserAgent:     params.UserAgent,
		Acr:           "aal1",
		Amr:           []byte(`["pwd"]`),
		IdleTimeoutAt: idleTimeoutAt,
		AbsTimeoutAt:  pgtype.Timestamptz{Time: now.Add(absTimeout), Valid: true},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("create session: %w", err)
	}

	// Issue JWT access token.
	accessToken, err := s.jwtSvc.Issue(&token.IssueParams{
		UserID:    user.ID,
		SessionID: sessionID,
		ProjectID: params.ProjectID,
		AuthTime:  now,
		ACR:       "aal1",
		AMR:       []string{"pwd"},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("issue access token: %w", err)
	}

	// Issue refresh token.
	refreshToken, err := s.refreshSvc.Issue(ctx, user.ID, sessionID, params.ProjectID)
	if err != nil {
		return nil, 0, fmt.Errorf("issue refresh token: %w", err)
	}

	// Decrypt email for response.
	projectDEK, err := s.getOrCreateProjectDEK(ctx, q, params.ProjectID)
	if err != nil {
		return nil, 0, fmt.Errorf("get project DEK: %w", err)
	}
	emailAAD := []byte("email:" + params.ProjectID)
	decryptedEmail, err := crypto.Decrypt(user.EmailEncrypted, projectDEK, emailAAD)
	if err != nil {
		return nil, 0, fmt.Errorf("decrypt email: %w", err)
	}

	// Audit log.
	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventAuthLoginSuccess,
		Actor:      audit.ActorInfo{UserID: user.ID, Email: string(decryptedEmail)},
		Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
		Result:     "success",
		AuthMethod: "password",
		ProjectID:  params.ProjectID,
	})

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    1800,
		User: UserInfo{
			ID:            user.ID,
			Email:         string(decryptedEmail),
			EmailVerified: user.EmailVerified,
			CreatedAt:     user.CreatedAt.Time.UTC().Format(time.RFC3339),
		},
	}, 0, nil
}
