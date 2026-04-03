package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/hook"
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/session"
	"github.com/palauth/palauth/internal/token"
)

// SignupResult contains the result of a successful signup.
type SignupResult struct {
	AccessToken       string   `json:"access_token"`
	RefreshToken      string   `json:"refresh_token"`
	TokenType         string   `json:"token_type"`
	ExpiresIn         int      `json:"expires_in"`
	User              UserInfo `json:"user"`
	VerificationToken string   `json:"verification_token,omitempty"` // for link-based verification
	VerificationCode  string   `json:"verification_code,omitempty"`  // for OTP-based verification
}

// UserInfo contains the user information returned after signup.
type UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     string `json:"created_at"`
}

// Signup registers a new user with email and password.
func (s *Service) Signup(ctx context.Context, email, password, projectID string) (*SignupResult, error) {
	if email == "" {
		return nil, ErrEmailRequired
	}
	if password == "" {
		return nil, ErrPasswordRequired
	}

	// Normalize email: lowercase + trim whitespace.
	email = normalizeEmail(email)

	// Validate email format.
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, ErrEmailRequired
	}

	// Validate password strength (15 char min, 64 max, no composition rules).
	if err := crypto.ValidatePassword(password); err != nil {
		return nil, err
	}

	// Check HIBP for breached passwords — fail closed per NIST 800-63B-4.
	breached, err := s.breachChecker.Check(ctx, password)
	if err != nil {
		s.logger.Error("HIBP check failed — rejecting signup (fail-closed)", "error", err)
		return nil, ErrHIBPUnavailable
	}
	if breached {
		s.logger.Warn("signup rejected: breached password", "project_id", projectID)
		return nil, crypto.ErrPasswordBreached
	}

	// Compute email hash for duplicate lookup.
	emailHash := crypto.DeterministicHash(email, s.emailHashKey)
	emailHashBytes, err := hex.DecodeString(emailHash)
	if err != nil {
		return nil, fmt.Errorf("decode email hash: %w", err)
	}

	q := sqlc.New(s.db)

	// Check for existing user with same email hash (enumeration prevention).
	_, existErr := q.GetUserByEmailHash(ctx, sqlc.GetUserByEmailHashParams{
		ProjectID: projectID,
		EmailHash: emailHashBytes,
	})
	if existErr == nil {
		// User exists — do a dummy password hash to equalize timing,
		// then return the same generic error.
		_, _ = crypto.Hash(password, s.pepper)
		s.logger.Warn("signup rejected: duplicate email", "project_id", projectID)
		return nil, ErrSignupFailed
	}
	if !errors.Is(existErr, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check existing user: %w", existErr)
	}

	// Get or create per-project DEK for email encryption.
	projectDEK, err := s.getOrCreateProjectDEK(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("get project DEK: %w", err)
	}

	// Encrypt email with project DEK.
	emailAAD := []byte("email:" + projectID)
	encryptedEmail, err := crypto.Encrypt([]byte(email), projectDEK, emailAAD)
	if err != nil {
		return nil, fmt.Errorf("encrypt email: %w", err)
	}

	// Hash password with Argon2id + pepper.
	passwordHash, err := crypto.Hash(password, s.pepper)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Execute before.user.create hook — deny blocks user creation.
	if s.hookCaller != nil {
		hookPayload := hook.Payload{
			User: &hook.UserInfo{Email: email},
		}
		resp, hookErr := s.hookCaller.ExecuteBlocking(ctx, projectID, hook.EventBeforeUserCreate, hookPayload)
		if hookErr != nil {
			if errors.Is(hookErr, hook.ErrHookDenied) {
				s.logger.Info("signup denied by hook", "project_id", projectID, "reason", resp.Reason)
				return nil, ErrHookDenied
			}
			// For non-deny errors (timeout with deny mode, etc.), propagate.
			return nil, fmt.Errorf("before.user.create hook: %w", hookErr)
		}
	}

	// Get project config for verification method.
	proj, err := s.projectSvc.Get(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("get project config: %w", err)
	}

	verificationMethod := proj.Config.EmailVerificationMethod
	if verificationMethod == "" {
		verificationMethod = "code"
	}

	// Begin transaction — all DB writes (user, password history, verification token, session)
	// must be atomic to avoid partial state.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	txq := sqlc.New(tx)

	// Create user.
	userID := id.New("usr_")
	user, err := txq.CreateUser(ctx, sqlc.CreateUserParams{
		ID:             userID,
		ProjectID:      projectID,
		EmailEncrypted: encryptedEmail,
		EmailHash:      emailHashBytes,
		PasswordHash:   &passwordHash,
		Metadata:       []byte("{}"),
	})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	// Store password in history (for future reuse check, PCI DSS Req 8.3.7).
	err = txq.CreatePasswordHistory(ctx, sqlc.CreatePasswordHistoryParams{
		ID:     id.New("ph_"),
		UserID: userID,
		Hash:   passwordHash,
	})
	if err != nil {
		return nil, fmt.Errorf("create password history: %w", err)
	}

	// Generate verification token based on project config.
	var verificationToken, verificationCode string

	switch verificationMethod {
	case "link":
		// 256-bit token, 24h expiry.
		plainToken, genErr := crypto.GenerateToken(32)
		if genErr != nil {
			return nil, fmt.Errorf("generate verification token: %w", genErr)
		}
		tokenHash := sha256Hash(plainToken)
		_, err = txq.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
			ID:        id.New("vt_"),
			ProjectID: projectID,
			UserID:    userID,
			TokenHash: tokenHash,
			Type:      "email_verify",
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
		})
		if err != nil {
			return nil, fmt.Errorf("create verification token: %w", err)
		}
		verificationToken = plainToken
	default: // "code" or "otp"
		// 6-digit OTP, 5min expiry (PSD2 RTS).
		otp, genErr := crypto.GenerateOTP(6)
		if genErr != nil {
			return nil, fmt.Errorf("generate OTP: %w", genErr)
		}
		otpHash := sha256Hash(otp)
		_, err = txq.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
			ID:        id.New("vt_"),
			ProjectID: projectID,
			UserID:    userID,
			TokenHash: otpHash,
			Type:      "email_verify_otp",
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(5 * time.Minute), Valid: true},
		})
		if err != nil {
			return nil, fmt.Errorf("create verification OTP: %w", err)
		}
		verificationCode = otp
	}

	// Create session for the new user using AAL-based timeouts.
	sessionID := id.New("sess_")
	now := time.Now()
	idleTimeout, absTimeout := session.AALTimeouts("aal1")

	var sessIdleTimeoutAt pgtype.Timestamptz
	if idleTimeout > 0 {
		sessIdleTimeoutAt = pgtype.Timestamptz{Time: now.Add(idleTimeout), Valid: true}
	}

	_, err = txq.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:            sessionID,
		ProjectID:     projectID,
		UserID:        userID,
		Acr:           "aal1",
		Amr:           []byte(`["pwd"]`),
		IdleTimeoutAt: sessIdleTimeoutAt,
		AbsTimeoutAt:  pgtype.Timestamptz{Time: now.Add(absTimeout), Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	// Issue JWT access token (outside transaction — stateless, no DB write).
	accessToken, err := s.jwtSvc.IssueWithContext(ctx, &token.IssueParams{
		UserID:    userID,
		SessionID: sessionID,
		ProjectID: projectID,
		AuthTime:  now,
		ACR:       "aal1",
		AMR:       []string{"pwd"},
	})
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	// Issue refresh token (writes to DB, but outside the signup transaction
	// since the user+session already exist after commit).
	refreshToken, err := s.refreshSvc.Issue(ctx, userID, sessionID, projectID)
	if err != nil {
		return nil, fmt.Errorf("issue refresh token: %w", err)
	}

	// Send verification email (best-effort, outside transaction).
	s.sendVerificationEmail(ctx, email, proj.Name, verificationMethod, verificationToken, verificationCode)

	// Audit log.
	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventAuthSignup,
		Actor:      audit.ActorInfo{UserID: userID, Email: email},
		Target:     &audit.TargetInfo{Type: "user", ID: userID},
		Result:     "success",
		AuthMethod: "password",
		ProjectID:  projectID,
	})

	return &SignupResult{
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		TokenType:         "Bearer",
		ExpiresIn:         1800,
		VerificationToken: verificationToken,
		VerificationCode:  verificationCode,
		User: UserInfo{
			ID:            user.ID,
			Email:         email,
			EmailVerified: user.EmailVerified,
			CreatedAt:     user.CreatedAt.Time.UTC().Format(time.RFC3339),
		},
	}, nil
}

// getOrCreateProjectDEK retrieves or creates a per-project data encryption key.
func (s *Service) getOrCreateProjectDEK(ctx context.Context, q *sqlc.Queries, projectID string) ([]byte, error) {
	dekAAD := []byte("project-dek:" + projectID)

	ek, err := q.GetProjectDEK(ctx, &projectID)
	if err == nil {
		return crypto.Decrypt(ek.EncryptedKey, s.kek, dekAAD)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get project DEK: %w", err)
	}

	// Generate new DEK.
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
		EncryptedKey: encryptedDEK,
		KeyType:      "project_dek",
	})
	if err != nil {
		return nil, fmt.Errorf("create encryption key: %w", err)
	}

	return dek, nil
}

// sha256Hash computes SHA-256 hash of a string and returns the raw bytes.
func sha256Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// constantTimeTokenCompare compares two token hashes in constant time.
func constantTimeTokenCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
