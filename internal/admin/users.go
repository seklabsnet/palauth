package admin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/email"
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/session"
)

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrUserAlreadyBanned = errors.New("user is already banned")
	ErrUserNotBanned    = errors.New("user is not banned")
	ErrInvalidEmail     = errors.New("invalid email address")
	ErrDuplicateEmail   = errors.New("email already exists in this project")
	ErrBanReasonRequired = errors.New("ban reason is required")
)

// UserDetail is the admin view of a user with decrypted fields.
type UserDetail struct {
	ID             string          `json:"id"`
	ProjectID      string          `json:"project_id"`
	Email          string          `json:"email"`
	EmailVerified  bool            `json:"email_verified"`
	Banned         bool            `json:"banned"`
	BanReason      string          `json:"ban_reason,omitempty"`
	Metadata       json.RawMessage `json:"metadata"`
	ActiveSessions int64           `json:"active_sessions"`
	LastLoginAt    string          `json:"last_login_at,omitempty"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at,omitempty"`
}

// UserListResult contains paginated user results.
type UserListResult struct {
	Users      []UserDetail `json:"users"`
	NextCursor *UserCursor  `json:"next_cursor,omitempty"`
	Total      int64        `json:"total"`
}

// UserCursor represents a pagination cursor.
type UserCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

// UserListOptions configures user listing.
type UserListOptions struct {
	Limit      int32
	Cursor     *UserCursor
	Banned     *bool
	EmailQuery string
}

// UpdateUserParams contains the fields that can be updated.
type UpdateUserParams struct {
	EmailVerified *bool            `json:"email_verified,omitempty"`
	Metadata      *json.RawMessage `json:"metadata,omitempty"`
}

// UserService manages admin user operations.
type UserService struct {
	db            *pgxpool.Pool
	auditSvc      *audit.Service
	sessionSvc    *session.Service
	breachChecker *crypto.BreachChecker
	emailSender   email.Sender
	emailRenderer *email.TemplateRenderer
	pepper        string
	kek           []byte
	emailHashKey  []byte
	logger        *slog.Logger
}

// NewUserService creates a new admin user service.
func NewUserService(
	db *pgxpool.Pool,
	auditSvc *audit.Service,
	sessionSvc *session.Service,
	breachChecker *crypto.BreachChecker,
	emailSender email.Sender,
	emailRenderer *email.TemplateRenderer,
	pepper string,
	kek []byte,
	logger *slog.Logger,
) *UserService {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte("email-hash-key"))
	emailHashKey := mac.Sum(nil)

	return &UserService{
		db:            db,
		auditSvc:      auditSvc,
		sessionSvc:    sessionSvc,
		breachChecker: breachChecker,
		emailSender:   emailSender,
		emailRenderer: emailRenderer,
		pepper:        pepper,
		kek:           kek,
		emailHashKey:  emailHashKey,
		logger:        logger,
	}
}

// CreateUser creates a new user within a project (admin action).
func (s *UserService) CreateUser(ctx context.Context, projectID, emailAddr, password string, metadata json.RawMessage, adminID string) (*UserDetail, error) {
	if emailAddr == "" {
		return nil, ErrEmailRequired
	}

	emailAddr = normalizeEmail(emailAddr)
	if _, err := mail.ParseAddress(emailAddr); err != nil {
		return nil, ErrInvalidEmail
	}

	if password != "" {
		if err := crypto.ValidatePassword(password); err != nil {
			return nil, err
		}
		breached, err := s.breachChecker.Check(ctx, password)
		if err != nil {
			s.logger.Error("HIBP check failed — rejecting user creation (fail-closed)", "error", err)
			return nil, fmt.Errorf("password breach check unavailable: %w", err)
		}
		if breached {
			return nil, crypto.ErrPasswordBreached
		}
	}

	emailHash := crypto.DeterministicHash(emailAddr, s.emailHashKey)
	emailHashBytes, err := hex.DecodeString(emailHash)
	if err != nil {
		return nil, fmt.Errorf("decode email hash: %w", err)
	}

	q := sqlc.New(s.db)

	// Check duplicate email.
	_, existErr := q.GetUserByEmailHash(ctx, sqlc.GetUserByEmailHashParams{
		ProjectID: projectID,
		EmailHash: emailHashBytes,
	})
	if existErr == nil {
		return nil, ErrDuplicateEmail
	}
	if !errors.Is(existErr, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check existing user: %w", existErr)
	}

	projectDEK, err := s.getOrCreateProjectDEK(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("get project DEK: %w", err)
	}

	emailAAD := []byte("email:" + projectID)
	encryptedEmail, err := crypto.Encrypt([]byte(emailAddr), projectDEK, emailAAD)
	if err != nil {
		return nil, fmt.Errorf("encrypt email: %w", err)
	}

	var passwordHashPtr *string
	if password != "" {
		hash, err := crypto.Hash(password, s.pepper)
		if err != nil {
			return nil, fmt.Errorf("hash password: %w", err)
		}
		passwordHashPtr = &hash
	}

	if metadata == nil {
		metadata = json.RawMessage("{}")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	txq := sqlc.New(tx)

	userID := id.New("usr_")
	user, err := txq.CreateUser(ctx, sqlc.CreateUserParams{
		ID:             userID,
		ProjectID:      projectID,
		EmailEncrypted: encryptedEmail,
		EmailHash:      emailHashBytes,
		PasswordHash:   passwordHashPtr,
		Metadata:       []byte(metadata),
	})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	if password != "" {
		err = txq.CreatePasswordHistory(ctx, sqlc.CreatePasswordHistoryParams{
			ID:     id.New("ph_"),
			UserID: userID,
			Hash:   *passwordHashPtr,
		})
		if err != nil {
			return nil, fmt.Errorf("create password history: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventAdminUserCreate,
		Actor:     audit.ActorInfo{UserID: adminID},
		Target:    &audit.TargetInfo{Type: "user", ID: userID},
		Result:    "success",
		ProjectID: projectID,
	})

	return s.toUserDetail(&user, emailAddr, 0), nil
}

// GetUser retrieves a user by ID with decrypted email.
func (s *UserService) GetUser(ctx context.Context, projectID, userID string) (*UserDetail, error) {
	q := sqlc.New(s.db)

	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	emailAddr, err := s.decryptEmail(ctx, q, user.EmailEncrypted, projectID)
	if err != nil {
		s.logger.Warn("failed to decrypt user email", "user_id", userID, "error", err)
		emailAddr = "[encrypted]"
	}

	activeSessions, err := q.CountActiveSessionsByUser(ctx, sqlc.CountActiveSessionsByUserParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		s.logger.Warn("failed to count active sessions", "user_id", userID, "error", err)
	}

	return s.toUserDetail(&user, emailAddr, activeSessions), nil
}

// ListUsers returns paginated users with cursor-based pagination.
func (s *UserService) ListUsers(ctx context.Context, projectID string, opts UserListOptions) (*UserListResult, error) {
	q := sqlc.New(s.db)

	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 100 {
		opts.Limit = 100
	}

	fetchLimit := opts.Limit + 1

	var users []sqlc.User
	var err error

	switch {
	case opts.EmailQuery != "":
		emailAddr := normalizeEmail(opts.EmailQuery)
		emailHash := crypto.DeterministicHash(emailAddr, s.emailHashKey)
		emailHashBytes, decErr := hex.DecodeString(emailHash)
		if decErr != nil {
			return nil, fmt.Errorf("decode email hash: %w", decErr)
		}
		users, err = q.ListUsersByEmailHash(ctx, sqlc.ListUsersByEmailHashParams{
			ProjectID: projectID,
			EmailHash: emailHashBytes,
			Limit:     fetchLimit,
		})
	case opts.Cursor != nil:
		ts := pgtype.Timestamptz{Time: opts.Cursor.CreatedAt, Valid: true}
		if opts.Banned != nil {
			users, err = q.ListUsersCursorBanned(ctx, sqlc.ListUsersCursorBannedParams{
				ProjectID:       projectID,
				Banned:          *opts.Banned,
				CursorCreatedAt: ts,
				CursorID:        opts.Cursor.ID,
				Lim:             fetchLimit,
			})
		} else {
			users, err = q.ListUsersCursor(ctx, sqlc.ListUsersCursorParams{
				ProjectID:       projectID,
				CursorCreatedAt: ts,
				CursorID:        opts.Cursor.ID,
				Lim:             fetchLimit,
			})
		}
	default:
		if opts.Banned != nil {
			users, err = q.ListUsersFirstBanned(ctx, sqlc.ListUsersFirstBannedParams{
				ProjectID: projectID,
				Banned:    *opts.Banned,
				Limit:     fetchLimit,
			})
		} else {
			users, err = q.ListUsersFirst(ctx, sqlc.ListUsersFirstParams{
				ProjectID: projectID,
				Limit:     fetchLimit,
			})
		}
	}
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	total, err := q.CountUsersByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}

	var nextCursor *UserCursor
	if len(users) > int(opts.Limit) {
		users = users[:opts.Limit]
		last := users[len(users)-1]
		nextCursor = &UserCursor{
			CreatedAt: last.CreatedAt.Time,
			ID:        last.ID,
		}
	}

	details := make([]UserDetail, 0, len(users))
	for i := range users {
		emailAddr, decErr := s.decryptEmail(ctx, q, users[i].EmailEncrypted, projectID)
		if decErr != nil {
			emailAddr = "[encrypted]"
		}
		details = append(details, *s.toUserDetail(&users[i], emailAddr, 0))
	}

	return &UserListResult{
		Users:      details,
		NextCursor: nextCursor,
		Total:      total,
	}, nil
}

// UpdateUser updates allowed user fields.
func (s *UserService) UpdateUser(ctx context.Context, projectID, userID string, params UpdateUserParams, adminID string) (*UserDetail, error) {
	q := sqlc.New(s.db)

	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	emailVerified := user.EmailVerified
	metadata := user.Metadata
	if params.EmailVerified != nil {
		emailVerified = *params.EmailVerified
	}
	if params.Metadata != nil {
		metadata = []byte(*params.Metadata)
	}

	err = q.UpdateUserEmailAndMetadata(ctx, sqlc.UpdateUserEmailAndMetadataParams{
		ID:            userID,
		EmailVerified: emailVerified,
		Metadata:      metadata,
		ProjectID:     projectID,
	})
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventAdminUserUpdate,
		Actor:     audit.ActorInfo{UserID: adminID},
		Target:    &audit.TargetInfo{Type: "user", ID: userID},
		Result:    "success",
		ProjectID: projectID,
	})

	return s.GetUser(ctx, projectID, userID)
}

// DeleteUser performs GDPR cryptographic erasure.
func (s *UserService) DeleteUser(ctx context.Context, projectID, userID, adminID string) error {
	q := sqlc.New(s.db)

	_, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}

	// Revoke all sessions first.
	if err := s.sessionSvc.RevokeAll(ctx, userID, projectID); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}

	// GDPR cryptographic erasure: revoke DEK + log gdpr.erasure event.
	if err := s.auditSvc.Erase(ctx, projectID, userID); err != nil {
		return fmt.Errorf("gdpr erasure: %w", err)
	}

	// Clean up FK-constrained records + delete user in a single transaction.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	txq := sqlc.New(tx)

	if err := txq.DeleteUserEncryptionKeys(ctx, sqlc.DeleteUserEncryptionKeysParams{UserID: &userID, ProjectID: &projectID}); err != nil {
		return fmt.Errorf("delete encryption keys: %w", err)
	}
	if err := txq.DeleteUserPasswordHistory(ctx, userID); err != nil {
		return fmt.Errorf("delete password history: %w", err)
	}
	if err := txq.DeleteUserVerificationTokens(ctx, sqlc.DeleteUserVerificationTokensParams{UserID: userID, ProjectID: projectID}); err != nil {
		return fmt.Errorf("delete verification tokens: %w", err)
	}
	if err := txq.DeleteUserConsents(ctx, sqlc.DeleteUserConsentsParams{UserID: userID, ProjectID: projectID}); err != nil {
		return fmt.Errorf("delete user consents: %w", err)
	}
	if err := txq.DeleteUserRefreshTokens(ctx, sqlc.DeleteUserRefreshTokensParams{UserID: userID, ProjectID: projectID}); err != nil {
		return fmt.Errorf("delete refresh tokens: %w", err)
	}
	if err := txq.DeleteUserSessions(ctx, sqlc.DeleteUserSessionsParams{UserID: userID, ProjectID: projectID}); err != nil {
		return fmt.Errorf("delete sessions: %w", err)
	}
	if err := txq.DeleteUser(ctx, sqlc.DeleteUserParams{ID: userID, ProjectID: projectID}); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete transaction: %w", err)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventAdminUserDelete,
		Actor:     audit.ActorInfo{UserID: adminID},
		Target:    &audit.TargetInfo{Type: "user", ID: userID},
		Result:    "success",
		ProjectID: projectID,
	})

	return nil
}

// BanUser bans a user and revokes all their sessions.
func (s *UserService) BanUser(ctx context.Context, projectID, userID, reason, adminID string) error {
	if reason == "" {
		return ErrBanReasonRequired
	}

	q := sqlc.New(s.db)

	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}

	if user.Banned {
		return ErrUserAlreadyBanned
	}

	if err := q.BanUser(ctx, sqlc.BanUserParams{
		ID:        userID,
		BanReason: &reason,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("ban user: %w", err)
	}

	// Revoke ALL sessions.
	if err := s.sessionSvc.RevokeAll(ctx, userID, projectID); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventAdminUserUpdate,
		Actor:     audit.ActorInfo{UserID: adminID},
		Target:    &audit.TargetInfo{Type: "user", ID: userID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"action": "ban", "reason": reason},
	})

	return nil
}

// UnbanUser removes the ban from a user.
func (s *UserService) UnbanUser(ctx context.Context, projectID, userID, adminID string) error {
	q := sqlc.New(s.db)

	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}

	if !user.Banned {
		return ErrUserNotBanned
	}

	if err := q.UnbanUser(ctx, sqlc.UnbanUserParams{
		ID:        userID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("unban user: %w", err)
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventAdminUserUpdate,
		Actor:     audit.ActorInfo{UserID: adminID},
		Target:    &audit.TargetInfo{Type: "user", ID: userID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"action": "unban"},
	})

	return nil
}

// ResetUserPassword generates a password reset token and revokes all sessions.
func (s *UserService) ResetUserPassword(ctx context.Context, projectID, userID, adminID string) error {
	q := sqlc.New(s.db)

	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("get user: %w", err)
	}

	// Generate reset token.
	plainToken, err := crypto.GenerateToken(32)
	if err != nil {
		return fmt.Errorf("generate reset token: %w", err)
	}
	tokenHash := sha256Hash(plainToken)

	_, err = q.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
		ID:        id.New("vt_"),
		ProjectID: projectID,
		UserID:    userID,
		TokenHash: tokenHash,
		Type:      "password_reset",
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(1 * time.Hour), Valid: true},
	})
	if err != nil {
		return fmt.Errorf("create reset token: %w", err)
	}

	// Revoke all sessions.
	if err := s.sessionSvc.RevokeAll(ctx, userID, projectID); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}

	// Send reset email (best-effort).
	emailAddr, decErr := s.decryptEmail(ctx, q, user.EmailEncrypted, projectID)
	if decErr == nil && s.emailSender != nil && s.emailRenderer != nil {
		htmlBody, textBody, renderErr := s.emailRenderer.Render(email.TemplatePasswordReset, &email.TemplateData{
			ProjectName: "PalAuth",
			UserEmail:   emailAddr,
			Token:       plainToken,
		})
		if renderErr == nil {
			_ = s.emailSender.Send(ctx, emailAddr, "Password Reset", htmlBody, textBody)
		}
	}

	s.auditLog(ctx, &audit.Event{
		EventType: audit.EventAuthPasswordResetReq,
		Actor:     audit.ActorInfo{UserID: adminID},
		Target:    &audit.TargetInfo{Type: "user", ID: userID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"initiated_by": "admin"},
	})

	return nil
}

// DeactivateInactiveUsers bans users who haven't logged in for the given number of days.
func (s *UserService) DeactivateInactiveUsers(ctx context.Context, days int32) (int, error) {
	q := sqlc.New(s.db)

	inactiveUsers, err := q.GetInactiveUsers(ctx, days)
	if err != nil {
		return 0, fmt.Errorf("get inactive users: %w", err)
	}

	count := 0
	reason := fmt.Sprintf("inactive_%dd", days)
	for _, u := range inactiveUsers {
		if banErr := q.BanUser(ctx, sqlc.BanUserParams{
			ID:        u.ID,
			BanReason: &reason,
			ProjectID: u.ProjectID,
		}); banErr != nil {
			s.logger.Error("failed to ban inactive user", "user_id", u.ID, "error", banErr)
			continue
		}

		// Revoke all sessions.
		if revokeErr := s.sessionSvc.RevokeAll(ctx, u.ID, u.ProjectID); revokeErr != nil {
			s.logger.Error("failed to revoke sessions for inactive user", "user_id", u.ID, "error", revokeErr)
		}

		s.auditLog(ctx, &audit.Event{
			EventType: audit.EventAdminUserDeactivateInactive,
			Actor:     audit.ActorInfo{UserID: "system"},
			Target:    &audit.TargetInfo{Type: "user", ID: u.ID},
			Result:    "success",
			ProjectID: u.ProjectID,
			Metadata:  map[string]any{"inactive_days": days},
		})

		count++
	}

	return count, nil
}

// getOrCreateProjectDEK retrieves or creates a per-project data encryption key.
func (s *UserService) getOrCreateProjectDEK(ctx context.Context, q *sqlc.Queries, projectID string) ([]byte, error) {
	dekAAD := []byte("project-dek:" + projectID)

	ek, err := q.GetProjectDEK(ctx, &projectID)
	if err == nil {
		return crypto.Decrypt(ek.EncryptedKey, s.kek, dekAAD)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get project DEK: %w", err)
	}

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

// decryptEmail decrypts a user's encrypted email using the project DEK.
func (s *UserService) decryptEmail(ctx context.Context, q *sqlc.Queries, encryptedEmail []byte, projectID string) (string, error) {
	dekAAD := []byte("project-dek:" + projectID)

	ek, err := q.GetProjectDEK(ctx, &projectID)
	if err != nil {
		return "", fmt.Errorf("get project DEK: %w", err)
	}

	dek, err := crypto.Decrypt(ek.EncryptedKey, s.kek, dekAAD)
	if err != nil {
		return "", fmt.Errorf("decrypt DEK: %w", err)
	}

	emailAAD := []byte("email:" + projectID)
	plaintext, err := crypto.Decrypt(encryptedEmail, dek, emailAAD)
	if err != nil {
		return "", fmt.Errorf("decrypt email: %w", err)
	}

	return string(plaintext), nil
}

// normalizeEmail lowercases and trims whitespace from an email address.
func normalizeEmail(addr string) string {
	return strings.ToLower(strings.TrimSpace(addr))
}

// sha256Hash computes SHA-256 hash and returns raw bytes.
func sha256Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// toUserDetail converts a sqlc.User to UserDetail.
func (s *UserService) toUserDetail(user *sqlc.User, emailAddr string, activeSessions int64) *UserDetail {
	detail := &UserDetail{
		ID:             user.ID,
		ProjectID:      user.ProjectID,
		Email:          emailAddr,
		EmailVerified:  user.EmailVerified,
		Banned:         user.Banned,
		Metadata:       user.Metadata,
		ActiveSessions: activeSessions,
	}
	if user.BanReason != nil {
		detail.BanReason = *user.BanReason
	}
	if user.LastLoginAt.Valid {
		detail.LastLoginAt = user.LastLoginAt.Time.UTC().Format(time.RFC3339)
	}
	if user.CreatedAt.Valid {
		detail.CreatedAt = user.CreatedAt.Time.UTC().Format(time.RFC3339)
	}
	if user.UpdatedAt.Valid {
		detail.UpdatedAt = user.UpdatedAt.Time.UTC().Format(time.RFC3339)
	}
	return detail
}

// auditLog safely logs an audit event.
func (s *UserService) auditLog(ctx context.Context, event *audit.Event) {
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, event) //nolint:errcheck // best-effort audit
	}
}
