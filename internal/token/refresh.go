package token

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/hook"
	"github.com/palauth/palauth/internal/id"
)

// Refresh token constants.
const (
	RefreshTokenBytes = 32                    // 256-bit
	GracePeriod       = 30 * time.Second      // concurrent refresh tolerance
	DefaultRefreshTTL = 30 * 24 * time.Hour   // 30 days
)

// Errors for refresh token operations.
var (
	ErrTokenNotFound  = errors.New("refresh token not found")
	ErrTokenUsed      = errors.New("refresh token already used")
	ErrTokenStolen    = errors.New("refresh token reuse detected — family revoked")
	ErrTokenExpiredRT = errors.New("refresh token expired")
	ErrSessionRevoked = errors.New("session has been revoked")
)

// RefreshResult is returned after a successful token rotation.
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	SessionID    string
	UserID       string
}

// RefreshService handles refresh token issuance and rotation.
type RefreshService struct {
	db          *pgxpool.Pool
	jwt         *JWTService
	hookCaller  hook.Caller
	ttl         time.Duration
	gracePeriod time.Duration
	logger      *slog.Logger
}

// SetHookCaller sets the hook caller on the refresh service.
func (s *RefreshService) SetHookCaller(caller hook.Caller) {
	s.hookCaller = caller
}

// NewRefreshService creates a new refresh token service.
func NewRefreshService(db *pgxpool.Pool, jwtSvc *JWTService, ttl time.Duration, logger *slog.Logger) *RefreshService {
	if ttl == 0 {
		ttl = DefaultRefreshTTL
	}
	return &RefreshService{
		db:          db,
		jwt:         jwtSvc,
		ttl:         ttl,
		gracePeriod: GracePeriod,
		logger:      logger,
	}
}

// SetGracePeriod overrides the default grace period. Intended for testing only.
func (s *RefreshService) SetGracePeriod(d time.Duration) {
	s.gracePeriod = d
}

// Issue creates a new refresh token and stores its hash in the database.
// Returns the plaintext token (to send to the client).
func (s *RefreshService) Issue(ctx context.Context, userID, sessionID, projectID string) (string, error) {
	plainToken, err := crypto.GenerateToken(RefreshTokenBytes)
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}

	tokenHash := hashToken(plainToken)
	familyID := id.New("rtf_")
	tokenID := id.New("rt_")

	q := sqlc.New(s.db)
	_, err = q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:        tokenID,
		ProjectID: projectID,
		SessionID: sessionID,
		UserID:    userID,
		TokenHash: tokenHash,
		FamilyID:  familyID,
		ParentID:  nil,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(s.ttl), Valid: true},
	})
	if err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}

	return plainToken, nil
}

// ErrProjectMismatch is returned when the refresh token doesn't belong to the requesting project.
var ErrProjectMismatch = errors.New("refresh token does not belong to this project")

// Rotate validates the old refresh token and issues a new one.
// Implements family-based revocation and 30s grace period.
// The entire operation runs inside a single serialized transaction with
// SELECT ... FOR UPDATE to prevent TOCTOU race conditions.
func (s *RefreshService) Rotate(ctx context.Context, oldPlainToken, projectID string, issueParams *IssueParams) (*RefreshResult, error) {
	// Execute before.token.refresh hook — deny blocks token refresh.
	if s.hookCaller != nil {
		hookPayload := hook.Payload{
			User: &hook.UserInfo{ID: issueParams.UserID},
		}
		_, hookErr := s.hookCaller.ExecuteBlocking(ctx, projectID, hook.EventBeforeTokenRefresh, hookPayload)
		if hookErr != nil {
			if errors.Is(hookErr, hook.ErrHookDenied) {
				return nil, hook.ErrHookDenied
			}
			return nil, fmt.Errorf("before.token.refresh hook: %w", hookErr)
		}
	}

	oldHash := hashToken(oldPlainToken)

	// Begin transaction — ALL reads and writes happen inside this transaction
	// with FOR UPDATE locks to prevent concurrent rotation races.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	q := sqlc.New(tx)

	// Lookup token with row-level lock to prevent concurrent rotation.
	oldToken, err := q.GetRefreshTokenByHashForUpdate(ctx, oldHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	// Validate project_id scoping — multi-tenant isolation.
	if oldToken.ProjectID != projectID {
		return nil, ErrProjectMismatch
	}

	// Check expiry.
	if oldToken.ExpiresAt.Valid && time.Now().After(oldToken.ExpiresAt.Time) {
		return nil, ErrTokenExpiredRT
	}

	// If token is already used, check for grace period or stolen token.
	if oldToken.Used {
		return s.handleUsedToken(ctx, tx, q, &oldToken, issueParams)
	}

	// Verify session is not revoked.
	session, err := q.GetSession(ctx, oldToken.SessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionRevoked
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	if session.RevokedAt.Valid {
		return nil, ErrSessionRevoked
	}

	// Mark old token as used.
	if err := q.MarkRefreshTokenUsed(ctx, oldToken.ID); err != nil {
		return nil, fmt.Errorf("mark token used: %w", err)
	}

	// Generate new refresh token in the same family.
	newPlainToken, err := crypto.GenerateToken(RefreshTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("generate new refresh token: %w", err)
	}

	newHash := hashToken(newPlainToken)
	newTokenID := id.New("rt_")
	parentID := oldToken.ID

	_, err = q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:        newTokenID,
		ProjectID: oldToken.ProjectID,
		SessionID: oldToken.SessionID,
		UserID:    oldToken.UserID,
		TokenHash: newHash,
		FamilyID:  oldToken.FamilyID,
		ParentID:  &parentID,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(s.ttl), Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("store new refresh token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	// Issue new access token. Preserve auth_time from the session's created_at
	// per RFC 9068 — auth_time reflects when the user originally authenticated.
	issueParams.UserID = oldToken.UserID
	issueParams.SessionID = oldToken.SessionID
	issueParams.ProjectID = session.ProjectID
	if issueParams.AuthTime.IsZero() {
		issueParams.AuthTime = session.CreatedAt.Time
	}

	accessToken, err := s.jwt.Issue(issueParams)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newPlainToken,
		SessionID:    oldToken.SessionID,
		UserID:       oldToken.UserID,
	}, nil
}

// handleUsedToken handles the case where the old token has already been used.
// Checks if the child token was created within the grace period; if so, returns
// a valid result. Otherwise, treats it as a stolen token and revokes the family.
// Runs inside the caller's transaction with FOR UPDATE locks.
func (s *RefreshService) handleUsedToken(ctx context.Context, tx pgx.Tx, q *sqlc.Queries, oldToken *sqlc.RefreshToken, issueParams *IssueParams) (*RefreshResult, error) {
	// Find the child token with row-level lock.
	parentID := oldToken.ID
	childToken, err := q.GetChildRefreshTokenForUpdate(ctx, &parentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No child found — the token was marked used but no child created.
			// This is unexpected; treat as stolen.
			s.revokeAndLog(ctx, q, oldToken)
			_ = tx.Commit(ctx) //nolint:errcheck // best-effort commit of revocation
			return nil, ErrTokenStolen
		}
		return nil, fmt.Errorf("find child token: %w", err)
	}

	// Grace period: check if the child was created within the grace window.
	if time.Since(childToken.CreatedAt.Time) > s.gracePeriod {
		// Outside grace period — stolen token.
		s.revokeAndLog(ctx, q, oldToken)
		_ = tx.Commit(ctx) //nolint:errcheck // best-effort commit of revocation
		return nil, ErrTokenStolen
	}

	// Within grace period — return a valid result.
	session, err := q.GetSession(ctx, oldToken.SessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionRevoked
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	issueParams.UserID = oldToken.UserID
	issueParams.SessionID = oldToken.SessionID
	issueParams.ProjectID = session.ProjectID
	if issueParams.AuthTime.IsZero() {
		issueParams.AuthTime = session.CreatedAt.Time
	}

	accessToken, err := s.jwt.Issue(issueParams)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	// Generate a new plaintext for the child token (we only store hashes).
	newPlainToken, err := crypto.GenerateToken(RefreshTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("generate grace period token: %w", err)
	}
	newHash := hashToken(newPlainToken)

	// Update the child token's hash (it hasn't been used yet) — locked by FOR UPDATE.
	if err := q.UpdateRefreshTokenHash(ctx, sqlc.UpdateRefreshTokenHashParams{
		TokenHash: newHash,
		ID:        childToken.ID,
	}); err != nil {
		return nil, fmt.Errorf("update grace period token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newPlainToken,
		SessionID:    oldToken.SessionID,
		UserID:       oldToken.UserID,
	}, nil
}

// revokeAndLog revokes the token family and logs the event.
func (s *RefreshService) revokeAndLog(ctx context.Context, q *sqlc.Queries, token *sqlc.RefreshToken) {
	s.logger.Warn("refresh token reuse detected",
		"family_id", token.FamilyID,
		"token_id", token.ID,
		"user_id", token.UserID,
	)
	if err := q.RevokeRefreshTokenFamily(ctx, token.FamilyID); err != nil {
		s.logger.Error("failed to revoke token family", "error", err)
	}
}

// RevokeFamily revokes all refresh tokens in a family.
func (s *RefreshService) RevokeFamily(ctx context.Context, familyID string) error {
	q := sqlc.New(s.db)
	return q.RevokeRefreshTokenFamily(ctx, familyID)
}

// RevokeByHash revokes a specific refresh token and its family.
func (s *RefreshService) RevokeByHash(ctx context.Context, plainToken string) error {
	tokenHash := hashToken(plainToken)
	q := sqlc.New(s.db)

	token, err := q.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Per RFC 7009: always return success even if token not found.
			return nil
		}
		return fmt.Errorf("get refresh token: %w", err)
	}

	return q.RevokeRefreshTokenFamily(ctx, token.FamilyID)
}

// hashToken computes SHA-256 hash of a plaintext token.
func hashToken(plainToken string) []byte {
	h := sha256.Sum256([]byte(plainToken))
	return h[:]
}
