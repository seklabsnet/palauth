package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionRevoked  = errors.New("session revoked")
)

// Service handles session lifecycle operations.
type Service struct {
	db       *pgxpool.Pool
	auditSvc *audit.Service
	logger   *slog.Logger
}

// NewService creates a new session service.
func NewService(db *pgxpool.Pool, auditSvc *audit.Service, logger *slog.Logger) *Service {
	return &Service{
		db:       db,
		auditSvc: auditSvc,
		logger:   logger,
	}
}

// CreateParams contains the parameters for creating a session.
type CreateParams struct {
	ProjectID string
	UserID    string
	IP        string
	UserAgent string
	ACR       string   // "aal1", "aal2", "aal3"
	AMR       []string // e.g. ["pwd"], ["pwd", "otp"]
}

// Session represents an active user session.
type Session struct {
	ID            string     `json:"id"`
	ProjectID     string     `json:"project_id"`
	UserID        string     `json:"user_id"`
	IP            string     `json:"ip,omitempty"`
	UserAgent     string     `json:"user_agent,omitempty"`
	ACR           string     `json:"acr"`
	AMR           []string   `json:"amr"`
	IdleTimeoutAt *time.Time `json:"idle_timeout_at,omitempty"`
	AbsTimeoutAt  time.Time  `json:"abs_timeout_at"`
	LastActivity  time.Time  `json:"last_activity"`
	CreatedAt     time.Time  `json:"created_at"`
}

// AALTimeouts returns the idle and absolute timeout durations for a given ACR level.
func AALTimeouts(acr string) (idleTimeout, absTimeout time.Duration) {
	switch acr {
	case "aal2":
		return 1 * time.Hour, 24 * time.Hour
	case "aal3":
		return 15 * time.Minute, 12 * time.Hour
	default: // aal1
		return 0, 30 * 24 * time.Hour // 0 = no idle timeout
	}
}

// Create creates a new session with AAL-based timeouts.
func (s *Service) Create(ctx context.Context, params *CreateParams) (*Session, error) {
	now := time.Now()
	idleTimeout, absTimeout := AALTimeouts(params.ACR)

	sessionID := id.New("sess_")
	amrJSON, err := json.Marshal(params.AMR)
	if err != nil {
		return nil, fmt.Errorf("marshal amr: %w", err)
	}

	var ip, ua *string
	if params.IP != "" {
		ip = &params.IP
	}
	if params.UserAgent != "" {
		ua = &params.UserAgent
	}

	var idleTimeoutAt pgtype.Timestamptz
	if idleTimeout > 0 {
		t := now.Add(idleTimeout)
		idleTimeoutAt = pgtype.Timestamptz{Time: t, Valid: true}
	}

	q := sqlc.New(s.db)
	row, err := q.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:            sessionID,
		ProjectID:     params.ProjectID,
		UserID:        params.UserID,
		Ip:            ip,
		UserAgent:     ua,
		Acr:           params.ACR,
		Amr:           amrJSON,
		IdleTimeoutAt: idleTimeoutAt,
		AbsTimeoutAt:  pgtype.Timestamptz{Time: now.Add(absTimeout), Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	sess := toSession(&row)

	// Audit log.
	s.auditSvc.Log(ctx, &audit.Event{ //nolint:errcheck // best-effort audit
		EventType: audit.EventSessionCreate,
		Actor:     audit.ActorInfo{UserID: params.UserID, IP: params.IP},
		Target:    &audit.TargetInfo{Type: "session", ID: sessionID},
		Result:    "success",
		ProjectID: params.ProjectID,
		Metadata:  map[string]any{"acr": params.ACR, "amr": params.AMR},
	})

	return sess, nil
}

// Get retrieves a session by ID, checking timeouts and auto-revoking if expired.
func (s *Service) Get(ctx context.Context, sessionID string) (*Session, error) {
	q := sqlc.New(s.db)
	row, err := q.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	sess := toSession(&row)

	// Check timeouts.
	if expired, reason := isExpired(sess); expired {
		// Auto-revoke expired session.
		if revokeErr := q.RevokeSession(ctx, sessionID); revokeErr != nil {
			s.logger.Error("failed to auto-revoke expired session", "session_id", sessionID, "error", revokeErr)
		}
		s.logger.Info("session auto-revoked", "session_id", sessionID, "reason", reason)
		return nil, ErrSessionExpired
	}

	return sess, nil
}

// List returns active sessions for a user within a project.
func (s *Service) List(ctx context.Context, userID, projectID string) ([]Session, error) {
	q := sqlc.New(s.db)
	rows, err := q.ListActiveSessionsByProject(ctx, sqlc.ListActiveSessionsByProjectParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}

	sessions := make([]Session, 0, len(rows))
	for i := range rows {
		sess := toSession(&rows[i])
		// Only include non-expired sessions.
		if expired, _ := isExpired(sess); !expired {
			sessions = append(sessions, *sess)
		}
	}

	return sessions, nil
}

// Revoke revokes a single session. The userID parameter ensures the caller
// owns the session (authorization check).
func (s *Service) Revoke(ctx context.Context, sessionID, projectID, userID string) error {
	q := sqlc.New(s.db)

	// Verify session exists, belongs to project, and is owned by the user.
	_, err := q.GetSessionByProjectAndUser(ctx, sqlc.GetSessionByProjectAndUserParams{
		ID:        sessionID,
		ProjectID: projectID,
		UserID:    userID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("get session: %w", err)
	}

	if err := q.RevokeSessionByProject(ctx, sqlc.RevokeSessionByProjectParams{
		ID:        sessionID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	s.auditSvc.Log(ctx, &audit.Event{ //nolint:errcheck // best-effort audit
		EventType: audit.EventSessionRevoke,
		Actor:     audit.ActorInfo{UserID: userID},
		Target:    &audit.TargetInfo{Type: "session", ID: sessionID},
		Result:    "success",
		ProjectID: projectID,
	})

	return nil
}

// RevokeAll revokes all active sessions for a user within a project.
func (s *Service) RevokeAll(ctx context.Context, userID, projectID string) error {
	q := sqlc.New(s.db)
	if err := q.RevokeUserSessionsByProject(ctx, sqlc.RevokeUserSessionsByProjectParams{
		UserID:    userID,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}

	s.auditSvc.Log(ctx, &audit.Event{ //nolint:errcheck // best-effort audit
		EventType: audit.EventSessionRevoke,
		Actor:     audit.ActorInfo{UserID: userID},
		Target:    &audit.TargetInfo{Type: "user", ID: userID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"scope": "all_sessions"},
	})

	return nil
}

// Touch updates a session's last_activity and recalculates idle_timeout_at.
func (s *Service) Touch(ctx context.Context, sess *Session) error {
	now := time.Now()
	idleTimeout, _ := AALTimeouts(sess.ACR)

	var idleTimeoutAt pgtype.Timestamptz
	if idleTimeout > 0 {
		t := now.Add(idleTimeout)
		idleTimeoutAt = pgtype.Timestamptz{Time: t, Valid: true}
	}

	q := sqlc.New(s.db)
	if err := q.UpdateSessionActivity(ctx, sqlc.UpdateSessionActivityParams{
		ID:            sess.ID,
		IdleTimeoutAt: idleTimeoutAt,
	}); err != nil {
		return fmt.Errorf("update session activity: %w", err)
	}

	return nil
}

// ValidateAndTouch gets a session, checks it's valid, and touches it.
// Returns the session if valid, or an error if expired/revoked/not found.
func (s *Service) ValidateAndTouch(ctx context.Context, sessionID string) (*Session, error) {
	sess, err := s.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if err := s.Touch(ctx, sess); err != nil {
		return nil, err
	}

	return sess, nil
}

// isExpired checks if a session has expired (idle or absolute timeout).
func isExpired(sess *Session) (expired bool, reason string) {
	now := time.Now()

	// Check absolute timeout.
	if now.After(sess.AbsTimeoutAt) {
		return true, "absolute_timeout"
	}

	// Check idle timeout (only if set).
	if sess.IdleTimeoutAt != nil && now.After(*sess.IdleTimeoutAt) {
		return true, "idle_timeout"
	}

	return false, ""
}

// toSession converts a sqlc Session to a domain Session.
func toSession(row *sqlc.Session) *Session {
	sess := &Session{
		ID:           row.ID,
		ProjectID:    row.ProjectID,
		UserID:       row.UserID,
		ACR:          row.Acr,
		AbsTimeoutAt: row.AbsTimeoutAt.Time,
		LastActivity: row.LastActivity.Time,
		CreatedAt:    row.CreatedAt.Time,
	}

	if row.Ip != nil {
		sess.IP = *row.Ip
	}
	if row.UserAgent != nil {
		sess.UserAgent = *row.UserAgent
	}
	if row.IdleTimeoutAt.Valid {
		t := row.IdleTimeoutAt.Time
		sess.IdleTimeoutAt = &t
	}

	// Unmarshal AMR from JSON.
	if len(row.Amr) > 0 {
		var amr []string
		if err := json.Unmarshal(row.Amr, &amr); err == nil {
			sess.AMR = amr
		}
	}

	return sess
}
