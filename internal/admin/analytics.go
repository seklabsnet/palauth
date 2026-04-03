package admin

import (
	"context"
	"fmt"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/database/sqlc"
)

// ProjectAnalytics contains project-level analytics data.
type ProjectAnalytics struct {
	MAU            int64 `json:"mau"`
	ActiveSessions int64 `json:"active_sessions"`
	TotalUsers     int64 `json:"total_users"`
	LoginTrend24h  int64 `json:"login_trend_24h"`
}

// GetProjectAnalytics returns analytics for a project.
func (s *UserService) GetProjectAnalytics(ctx context.Context, projectID string) (*ProjectAnalytics, error) {
	q := sqlc.New(s.db)

	mau, err := q.CountActiveUsersByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("count MAU: %w", err)
	}

	activeSessions, err := q.CountActiveSessionsByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("count active sessions: %w", err)
	}

	totalUsers, err := q.CountUsersByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("count total users: %w", err)
	}

	loginTrend, err := q.CountRecentAuditLogsByType(ctx, sqlc.CountRecentAuditLogsByTypeParams{
		ProjectID: projectID,
		EventType: audit.EventAuthLoginSuccess,
		Column3:   24,
	})
	if err != nil {
		s.logger.Warn("failed to count login trend", "project_id", projectID, "error", err)
		loginTrend = 0
	}

	return &ProjectAnalytics{
		MAU:            mau,
		ActiveSessions: activeSessions,
		TotalUsers:     totalUsers,
		LoginTrend24h:  loginTrend,
	}, nil
}
