package project

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

var (
	ErrNotFound    = errors.New("project not found")
	ErrEmptyName   = errors.New("project name is required")
	ErrInvalidJSON = errors.New("invalid project config JSON")
)

// Config holds project-level settings stored as JSONB.
type Config struct {
	EmailVerificationMethod string `json:"email_verification_method"` // "code" or "link"
	EmailVerificationTTL    int    `json:"email_verification_ttl"`    // seconds
	PasswordMinLength       int    `json:"password_min_length"`
	PasswordMaxLength       int    `json:"password_max_length"`
	MFAEnabled              bool   `json:"mfa_enabled"`
	SessionIdleTimeout      int    `json:"session_idle_timeout"` // seconds, 0 = no idle timeout
	SessionAbsTimeout       int    `json:"session_abs_timeout"`  // seconds
}

// DefaultConfig returns sensible defaults for a new project.
func DefaultConfig() Config {
	return Config{
		EmailVerificationMethod: "code",
		EmailVerificationTTL:    3600,
		PasswordMinLength:       15,
		PasswordMaxLength:       64,
		MFAEnabled:              false,
		SessionIdleTimeout:      0,
		SessionAbsTimeout:       2592000, // 30 days
	}
}

// Project is the domain model returned to callers.
type Project struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Config    Config `json:"config"`
	CreatedAt string        `json:"created_at"`
	UpdatedAt string        `json:"updated_at"`
}

// Service manages project CRUD operations.
type Service struct {
	db     *pgxpool.Pool
	logger *slog.Logger
}

// NewService creates a new project service.
func NewService(db *pgxpool.Pool, logger *slog.Logger) *Service {
	return &Service{db: db, logger: logger}
}

// Create creates a new project with the given name and config.
func (s *Service) Create(ctx context.Context, name string, cfg Config) (*Project, error) {
	if name == "" {
		return nil, ErrEmptyName
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	q := sqlc.New(s.db)
	row, err := q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID:     id.New("prj_"),
		Name:   name,
		Config: configJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}

	return toProject(&row)
}

// Get retrieves a project by ID.
func (s *Service) Get(ctx context.Context, projectID string) (*Project, error) {
	q := sqlc.New(s.db)
	row, err := q.GetProject(ctx, projectID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get project: %w", err)
	}

	return toProject(&row)
}

// Update updates a project's name and config.
func (s *Service) Update(ctx context.Context, projectID, name string, cfg Config) (*Project, error) {
	if name == "" {
		return nil, ErrEmptyName
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	q := sqlc.New(s.db)
	row, err := q.UpdateProject(ctx, sqlc.UpdateProjectParams{
		ID:     projectID,
		Name:   name,
		Config: configJSON,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("update project: %w", err)
	}

	return toProject(&row)
}

// Delete deletes a project by ID. Returns ErrNotFound if the project does not exist.
func (s *Service) Delete(ctx context.Context, projectID string) error {
	q := sqlc.New(s.db)
	_, err := q.DeleteProject(ctx, projectID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("delete project: %w", err)
	}
	return nil
}

// List returns all projects.
func (s *Service) List(ctx context.Context) ([]Project, error) {
	q := sqlc.New(s.db)
	rows, err := q.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}

	projects := make([]Project, 0, len(rows))
	for _, row := range rows {
		p, err := toProject(&row)
		if err != nil {
			return nil, err
		}
		projects = append(projects, *p)
	}

	return projects, nil
}

func toProject(row *sqlc.Project) (*Project, error) {
	var cfg Config
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal project config: %w", err)
	}

	p := &Project{
		ID:     row.ID,
		Name:   row.Name,
		Config: cfg,
	}
	if row.CreatedAt.Valid {
		p.CreatedAt = row.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
	}
	if row.UpdatedAt.Valid {
		p.UpdatedAt = row.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
	}
	return p, nil
}
