package project

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
)

var (
	ErrNotFound    = errors.New("project not found")
	ErrEmptyName   = errors.New("project name is required")
	ErrInvalidJSON = errors.New("invalid project config JSON")
)

// SocialProviderConfig holds configuration for a single social login provider.
type SocialProviderConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // encrypted at rest in DB
	Enabled      bool   `json:"enabled"`
	// Apple-specific
	TeamID     string `json:"team_id,omitempty"`
	KeyID      string `json:"key_id,omitempty"`
	PrivateKey string `json:"private_key,omitempty"` // encrypted at rest in DB
	// Microsoft-specific
	Tenant string `json:"tenant,omitempty"` // default: "common"
}

// Config holds project-level settings stored as JSONB.
type Config struct {
	EmailVerificationMethod string                          `json:"email_verification_method"` // "code" or "link"
	EmailVerificationTTL    int                             `json:"email_verification_ttl"`    // seconds
	PasswordMinLength       int                             `json:"password_min_length"`
	PasswordMaxLength       int                             `json:"password_max_length"`
	MFAEnabled              bool                            `json:"mfa_enabled"`
	SessionIdleTimeout      int                             `json:"session_idle_timeout"` // seconds, 0 = no idle timeout
	SessionAbsTimeout       int                             `json:"session_abs_timeout"`  // seconds
	SocialProviders         map[string]SocialProviderConfig `json:"social_providers,omitempty"`
	AllowedRedirectURIs     []string                        `json:"allowed_redirect_uris,omitempty"`
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
	kek    []byte // KEK for encrypting social provider secrets
	logger *slog.Logger
}

// NewService creates a new project service.
func NewService(db *pgxpool.Pool, kek []byte, logger *slog.Logger) *Service {
	return &Service{db: db, kek: kek, logger: logger}
}

// Create creates a new project with the given name and config.
func (s *Service) Create(ctx context.Context, name string, cfg *Config) (*Project, error) {
	if name == "" {
		return nil, ErrEmptyName
	}

	projectID := id.New("prj_")

	// Work on a copy to avoid mutating the caller's config.
	cfgCopy := *cfg

	// Encrypt social provider secrets before storing.
	if err := s.encryptSocialSecrets(&cfgCopy, projectID); err != nil {
		return nil, err
	}

	configJSON, err := json.Marshal(cfgCopy)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	q := sqlc.New(s.db)
	row, err := q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID:     projectID,
		Name:   name,
		Config: configJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}

	return s.toProject(&row)
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

	return s.toProject(&row)
}

// Update updates a project's name and config.
func (s *Service) Update(ctx context.Context, projectID, name string, cfg *Config) (*Project, error) {
	if name == "" {
		return nil, ErrEmptyName
	}

	// Work on a copy to avoid mutating the caller's config.
	cfgCopy := *cfg

	// Encrypt social provider secrets before storing.
	if err := s.encryptSocialSecrets(&cfgCopy, projectID); err != nil {
		return nil, err
	}

	configJSON, err := json.Marshal(cfgCopy)
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

	return s.toProject(&row)
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
		p, err := s.toProject(&row)
		if err != nil {
			return nil, err
		}
		projects = append(projects, *p)
	}

	return projects, nil
}

// encryptSocialSecrets encrypts client_secret and private_key fields in social provider configs.
func (s *Service) encryptSocialSecrets(cfg *Config, projectID string) error {
	if len(s.kek) == 0 || cfg.SocialProviders == nil {
		return nil
	}
	for name, pc := range cfg.SocialProviders {
		aad := []byte("social-secret:" + projectID + ":" + name)
		if pc.ClientSecret != "" {
			enc, err := crypto.Encrypt([]byte(pc.ClientSecret), s.kek, aad)
			if err != nil {
				return fmt.Errorf("encrypt client_secret for %s: %w", name, err)
			}
			pc.ClientSecret = base64.StdEncoding.EncodeToString(enc)
		}
		if pc.PrivateKey != "" {
			enc, err := crypto.Encrypt([]byte(pc.PrivateKey), s.kek, aad)
			if err != nil {
				return fmt.Errorf("encrypt private_key for %s: %w", name, err)
			}
			pc.PrivateKey = base64.StdEncoding.EncodeToString(enc)
		}
		cfg.SocialProviders[name] = pc
	}
	return nil
}

// decryptSocialSecrets decrypts client_secret and private_key fields in social provider configs.
func (s *Service) decryptSocialSecrets(cfg *Config, projectID string) error {
	if len(s.kek) == 0 || cfg.SocialProviders == nil {
		return nil
	}
	for name, pc := range cfg.SocialProviders {
		aad := []byte("social-secret:" + projectID + ":" + name)
		if pc.ClientSecret != "" {
			enc, err := base64.StdEncoding.DecodeString(pc.ClientSecret)
			if err != nil {
				return fmt.Errorf("decode client_secret for %s: %w", name, err)
			}
			dec, err := crypto.Decrypt(enc, s.kek, aad)
			if err != nil {
				return fmt.Errorf("decrypt client_secret for %s: %w", name, err)
			}
			pc.ClientSecret = string(dec)
		}
		if pc.PrivateKey != "" {
			enc, err := base64.StdEncoding.DecodeString(pc.PrivateKey)
			if err != nil {
				return fmt.Errorf("decode private_key for %s: %w", name, err)
			}
			dec, err := crypto.Decrypt(enc, s.kek, aad)
			if err != nil {
				return fmt.Errorf("decrypt private_key for %s: %w", name, err)
			}
			pc.PrivateKey = string(dec)
		}
		cfg.SocialProviders[name] = pc
	}
	return nil
}

// GetAllowedRedirectURIs returns the configured allowed redirect URIs for a project.
// Implements social.RedirectURIValidator.
func (s *Service) GetAllowedRedirectURIs(ctx context.Context, projectID string) ([]string, error) {
	p, err := s.Get(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return p.Config.AllowedRedirectURIs, nil
}

func (s *Service) toProject(row *sqlc.Project) (*Project, error) {
	var cfg Config
	if err := json.Unmarshal(row.Config, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal project config: %w", err)
	}

	// Decrypt social provider secrets on read.
	if err := s.decryptSocialSecrets(&cfg, row.ID); err != nil {
		return nil, err
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
