package admin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/project"
)

var (
	ErrAdminAlreadyExists = errors.New("admin user already exists")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired admin token")
	ErrEmailRequired      = errors.New("email is required")
	ErrPasswordRequired   = errors.New("password is required")
)

const adminTokenExpiry = 24 * time.Hour

// AdminUser is the domain model for an admin user.
type AdminUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

// AdminClaims holds the parsed admin JWT claims.
type AdminClaims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// SetupResult is returned from the initial admin setup.
type SetupResult struct {
	Admin   *AdminUser       `json:"admin"`
	Project *project.Project `json:"project"`
	APIKeys *apikey.APIKeys  `json:"api_keys"`
}

// Service manages admin authentication.
type Service struct {
	db         *pgxpool.Pool
	pepper     string
	signingKey []byte
	logger     *slog.Logger
}

// NewService creates a new admin service.
func NewService(db *pgxpool.Pool, pepper string, signingKey []byte, logger *slog.Logger) *Service {
	return &Service{
		db:         db,
		pepper:     pepper,
		signingKey: signingKey,
		logger:     logger,
	}
}

// Setup creates the first admin user, a default project, and generates API keys.
// The entire operation is wrapped in a transaction for atomicity.
// Returns an error if any admin already exists.
func (s *Service) Setup(ctx context.Context, email, password string) (*SetupResult, error) {
	if email == "" {
		return nil, ErrEmailRequired
	}
	if password == "" {
		return nil, ErrPasswordRequired
	}

	// Hash the password before starting the transaction to avoid
	// holding the transaction open during the expensive Argon2id computation.
	hash, err := crypto.Hash(password, s.pepper)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	// Acquire advisory lock to serialize concurrent setup requests.
	// This prevents a race where two requests both see count=0 before either commits.
	// The lock is automatically released when the transaction ends.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(1)"); err != nil {
		return nil, fmt.Errorf("advisory lock: %w", err)
	}

	q := sqlc.New(tx)

	// Check if any admin exists.
	count, err := q.CountAdmins(ctx)
	if err != nil {
		return nil, fmt.Errorf("count admins: %w", err)
	}
	if count > 0 {
		return nil, ErrAdminAlreadyExists
	}

	// Create admin user.
	adminRow, err := q.CreateAdminUser(ctx, sqlc.CreateAdminUserParams{
		ID:           id.New("adm_"),
		Email:        email,
		PasswordHash: hash,
		Role:         "owner",
	})
	if err != nil {
		return nil, fmt.Errorf("create admin: %w", err)
	}

	adminUser := toAdminUser(adminRow)

	// Create default project.
	cfg := project.DefaultConfig()
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal project config: %w", err)
	}

	projectRow, err := q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID:     id.New("prj_"),
		Name:   "Default Project",
		Config: cfgJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("create default project: %w", err)
	}

	prj := &project.Project{
		ID:   projectRow.ID,
		Name: projectRow.Name,
	}
	if err := json.Unmarshal(projectRow.Config, &prj.Config); err != nil {
		return nil, fmt.Errorf("unmarshal project config: %w", err)
	}
	if projectRow.CreatedAt.Valid {
		prj.CreatedAt = projectRow.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
	}
	if projectRow.UpdatedAt.Valid {
		prj.UpdatedAt = projectRow.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
	}

	// Generate all 4 API keys within the transaction.
	keys := &apikey.APIKeys{}
	for _, kt := range apikey.AllKeyTypes {
		prefix := apikey.KeyPrefix(kt)
		randomPart, err := crypto.GenerateToken(32)
		if err != nil {
			return nil, fmt.Errorf("generate random for %s: %w", kt, err)
		}

		plainKey := prefix + randomPart
		keyHash := apikey.HashKey(plainKey)

		_, err = q.CreateAPIKey(ctx, sqlc.CreateAPIKeyParams{
			ID:        id.New("key_"),
			ProjectID: prj.ID,
			KeyHash:   keyHash,
			KeyPrefix: prefix,
			KeyType:   kt,
		})
		if err != nil {
			return nil, fmt.Errorf("create api key %s: %w", kt, err)
		}

		switch kt {
		case apikey.KeyTypePublicTest:
			keys.PublicTest = plainKey
		case apikey.KeyTypeSecretTest:
			keys.SecretTest = plainKey
		case apikey.KeyTypePublicLive:
			keys.PublicLive = plainKey
		case apikey.KeyTypeSecretLive:
			keys.SecretLive = plainKey
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return &SetupResult{
		Admin:   adminUser,
		Project: prj,
		APIKeys: keys,
	}, nil
}

// Login authenticates an admin user and returns a JWT token.
func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	if email == "" {
		return "", ErrEmailRequired
	}
	if password == "" {
		return "", ErrPasswordRequired
	}

	q := sqlc.New(s.db)
	adminRow, err := q.GetAdminByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Perform a dummy hash to prevent timing attacks.
			_, _ = crypto.Hash("dummy-password-for-timing", s.pepper)
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("get admin: %w", err)
	}

	match, err := crypto.Verify(password, adminRow.PasswordHash, s.pepper)
	if err != nil {
		return "", fmt.Errorf("verify password: %w", err)
	}
	if !match {
		return "", ErrInvalidCredentials
	}

	// Issue admin JWT.
	now := time.Now()
	claims := AdminClaims{
		Sub:  adminRow.ID,
		Role: adminRow.Role,
		Iat:  now.Unix(),
		Exp:  now.Add(adminTokenExpiry).Unix(),
	}

	token, err := s.signToken(claims)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return token, nil
}

// ValidateToken parses and validates an admin JWT.
func (s *Service) ValidateToken(token string) (*AdminClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}

	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	if subtle.ConstantTimeCompare(signature, expectedSig) != 1 {
		return nil, ErrInvalidToken
	}

	// Decode payload.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims AdminClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	// Check expiry.
	if time.Now().Unix() > claims.Exp {
		return nil, ErrInvalidToken
	}

	return &claims, nil
}

// signToken creates an HMAC-SHA256 signed JWT.
func (s *Service) signToken(claims AdminClaims) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature, nil
}

func toAdminUser(row sqlc.AdminUser) *AdminUser {
	a := &AdminUser{
		ID:    row.ID,
		Email: row.Email,
		Role:  row.Role,
	}
	if row.CreatedAt.Valid {
		a.CreatedAt = row.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
	}
	return a
}
