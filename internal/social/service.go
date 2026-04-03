package social

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/session"
	"github.com/palauth/palauth/internal/token"
)

// providerHTTPClient is the shared HTTP client for provider API calls with a timeout.
var providerHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

// MFAChecker checks if a user has MFA enrolled and issues MFA tokens.
type MFAChecker interface {
	HasMFA(ctx context.Context, projectID, userID string) (bool, []string, error)
	IssueMFATokenForLogin(ctx context.Context, userID, projectID, ip, userAgent string) (string, error)
}

// RedirectURIValidator validates redirect URIs against a project's allowlist.
type RedirectURIValidator interface {
	GetAllowedRedirectURIs(ctx context.Context, projectID string) ([]string, error)
}

// CallbackResult contains the result of a social login callback.
type CallbackResult struct {
	AccessToken  string   `json:"access_token,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	TokenType    string   `json:"token_type,omitempty"`
	ExpiresIn    int      `json:"expires_in,omitempty"`
	User         UserInfo `json:"user"`
	MFARequired  bool     `json:"mfa_required,omitempty"`
	MFAToken     string   `json:"mfa_token,omitempty"`
	MFAFactors   []string `json:"mfa_factors,omitempty"`
	IsNewUser    bool     `json:"is_new_user"`
}

// UserInfo contains user information in callback results.
type UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     string `json:"created_at"`
}

// IdentityInfo is the public representation of a linked social identity.
type IdentityInfo struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
	CreatedAt      string `json:"created_at"`
}

// Service handles social login operations.
type Service struct {
	db                   *pgxpool.Pool
	rdb                  *redis.Client
	providers            map[string]Provider
	jwtSvc               *token.JWTService
	refreshSvc           *token.RefreshService
	auditSvc             *audit.Service
	mfaChecker           MFAChecker
	redirectURIValidator RedirectURIValidator
	kek                  []byte
	emailHashKey         []byte
	pepper               string
	logger               *slog.Logger
}

// NewService creates a new social login service.
func NewService(
	db *pgxpool.Pool,
	rdb *redis.Client,
	jwtSvc *token.JWTService,
	refreshSvc *token.RefreshService,
	auditSvc *audit.Service,
	pepper string,
	kek []byte,
	logger *slog.Logger,
) *Service {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte("email-hash-key"))
	emailHashKey := mac.Sum(nil)

	return &Service{
		db:           db,
		rdb:          rdb,
		providers:    make(map[string]Provider),
		jwtSvc:       jwtSvc,
		refreshSvc:   refreshSvc,
		auditSvc:     auditSvc,
		kek:          kek,
		emailHashKey: emailHashKey,
		pepper:       pepper,
		logger:       logger,
	}
}

// SetMFAChecker sets the MFA checker (to break circular dependency).
func (s *Service) SetMFAChecker(checker MFAChecker) {
	s.mfaChecker = checker
}

// SetRedirectURIValidator sets the redirect URI validator.
func (s *Service) SetRedirectURIValidator(v RedirectURIValidator) {
	s.redirectURIValidator = v
}

// RegisterProvider adds a provider to the service.
func (s *Service) RegisterProvider(p Provider) {
	s.providers[p.Name()] = p
}

// GetProvider returns a registered provider by name.
func (s *Service) GetProvider(name string) (Provider, bool) {
	p, ok := s.providers[name]
	return p, ok
}

// Authorize generates an OAuth authorization URL with PKCE and state.
func (s *Service) Authorize(ctx context.Context, projectID, providerName, redirectURI string) (string, error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return "", ErrUnsupportedProvider
	}

	// Validate redirect_uri against project allowlist (RFC 6749 Section 3.1.2.2).
	if err := s.validateRedirectURI(ctx, projectID, redirectURI); err != nil {
		return "", err
	}

	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return "", fmt.Errorf("generate PKCE: %w", err)
	}

	stateToken, err := GenerateState(ctx, s.rdb, &OAuthState{
		ProjectID:    projectID,
		Provider:     providerName,
		CodeVerifier: verifier,
		RedirectURI:  redirectURI,
	})
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	authURL := provider.AuthURL(stateToken, challenge, redirectURI)
	return authURL, nil
}

// Callback handles the OAuth callback: verifies state, exchanges code, links/creates user, issues tokens.
func (s *Service) Callback(ctx context.Context, projectID, providerName, code, stateToken, ip, userAgent string) (*CallbackResult, error) {
	state, err := ConsumeState(ctx, s.rdb, stateToken)
	if err != nil {
		return nil, err
	}

	if state.ProjectID != projectID || state.Provider != providerName {
		return nil, ErrInvalidState
	}

	provider, ok := s.providers[providerName]
	if !ok {
		return nil, ErrUnsupportedProvider
	}

	pu, err := provider.Exchange(ctx, code, state.CodeVerifier, state.RedirectURI)
	if err != nil {
		return nil, err
	}

	return s.completeLogin(ctx, projectID, providerName, pu, ip, userAgent)
}

// ExchangeCredential handles mobile native flow: validates a provider credential and issues tokens.
func (s *Service) ExchangeCredential(ctx context.Context, projectID, providerName, credential, ip, userAgent string) (*CallbackResult, error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return nil, ErrUnsupportedProvider
	}

	pu, err := provider.ValidateCredential(ctx, credential)
	if err != nil {
		return nil, err
	}

	return s.completeLogin(ctx, projectID, providerName, pu, ip, userAgent)
}

// ListIdentities returns all social identities for a user within a project.
func (s *Service) ListIdentities(ctx context.Context, projectID, userID string) ([]IdentityInfo, error) {
	q := sqlc.New(s.db)
	identities, err := q.ListIdentitiesByUser(ctx, sqlc.ListIdentitiesByUserParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}

	result := make([]IdentityInfo, 0, len(identities))
	for i := range identities {
		result = append(result, IdentityInfo{
			ID:             identities[i].ID,
			Provider:       identities[i].Provider,
			ProviderUserID: identities[i].ProviderUserID,
			CreatedAt:      identities[i].CreatedAt.Time.UTC().Format(time.RFC3339),
		})
	}

	return result, nil
}

// LinkIdentity links a social provider to an existing authenticated user.
func (s *Service) LinkIdentity(ctx context.Context, projectID, userID, providerName, credential string) error {
	provider, ok := s.providers[providerName]
	if !ok {
		return ErrUnsupportedProvider
	}

	pu, err := provider.ValidateCredential(ctx, credential)
	if err != nil {
		return err
	}

	q := sqlc.New(s.db)

	existing, err := q.GetIdentityByProviderUser(ctx, sqlc.GetIdentityByProviderUserParams{
		ProjectID:      projectID,
		Provider:       providerName,
		ProviderUserID: pu.ProviderID,
	})
	if err == nil {
		if existing.UserID == userID {
			return nil // already linked to this user
		}
		return ErrIdentityAlreadyLinked
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check existing identity: %w", err)
	}

	if err := s.createIdentityRecord(ctx, q, projectID, userID, providerName, pu); err != nil {
		return err
	}

	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventSocialLink,
		Actor:      audit.ActorInfo{UserID: userID},
		Target:     &audit.TargetInfo{Type: "identity", ID: pu.ProviderID},
		Result:     "success",
		AuthMethod: providerName,
		ProjectID:  projectID,
		Metadata:   map[string]any{"provider": providerName},
	})

	return nil
}

// UnlinkIdentity removes a social identity. Ensures at least one auth method remains.
func (s *Service) UnlinkIdentity(ctx context.Context, projectID, userID, identityID string) error {
	q := sqlc.New(s.db)

	identityCount, err := q.CountIdentitiesByUser(ctx, sqlc.CountIdentitiesByUserParams{
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("count identities: %w", err)
	}

	user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:        userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	hasPassword := user.PasswordHash != nil && *user.PasswordHash != ""
	if identityCount <= 1 && !hasPassword {
		return ErrCannotUnlinkLast
	}

	err = q.DeleteIdentity(ctx, sqlc.DeleteIdentityParams{
		ID:        identityID,
		UserID:    userID,
		ProjectID: projectID,
	})
	if err != nil {
		return fmt.Errorf("delete identity: %w", err)
	}

	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventSocialUnlink,
		Actor:      audit.ActorInfo{UserID: userID},
		Target:     &audit.TargetInfo{Type: "identity", ID: identityID},
		Result:     "success",
		ProjectID:  projectID,
		Metadata:   map[string]any{"identity_id": identityID},
	})

	return nil
}

// completeLogin handles the common login flow after obtaining provider user info.
func (s *Service) completeLogin(ctx context.Context, projectID, providerName string, pu *ProviderUser, ip, userAgent string) (*CallbackResult, error) {
	q := sqlc.New(s.db)

	user, isNew, err := s.linkOrCreateUser(ctx, q, projectID, providerName, pu)
	if err != nil {
		return nil, err
	}

	if user.Banned {
		s.auditLog(ctx, &audit.Event{
			EventType:  audit.EventSocialLogin,
			Actor:      audit.ActorInfo{UserID: user.ID},
			Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
			Result:     "failure",
			AuthMethod: providerName,
			ProjectID:  projectID,
			Metadata:   map[string]any{"reason": "user_banned"},
		})
		return nil, errors.New("user is banned")
	}

	// Check MFA: social login does NOT bypass MFA.
	if mfaResult, err := s.checkMFA(ctx, projectID, user, pu, ip, userAgent, isNew); mfaResult != nil || err != nil {
		return mfaResult, err
	}

	// Update last_login_at.
	if err := q.UpdateUserLastLogin(ctx, sqlc.UpdateUserLastLoginParams{
		ID:        user.ID,
		ProjectID: projectID,
	}); err != nil {
		return nil, fmt.Errorf("update last login: %w", err)
	}

	result, err := s.createSessionAndTokens(ctx, q, projectID, providerName, user, ip, userAgent)
	if err != nil {
		return nil, err
	}
	result.User = s.buildUserInfo(user, pu.Email)
	result.IsNewUser = isNew

	s.auditLog(ctx, &audit.Event{
		EventType:  audit.EventSocialLogin,
		Actor:      audit.ActorInfo{UserID: user.ID, Email: pu.Email},
		Target:     &audit.TargetInfo{Type: "user", ID: user.ID},
		Result:     "success",
		AuthMethod: providerName,
		ProjectID:  projectID,
		Metadata:   map[string]any{"provider": providerName, "is_new_user": isNew},
	})

	return result, nil
}

// checkMFA checks if the user has MFA enrolled and returns an MFA challenge if needed.
// Returns (nil, nil) if MFA is not required.
func (s *Service) checkMFA(ctx context.Context, projectID string, user *sqlc.User, pu *ProviderUser, ip, userAgent string, isNew bool) (*CallbackResult, error) {
	if s.mfaChecker == nil || !user.HasMfa {
		return nil, nil
	}

	hasMFA, factors, err := s.mfaChecker.HasMFA(ctx, projectID, user.ID)
	if err != nil {
		return nil, fmt.Errorf("check mfa: %w", err)
	}
	if !hasMFA || len(factors) == 0 {
		return nil, nil
	}

	mfaToken, err := s.mfaChecker.IssueMFATokenForLogin(ctx, user.ID, projectID, ip, userAgent)
	if err != nil {
		return nil, fmt.Errorf("issue mfa token: %w", err)
	}

	return &CallbackResult{
		User:        s.buildUserInfo(user, pu.Email),
		MFARequired: true,
		MFAToken:    mfaToken,
		MFAFactors:  factors,
		IsNewUser:   isNew,
	}, nil
}

// createSessionAndTokens creates a session, access token, and refresh token.
func (s *Service) createSessionAndTokens(ctx context.Context, q *sqlc.Queries, projectID, providerName string, user *sqlc.User, ip, userAgent string) (*CallbackResult, error) {
	now := time.Now()
	sessionID := id.New("sess_")
	idleTimeout, absTimeout := session.AALTimeouts("aal1")

	var idleTimeoutAt pgtype.Timestamptz
	if idleTimeout > 0 {
		idleTimeoutAt = pgtype.Timestamptz{Time: now.Add(idleTimeout), Valid: true}
	}

	amrJSON, _ := json.Marshal([]string{providerName})
	_, err := q.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:            sessionID,
		ProjectID:     projectID,
		UserID:        user.ID,
		Ip:            &ip,
		UserAgent:     &userAgent,
		Acr:           "aal1",
		Amr:           amrJSON,
		IdleTimeoutAt: idleTimeoutAt,
		AbsTimeoutAt:  pgtype.Timestamptz{Time: now.Add(absTimeout), Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	accessToken, err := s.jwtSvc.Issue(&token.IssueParams{
		UserID:    user.ID,
		SessionID: sessionID,
		ProjectID: projectID,
		AuthTime:  now,
		ACR:       "aal1",
		AMR:       []string{providerName},
	})
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	refreshToken, err := s.refreshSvc.Issue(ctx, user.ID, sessionID, projectID)
	if err != nil {
		return nil, fmt.Errorf("issue refresh token: %w", err)
	}

	return &CallbackResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    1800,
	}, nil
}

// linkOrCreateUser handles the account linking logic.
func (s *Service) linkOrCreateUser(ctx context.Context, q *sqlc.Queries, projectID, providerName string, pu *ProviderUser) (*sqlc.User, bool, error) {
	// 1. Check if identity already exists.
	existing, err := q.GetIdentityByProviderUser(ctx, sqlc.GetIdentityByProviderUserParams{
		ProjectID:      projectID,
		Provider:       providerName,
		ProviderUserID: pu.ProviderID,
	})
	if err == nil {
		user, err := q.GetUserByID(ctx, sqlc.GetUserByIDParams{
			ID:        existing.UserID,
			ProjectID: projectID,
		})
		if err != nil {
			return nil, false, fmt.Errorf("get user by identity: %w", err)
		}
		return &user, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("lookup identity: %w", err)
	}

	// 2. If provider email is verified, try to link to existing user by email hash.
	if pu.Verified && pu.Email != "" {
		user, err := s.linkToExistingUserByEmail(ctx, q, projectID, providerName, pu)
		if err != nil {
			return nil, false, err
		}
		if user != nil {
			return user, false, nil
		}
	}

	// 3. Create new user + identity.
	return s.createNewUser(ctx, q, projectID, providerName, pu)
}

// linkToExistingUserByEmail tries to link a social identity to an existing user with the same verified email.
// Returns nil user if no matching user was found.
func (s *Service) linkToExistingUserByEmail(ctx context.Context, q *sqlc.Queries, projectID, providerName string, pu *ProviderUser) (*sqlc.User, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(pu.Email))
	emailHash := crypto.DeterministicHash(normalizedEmail, s.emailHashKey)
	emailHashBytes, err := hex.DecodeString(emailHash)
	if err != nil {
		return nil, fmt.Errorf("decode email hash: %w", err)
	}

	existingUser, err := q.GetUserByEmailHash(ctx, sqlc.GetUserByEmailHashParams{
		ProjectID: projectID,
		EmailHash: emailHashBytes,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // no matching user
	}
	if err != nil {
		return nil, fmt.Errorf("lookup user by email: %w", err)
	}

	if err := s.createIdentityRecord(ctx, q, projectID, existingUser.ID, providerName, pu); err != nil {
		return nil, fmt.Errorf("create identity for existing user: %w", err)
	}
	return &existingUser, nil
}

// createNewUser creates a new user and associated identity for social login.
func (s *Service) createNewUser(ctx context.Context, q *sqlc.Queries, projectID, providerName string, pu *ProviderUser) (*sqlc.User, bool, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(pu.Email))
	emailHash := crypto.DeterministicHash(normalizedEmail, s.emailHashKey)
	emailHashBytes, err := hex.DecodeString(emailHash)
	if err != nil {
		return nil, false, fmt.Errorf("decode email hash: %w", err)
	}

	projectDEK, err := s.getOrCreateProjectDEK(ctx, q, projectID)
	if err != nil {
		return nil, false, fmt.Errorf("get project DEK: %w", err)
	}

	emailAAD := []byte("email:" + projectID)
	encryptedEmail, err := crypto.Encrypt([]byte(normalizedEmail), projectDEK, emailAAD)
	if err != nil {
		return nil, false, fmt.Errorf("encrypt email: %w", err)
	}

	userID := id.New("usr_")
	newUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{
		ID:             userID,
		ProjectID:      projectID,
		EmailEncrypted: encryptedEmail,
		EmailHash:      emailHashBytes,
		PasswordHash:   nil,
		Metadata:       []byte("{}"),
	})
	if err != nil {
		return nil, false, fmt.Errorf("create user: %w", err)
	}

	if pu.Verified {
		if err := q.UpdateUserEmailVerified(ctx, userID); err != nil {
			return nil, false, fmt.Errorf("verify email: %w", err)
		}
		newUser.EmailVerified = true
	}

	if err := s.createIdentityRecord(ctx, q, projectID, userID, providerName, pu); err != nil {
		return nil, false, err
	}

	return &newUser, true, nil
}

// createIdentityRecord creates an identity record in the database.
func (s *Service) createIdentityRecord(ctx context.Context, q *sqlc.Queries, projectID, userID, providerName string, pu *ProviderUser) error {
	providerData, _ := json.Marshal(map[string]string{
		"name":       pu.Name,
		"avatar_url": pu.AvatarURL,
	})
	_, err := q.CreateIdentity(ctx, sqlc.CreateIdentityParams{
		ID:             id.New("ident_"),
		ProjectID:      projectID,
		UserID:         userID,
		Provider:       providerName,
		ProviderUserID: pu.ProviderID,
		ProviderData:   providerData,
	})
	if err != nil {
		return fmt.Errorf("create identity: %w", err)
	}
	return nil
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

// buildUserInfo constructs a UserInfo from a sqlc.User and decrypted email.
func (s *Service) buildUserInfo(user *sqlc.User, email string) UserInfo {
	createdAt := ""
	if user.CreatedAt.Valid {
		createdAt = user.CreatedAt.Time.UTC().Format(time.RFC3339)
	}
	return UserInfo{
		ID:            user.ID,
		Email:         email,
		EmailVerified: user.EmailVerified,
		CreatedAt:     createdAt,
	}
}

// validateRedirectURI checks that the redirect_uri is in the project's allowlist.
func (s *Service) validateRedirectURI(ctx context.Context, projectID, redirectURI string) error {
	if s.redirectURIValidator == nil {
		return nil // no validator configured — skip (e.g., in tests)
	}

	allowed, err := s.redirectURIValidator.GetAllowedRedirectURIs(ctx, projectID)
	if err != nil {
		return fmt.Errorf("get allowed redirect URIs: %w", err)
	}

	// Exact match required (FAPI 2.0).
	for _, uri := range allowed {
		if uri == redirectURI {
			return nil
		}
	}

	return ErrInvalidRedirectURI
}

// auditLog safely logs an audit event, handling nil auditSvc.
func (s *Service) auditLog(ctx context.Context, event *audit.Event) {
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, event) //nolint:errcheck // best-effort audit
	}
}
