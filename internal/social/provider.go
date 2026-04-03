package social

import (
	"context"
	"errors"
)

// Supported provider names.
const (
	ProviderGoogle    = "google"
	ProviderApple     = "apple"
	ProviderGitHub    = "github"
	ProviderMicrosoft = "microsoft"
)

// ValidProviders lists all supported provider names.
var ValidProviders = map[string]bool{
	ProviderGoogle:    true,
	ProviderApple:     true,
	ProviderGitHub:    true,
	ProviderMicrosoft: true,
}

var (
	ErrUnsupportedProvider  = errors.New("unsupported social provider")
	ErrProviderNotEnabled   = errors.New("social provider is not enabled for this project")
	ErrInvalidState         = errors.New("invalid or expired OAuth state")
	ErrInvalidCredential    = errors.New("invalid provider credential")
	ErrProviderExchange     = errors.New("failed to exchange authorization code")
	ErrIdentityNotFound     = errors.New("social identity not found")
	ErrCannotUnlinkLast     = errors.New("cannot unlink last authentication method")
	ErrIdentityAlreadyLinked = errors.New("this social identity is already linked to another account")
	ErrEmailAlreadyLinked   = errors.New("email already linked to another user with different identity")
)

// Provider defines the interface for social login providers.
type Provider interface {
	// Name returns the provider name (e.g., "google", "github").
	Name() string
	// AuthURL returns the authorization URL with PKCE challenge and state.
	AuthURL(state, codeChallenge, redirectURI string) string
	// Exchange trades an authorization code for user profile information.
	Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*ProviderUser, error)
	// ValidateCredential validates a provider-specific credential (e.g., id_token)
	// and returns the associated user profile. Used for mobile native flows.
	ValidateCredential(ctx context.Context, credential string) (*ProviderUser, error)
}

// ProviderUser represents the user profile returned by a social provider.
type ProviderUser struct {
	ProviderID string // unique ID from the provider
	Email      string
	Name       string
	AvatarURL  string
	Verified   bool // email verified by the provider
}

// ProviderConfig holds the configuration for a social provider.
type ProviderConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Enabled      bool   `json:"enabled"`
	// Apple-specific
	TeamID     string `json:"team_id,omitempty"`
	KeyID      string `json:"key_id,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	// Microsoft-specific
	Tenant string `json:"tenant,omitempty"`
}

// ErrInvalidRedirectURI is returned when the redirect_uri is not in the project's allowlist.
var ErrInvalidRedirectURI = errors.New("redirect_uri is not allowed")
