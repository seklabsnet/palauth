package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
	oauth2github "golang.org/x/oauth2/github"
)

// GitHubProvider implements the Provider interface for GitHub OAuth2.
type GitHubProvider struct {
	config *oauth2.Config
}

// NewGitHubProvider creates a new GitHub provider.
func NewGitHubProvider(clientID, clientSecret string) *GitHubProvider {
	return &GitHubProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     oauth2github.Endpoint,
			Scopes:       []string{"read:user", "user:email"},
		},
	}
}

func (p *GitHubProvider) Name() string { return ProviderGitHub }

func (p *GitHubProvider) AuthURL(state, codeChallenge, redirectURI string) string {
	cfg := *p.config
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (p *GitHubProvider) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*ProviderUser, error) {
	cfg := *p.config
	cfg.RedirectURL = redirectURI
	tok, err := cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}

	return fetchGitHubUser(ctx, tok.AccessToken)
}

func (p *GitHubProvider) ValidateCredential(ctx context.Context, credential string) (*ProviderUser, error) {
	return fetchGitHubUser(ctx, credential)
}

// fetchGitHubUser calls GitHub's /user API to get the user profile.
func fetchGitHubUser(ctx context.Context, accessToken string) (*ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create github request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := providerHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredential, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidCredential
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read github response: %w", err)
	}

	var ghUser struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(body, &ghUser); err != nil {
		return nil, fmt.Errorf("parse github user: %w", err)
	}

	if ghUser.ID == 0 {
		return nil, ErrInvalidCredential
	}

	// Always call /user/emails to get verified primary email — don't trust /user email field.
	email, verified := fetchGitHubPrimaryEmail(ctx, accessToken)

	name := ghUser.Name
	if name == "" {
		name = ghUser.Login
	}

	return &ProviderUser{
		ProviderID: strconv.Itoa(ghUser.ID),
		Email:      email,
		Name:       name,
		AvatarURL:  ghUser.AvatarURL,
		Verified:   verified,
	}, nil
}

// fetchGitHubPrimaryEmail fetches the primary verified email from GitHub's emails API.
func fetchGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", http.NoBody)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := providerHTTPClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", false
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true
		}
	}

	return "", false
}
