package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleProvider implements the Provider interface for Google OAuth2/OIDC.
type GoogleProvider struct {
	config *oauth2.Config
}

// NewGoogleProvider creates a new Google provider.
func NewGoogleProvider(clientID, clientSecret string) *GoogleProvider {
	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email", "profile"},
		},
	}
}

func (p *GoogleProvider) Name() string { return ProviderGoogle }

func (p *GoogleProvider) AuthURL(state, codeChallenge, redirectURI string) string {
	cfg := *p.config
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (p *GoogleProvider) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*ProviderUser, error) {
	cfg := *p.config
	cfg.RedirectURL = redirectURI
	tok, err := cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}

	// Google returns id_token in the token response.
	idToken, ok := tok.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, fmt.Errorf("%w: no id_token in response", ErrProviderExchange)
	}

	return parseGoogleIDToken(idToken)
}

func (p *GoogleProvider) ValidateCredential(ctx context.Context, credential string) (*ProviderUser, error) {
	// Validate Google ID token via tokeninfo endpoint.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://oauth2.googleapis.com/tokeninfo?id_token="+credential, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredential, err)
	}
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
		return nil, fmt.Errorf("read google tokeninfo: %w", err)
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Aud           string `json:"aud"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("parse google tokeninfo: %w", err)
	}

	if claims.Sub == "" {
		return nil, ErrInvalidCredential
	}

	// Verify the token was issued for this application's client_id.
	if claims.Aud != p.config.ClientID {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidCredential)
	}

	return &ProviderUser{
		ProviderID: claims.Sub,
		Email:      claims.Email,
		Name:       claims.Name,
		AvatarURL:  claims.Picture,
		Verified:   claims.EmailVerified == "true",
	}, nil
}

// parseGoogleIDToken parses a Google ID token JWT (unverified — the token was
// just exchanged via HTTPS with Google's token endpoint, so it's trusted).
func parseGoogleIDToken(idToken string) (*ProviderUser, error) {
	// Decode the JWT payload without verification (token came from trusted exchange).
	claims, err := decodeJWTPayload(idToken)
	if err != nil {
		return nil, fmt.Errorf("decode google id_token: %w", err)
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing sub claim", ErrProviderExchange)
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)
	emailVerified, _ := claims["email_verified"].(bool)

	return &ProviderUser{
		ProviderID: sub,
		Email:      email,
		Name:       name,
		AvatarURL:  picture,
		Verified:   emailVerified,
	}, nil
}
