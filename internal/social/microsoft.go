package social

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// MicrosoftProvider implements the Provider interface for Microsoft (Azure AD) OIDC.
type MicrosoftProvider struct {
	config   *oauth2.Config
	tenant   string
	verifier *jwksVerifier
}

// NewMicrosoftProvider creates a new Microsoft provider.
func NewMicrosoftProvider(clientID, clientSecret, tenant string) *MicrosoftProvider {
	if tenant == "" {
		tenant = "common"
	}

	// Microsoft's JWKS URL and issuer depend on the tenant.
	jwksURL := "https://login.microsoftonline.com/" + tenant + "/discovery/v2.0/keys"
	// For "common" tenant, issuer validation is skipped (multi-tenant).
	issuer := ""
	if tenant != "common" && tenant != "organizations" && tenant != "consumers" {
		issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"
	}

	return &MicrosoftProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize",
				TokenURL: "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token",
			},
			Scopes: []string{"openid", "email", "profile"},
		},
		tenant:   tenant,
		verifier: newJWKSVerifier(jwksURL, issuer, clientID),
	}
}

func (p *MicrosoftProvider) Name() string { return ProviderMicrosoft }

func (p *MicrosoftProvider) AuthURL(state, codeChallenge, redirectURI string) string {
	cfg := *p.config
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (p *MicrosoftProvider) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*ProviderUser, error) {
	cfg := *p.config
	cfg.RedirectURL = redirectURI
	tok, err := cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}

	idToken, ok := tok.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, fmt.Errorf("%w: no id_token in Microsoft response", ErrProviderExchange)
	}

	return parseMicrosoftIDToken(idToken)
}

func (p *MicrosoftProvider) ValidateCredential(ctx context.Context, credential string) (*ProviderUser, error) {
	// Mobile flow: verify id_token signature against Microsoft's JWKS, validate aud/exp.
	claims, err := p.verifier.verifyIDToken(ctx, credential)
	if err != nil {
		return nil, err
	}
	return microsoftUserFromClaims(claims)
}

// parseMicrosoftIDToken parses a Microsoft ID token JWT (unverified — used only for
// tokens just received from Microsoft's token endpoint via HTTPS).
func parseMicrosoftIDToken(idToken string) (*ProviderUser, error) {
	claims, err := decodeJWTPayload(idToken)
	if err != nil {
		return nil, fmt.Errorf("decode microsoft id_token: %w", err)
	}
	return microsoftUserFromClaims(claims)
}

// microsoftUserFromClaims extracts ProviderUser from Microsoft JWT claims.
func microsoftUserFromClaims(claims map[string]any) (*ProviderUser, error) {
	// Microsoft uses "sub" or "oid" as user ID.
	sub, _ := claims["sub"].(string)
	if sub == "" {
		sub, _ = claims["oid"].(string)
	}
	if sub == "" {
		return nil, fmt.Errorf("%w: missing sub/oid claim", ErrInvalidCredential)
	}

	email, _ := claims["email"].(string)
	if email == "" {
		email, _ = claims["preferred_username"].(string)
	}
	name, _ := claims["name"].(string)

	return &ProviderUser{
		ProviderID: sub,
		Email:      email,
		Name:       name,
		Verified:   true, // Microsoft verifies emails before allowing sign-in
	}, nil
}
