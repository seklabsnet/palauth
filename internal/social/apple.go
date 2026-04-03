package social

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// Apple OIDC endpoints.
var appleEndpoint = oauth2.Endpoint{
	AuthURL:  "https://appleid.apple.com/auth/authorize",
	TokenURL: "https://appleid.apple.com/auth/token",
}

// AppleProvider implements the Provider interface for Apple Sign In.
type AppleProvider struct {
	config   *oauth2.Config
	teamID   string
	keyID    string
	privKey  string // PEM-encoded private key for client_secret JWT
	verifier *jwksVerifier
}

// NewAppleProvider creates a new Apple provider.
func NewAppleProvider(clientID, teamID, keyID, privateKey string) *AppleProvider {
	return &AppleProvider{
		config: &oauth2.Config{
			ClientID: clientID,
			Endpoint: appleEndpoint,
			Scopes:   []string{"openid", "email", "name"},
		},
		teamID:   teamID,
		keyID:    keyID,
		privKey:  privateKey,
		verifier: newJWKSVerifier("https://appleid.apple.com/auth/keys", "https://appleid.apple.com", clientID),
	}
}

func (p *AppleProvider) Name() string { return ProviderApple }

func (p *AppleProvider) AuthURL(state, codeChallenge, redirectURI string) string {
	cfg := *p.config
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("response_mode", "form_post"),
	)
}

// generateClientSecret creates a signed JWT used as Apple's client_secret.
// See: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
func (p *AppleProvider) generateClientSecret() (string, error) {
	block, _ := pem.Decode([]byte(p.privKey))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block for Apple private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse apple private key: %w", err)
	}

	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.keyID))
	if err != nil {
		return "", fmt.Errorf("create apple jwt signer: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:    p.teamID,
		Subject:   p.config.ClientID,
		Audience:  jwt.Audience{"https://appleid.apple.com"},
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign apple client secret: %w", err)
	}

	return token, nil
}

func (p *AppleProvider) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*ProviderUser, error) {
	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}

	cfg := *p.config
	cfg.RedirectURL = redirectURI
	cfg.ClientSecret = clientSecret

	tok, err := cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderExchange, err)
	}

	idToken, ok := tok.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, fmt.Errorf("%w: no id_token in Apple response", ErrProviderExchange)
	}

	return parseAppleIDToken(idToken)
}

func (p *AppleProvider) ValidateCredential(ctx context.Context, credential string) (*ProviderUser, error) {
	// Mobile flow: verify id_token signature against Apple's JWKS, validate iss/aud/exp.
	claims, err := p.verifier.verifyIDToken(ctx, credential)
	if err != nil {
		return nil, err
	}
	return appleUserFromClaims(claims)
}

// parseAppleIDToken parses an Apple ID token JWT (unverified — used only for
// tokens just received from Apple's token endpoint via HTTPS).
func parseAppleIDToken(idToken string) (*ProviderUser, error) {
	claims, err := decodeJWTPayload(idToken)
	if err != nil {
		return nil, fmt.Errorf("decode apple id_token: %w", err)
	}
	return appleUserFromClaims(claims)
}

// appleUserFromClaims extracts ProviderUser from Apple JWT claims.
func appleUserFromClaims(claims map[string]any) (*ProviderUser, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing sub claim", ErrInvalidCredential)
	}

	email, _ := claims["email"].(string)
	emailVerified := false
	switch ev := claims["email_verified"].(type) {
	case bool:
		emailVerified = ev
	case string:
		emailVerified = ev == "true"
	}

	return &ProviderUser{
		ProviderID: sub,
		Email:      email,
		Verified:   emailVerified,
	}, nil
}
