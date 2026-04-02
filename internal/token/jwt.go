package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// Algorithm constants for JWT signing.
const (
	AlgPS256 = "PS256"
	AlgES256 = "ES256"
)

// Default token TTLs.
const (
	DefaultAccessTokenTTL = 30 * time.Minute
	FAPIAccessTokenTTL    = 5 * time.Minute
)

// Errors for JWT operations.
var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrUnsupportedAlg     = errors.New("unsupported algorithm")
	ErrMissingKID         = errors.New("missing kid header")
	ErrMissingAuthTime    = errors.New("missing auth_time claim")
	ErrKeyNotFound        = errors.New("signing key not found")
	ErrCustomTokenExpired = errors.New("custom token expired")
)

// Claims represents the JWT claims for a PalAuth access token.
type Claims struct {
	Subject      string         `json:"sub"`
	Issuer       string         `json:"iss"`
	Audience     []string       `json:"aud,omitempty"`
	ExpiresAt    time.Time      `json:"exp"`
	IssuedAt     time.Time      `json:"iat"`
	JWTID        string         `json:"jti"`
	KID          string         `json:"kid"`
	ACR          string         `json:"acr,omitempty"`
	AMR          []string       `json:"amr,omitempty"`
	AuthTime     int64          `json:"auth_time"`
	ProjectID    string         `json:"project_id"`
	SessionID    string         `json:"session_id,omitempty"`
	CustomClaims map[string]any `json:"custom_claims,omitempty"`
}

// IssueParams contains the parameters for issuing a JWT.
type IssueParams struct {
	UserID       string
	SessionID    string
	ProjectID    string
	Issuer       string
	Audience     []string
	ACR          string
	AMR          []string
	AuthTime     time.Time
	TTL          time.Duration
	CustomClaims map[string]any
}

// signingKey holds a key pair with its ID and algorithm.
type signingKey struct {
	id         string
	alg        jose.SignatureAlgorithm
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
}

// JWTService handles JWT issuance and verification.
type JWTService struct {
	mu      sync.RWMutex
	keys    []signingKey // most recent last
	fapi    bool
	ttl     time.Duration
	logger  *slog.Logger
}

// JWTConfig configures the JWT service.
type JWTConfig struct {
	Algorithm string        // PS256 or ES256
	FAPI      bool          // FAPI mode: 5min access token
	TTL       time.Duration // custom TTL override (0 = use default)
	Logger    *slog.Logger
}

// NewJWTService creates a new JWT service and generates an initial signing key.
func NewJWTService(cfg JWTConfig) (*JWTService, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	alg := cfg.Algorithm
	if alg == "" {
		alg = AlgPS256
	}

	ttl := cfg.TTL
	if ttl == 0 {
		if cfg.FAPI {
			ttl = FAPIAccessTokenTTL
		} else {
			ttl = DefaultAccessTokenTTL
		}
	}

	s := &JWTService{
		fapi:   cfg.FAPI,
		ttl:    ttl,
		logger: cfg.Logger,
	}

	if err := s.GenerateKey(alg); err != nil {
		return nil, fmt.Errorf("generate initial key: %w", err)
	}

	return s, nil
}

// GenerateKey generates a new signing key and adds it to the keyring.
func (s *JWTService) GenerateKey(alg string) error {
	kid := uuid.Must(uuid.NewV7()).String()
	var joseAlg jose.SignatureAlgorithm
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey

	switch alg {
	case AlgPS256:
		joseAlg = jose.PS256
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate RSA key: %w", err)
		}
		privKey = rsaKey
		pubKey = &rsaKey.PublicKey
	case AlgES256:
		joseAlg = jose.ES256
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate EC key: %w", err)
		}
		privKey = ecKey
		pubKey = &ecKey.PublicKey
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, signingKey{
		id:         kid,
		alg:        joseAlg,
		privateKey: privKey,
		publicKey:  pubKey,
	})

	s.logger.Info("generated signing key", "kid", kid, "alg", alg)
	return nil
}

// currentKey returns the most recently added signing key.
func (s *JWTService) currentKey() (signingKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.keys) == 0 {
		return signingKey{}, ErrKeyNotFound
	}
	return s.keys[len(s.keys)-1], nil
}

// Issue creates and signs a JWT access token.
func (s *JWTService) Issue(params *IssueParams) (string, error) {
	key, err := s.currentKey()
	if err != nil {
		return "", err
	}

	now := time.Now()
	ttl := params.TTL
	if ttl == 0 {
		ttl = s.ttl
	}

	jti := uuid.Must(uuid.NewV7()).String()

	authTimeUnix := params.AuthTime.Unix()
	if params.AuthTime.IsZero() {
		authTimeUnix = now.Unix()
	}

	claims := customJWTClaims{
		Claims: jwt.Claims{
			Subject:   params.UserID,
			Issuer:    params.Issuer,
			Audience:  jwt.Audience(params.Audience),
			Expiry:    jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		ACR:          params.ACR,
		AMR:          params.AMR,
		AuthTime:     authTimeUnix,
		ProjectID:    params.ProjectID,
		SessionID:    params.SessionID,
		CustomClaims: params.CustomClaims,
	}

	signerOpts := jose.SignerOptions{}
	signerOpts.WithHeader(jose.HeaderKey("kid"), key.id)
	signerOpts.WithType("JWT")

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: key.alg, Key: key.privateKey},
		&signerOpts,
	)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return raw, nil
}

// allowedVerifyAlgs is the explicit allowlist of algorithms accepted during
// verification. Hardcoded to prevent algorithm confusion attacks — even if a
// key were somehow added with a different algorithm, verification rejects it.
var allowedVerifyAlgs = []jose.SignatureAlgorithm{jose.PS256, jose.ES256}

// Verify parses and validates a JWT access token, returning its claims.
func (s *JWTService) Verify(tokenStr string) (*Claims, error) {
	tok, err := jwt.ParseSigned(tokenStr, allowedVerifyAlgs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	// Extract kid from header.
	if len(tok.Headers) == 0 {
		return nil, ErrMissingKID
	}

	// kid can be in the standard KeyID field or in ExtraHeaders depending on
	// how go-jose serializes/parses it.
	kid := tok.Headers[0].KeyID
	if kid == "" {
		if v, ok := tok.Headers[0].ExtraHeaders[jose.HeaderKey("kid")].(string); ok {
			kid = v
		}
	}
	if kid == "" {
		return nil, ErrMissingKID
	}

	// Find matching key.
	pubKey, err := s.publicKeyByKID(kid)
	if err != nil {
		return nil, err
	}

	var raw customJWTClaims
	if err := tok.Claims(pubKey, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	// Validate standard claims with no leeway (strict expiry check).
	expected := jwt.Expected{
		Time: time.Now(),
	}
	if err := raw.ValidateWithLeeway(expected, 0); err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	// auth_time is mandatory per RFC 9068.
	if raw.AuthTime == 0 {
		return nil, ErrMissingAuthTime
	}

	return &Claims{
		Subject:      raw.Subject,
		Issuer:       raw.Issuer,
		Audience:     []string(raw.Audience),
		ExpiresAt:    raw.Expiry.Time(),
		IssuedAt:     raw.IssuedAt.Time(),
		JWTID:        raw.ID,
		KID:          kid,
		ACR:          raw.ACR,
		AMR:          raw.AMR,
		AuthTime:     raw.AuthTime,
		ProjectID:    raw.ProjectID,
		SessionID:    raw.SessionID,
		CustomClaims: raw.CustomClaims,
	}, nil
}

// PublicKeys returns all public keys in JWK Set format.
func (s *JWTService) PublicKeys() jose.JSONWebKeySet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]jose.JSONWebKey, 0, len(s.keys))
	for _, k := range s.keys {
		keys = append(keys, jose.JSONWebKey{
			Key:       k.publicKey,
			KeyID:     k.id,
			Algorithm: string(k.alg),
			Use:       "sig",
		})
	}
	return jose.JSONWebKeySet{Keys: keys}
}

// publicKeyByKID finds a public key by its key ID.
func (s *JWTService) publicKeyByKID(kid string) (crypto.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		if k.id == kid {
			return k.publicKey, nil
		}
	}
	return nil, fmt.Errorf("%w: kid=%s", ErrKeyNotFound, kid)
}

// customJWTClaims extends the standard JWT claims with PalAuth-specific fields.
type customJWTClaims struct {
	jwt.Claims
	ACR          string         `json:"acr,omitempty"`
	AMR          []string       `json:"amr,omitempty"`
	AuthTime     int64          `json:"auth_time"`
	ProjectID    string         `json:"project_id"`
	SessionID    string         `json:"session_id,omitempty"`
	CustomClaims map[string]any `json:"custom_claims,omitempty"`
}
