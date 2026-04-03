package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// jwksCache caches a JWKS keyset with TTL.
type jwksCache struct {
	mu        sync.RWMutex
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
	ttl       time.Duration
}

// jwksVerifier fetches and caches provider JWKS keys for id_token verification.
type jwksVerifier struct {
	jwksURL  string
	issuer   string
	clientID string
	cache    jwksCache
}

// newJWKSVerifier creates a verifier that fetches keys from the given JWKS URL.
func newJWKSVerifier(jwksURL, issuer, clientID string) *jwksVerifier {
	return &jwksVerifier{
		jwksURL:  jwksURL,
		issuer:   issuer,
		clientID: clientID,
		cache: jwksCache{
			ttl: 1 * time.Hour,
		},
	}
}

// supportedAlgorithms lists all signature algorithms we accept from OIDC providers.
var supportedAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// verifyIDToken verifies the JWT signature against the provider's JWKS,
// validates iss, aud, exp claims, and returns the parsed claims.
func (v *jwksVerifier) verifyIDToken(ctx context.Context, rawToken string) (map[string]any, error) {
	parsedJWT, err := jwt.ParseSigned(rawToken, supportedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: parse jwt: %w", ErrInvalidCredential, err)
	}

	keys, err := v.getKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}

	matchingKeys := v.findMatchingKeys(parsedJWT, keys)
	if len(matchingKeys) == 0 {
		// Key may have rotated — refresh cache and retry.
		keys, err = v.fetchKeys(ctx)
		if err != nil {
			return nil, fmt.Errorf("refresh jwks: %w", err)
		}
		matchingKeys = v.findMatchingKeys(parsedJWT, keys)
		if len(matchingKeys) == 0 {
			return nil, fmt.Errorf("%w: no matching key found in JWKS", ErrInvalidCredential)
		}
	}

	// Verify signature and extract claims.
	var rawClaims map[string]any
	if err := parsedJWT.Claims(matchingKeys[0].Key, &rawClaims); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %w", ErrInvalidCredential, err)
	}

	if err := v.validateClaims(rawClaims); err != nil {
		return nil, err
	}

	return rawClaims, nil
}

// findMatchingKeys returns JWKS keys matching the JWT's kid header.
func (v *jwksVerifier) findMatchingKeys(parsedJWT *jwt.JSONWebToken, keys *jose.JSONWebKeySet) []jose.JSONWebKey {
	for _, h := range parsedJWT.Headers {
		if h.KeyID != "" {
			return keys.Key(h.KeyID)
		}
	}
	return nil
}

// validateClaims checks iss, aud, and exp.
func (v *jwksVerifier) validateClaims(claims map[string]any) error {
	// Validate issuer.
	iss, _ := claims["iss"].(string)
	if v.issuer != "" && iss != v.issuer {
		return fmt.Errorf("%w: invalid issuer: got %q, want %q", ErrInvalidCredential, iss, v.issuer)
	}

	// Validate audience — must match our client_id.
	switch aud := claims["aud"].(type) {
	case string:
		if aud != v.clientID {
			return fmt.Errorf("%w: invalid audience", ErrInvalidCredential)
		}
	case []any:
		found := false
		for _, a := range aud {
			if s, ok := a.(string); ok && s == v.clientID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: invalid audience", ErrInvalidCredential)
		}
	default:
		return fmt.Errorf("%w: missing audience claim", ErrInvalidCredential)
	}

	// Validate expiry.
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("%w: missing exp claim", ErrInvalidCredential)
	}
	if time.Now().Unix() > int64(exp) {
		return fmt.Errorf("%w: token expired", ErrInvalidCredential)
	}

	return nil
}

// getKeys returns cached keys or fetches them if expired.
func (v *jwksVerifier) getKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	v.cache.mu.RLock()
	if v.cache.keys != nil && time.Since(v.cache.fetchedAt) < v.cache.ttl {
		keys := v.cache.keys
		v.cache.mu.RUnlock()
		return keys, nil
	}
	v.cache.mu.RUnlock()
	return v.fetchKeys(ctx)
}

// fetchKeys fetches JWKS from the provider and updates the cache.
func (v *jwksVerifier) fetchKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	v.cache.mu.Lock()
	defer v.cache.mu.Unlock()

	// Double-check after acquiring write lock.
	if v.cache.keys != nil && time.Since(v.cache.fetchedAt) < v.cache.ttl {
		return v.cache.keys, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create jwks request: %w", err)
	}

	resp, err := providerHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks from %s: %w", v.jwksURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read jwks response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}

	v.cache.keys = &keys
	v.cache.fetchedAt = time.Now()
	return &keys, nil
}
