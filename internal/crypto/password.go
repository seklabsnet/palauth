package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alexedwards/argon2id"
)

var (
	ErrPasswordTooShort = errors.New("password must be at least 15 characters")
	ErrPasswordTooLong  = errors.New("password must be at most 64 characters")
	ErrPasswordBreached = errors.New("password has been found in a data breach")
	ErrPasswordReused   = errors.New("password was recently used")
	ErrEmptyPepper      = errors.New("pepper must not be empty")
)

// Argon2id parameters per spec: memory=64MB, time=3, parallelism=1, keyLength=32, saltLength=16.
var argon2Params = &argon2id.Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// ValidatePassword checks length constraints. No composition rules (NIST SHALL NOT).
// No truncation allowed.
func ValidatePassword(password string) error {
	length := utf8.RuneCountInString(password)
	if length < 15 {
		return ErrPasswordTooShort
	}
	if length > 64 {
		return ErrPasswordTooLong
	}
	return nil
}

// Hash applies HMAC-SHA256 pepper then Argon2id hashing.
func Hash(password, pepper string) (string, error) {
	if pepper == "" {
		return "", ErrEmptyPepper
	}
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	peppered := applyPepper(password, pepper)
	hash, err := argon2id.CreateHash(peppered, argon2Params)
	if err != nil {
		return "", fmt.Errorf("argon2id hash: %w", err)
	}
	return hash, nil
}

// Verify checks a password against an Argon2id hash with pepper.
// Uses constant-time comparison internally via argon2id library.
func Verify(password, hash, pepper string) (bool, error) {
	if pepper == "" {
		return false, ErrEmptyPepper
	}
	peppered := applyPepper(password, pepper)
	match, err := argon2id.ComparePasswordAndHash(peppered, hash)
	if err != nil {
		return false, fmt.Errorf("argon2id verify: %w", err)
	}
	return match, nil
}

// CheckPasswordHistory checks if a password matches any of the previous hashes.
// Returns ErrPasswordReused if the password matches any hash in the history.
// The service layer is responsible for storing and retrieving the last N hashes.
func CheckPasswordHistory(password string, previousHashes []string, pepper string) error {
	for _, h := range previousHashes {
		match, err := Verify(password, h, pepper)
		if err != nil {
			return fmt.Errorf("checking password history: %w", err)
		}
		if match {
			return ErrPasswordReused
		}
	}
	return nil
}

// applyPepper applies HMAC-SHA256(pepper, password) and returns hex-encoded result.
func applyPepper(password, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(password))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// BreachChecker checks passwords against the HaveIBeenPwned API using k-Anonymity.
type BreachChecker struct {
	baseURL    string
	httpClient *http.Client
}

// NewBreachChecker creates a BreachChecker with the production HIBP API.
func NewBreachChecker() *BreachChecker {
	return &BreachChecker{
		baseURL: "https://api.pwnedpasswords.com/range/",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// NewBreachCheckerWithURL creates a BreachChecker with a custom base URL (for testing).
func NewBreachCheckerWithURL(baseURL string) *BreachChecker {
	return &BreachChecker{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Check checks the password against HaveIBeenPwned using k-Anonymity.
// It sends only the first 5 characters of the SHA-1 hash to the API.
func (bc *BreachChecker) Check(ctx context.Context, password string) (bool, error) {
	h := sha1.New()
	h.Write([]byte(password))
	fullHash := fmt.Sprintf("%X", h.Sum(nil))

	prefix := fullHash[:5]
	suffix := fullHash[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bc.baseURL+prefix, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("hibp request: %w", err)
	}
	req.Header.Set("User-Agent", "PalAuth-Server")
	req.Header.Set("Add-Padding", "true")

	resp, err := bc.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("hibp api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hibp api returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return false, fmt.Errorf("hibp read body: %w", err)
	}

	lines := strings.Split(string(body), "\r\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], suffix) {
			return true, nil
		}
	}

	return false, nil
}
