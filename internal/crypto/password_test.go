package crypto

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

const testPepper = "this-is-a-test-pepper-at-least-32-bytes-long-ok"

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"valid 15 chars", "abcdefghijklmno", nil},
		{"valid 64 chars", strings.Repeat("a", 64), nil},
		{"too short 14 chars", "abcdefghijklmn", ErrPasswordTooShort},
		{"too short empty", "", ErrPasswordTooShort},
		{"too long 65 chars", strings.Repeat("a", 65), ErrPasswordTooLong},
		{"unicode counted as runes", strings.Repeat("ä", 15), nil},
		{"unicode too short", strings.Repeat("ä", 14), ErrPasswordTooShort},
		{"no composition rules - no uppercase needed", "abcdefghijklmno", nil},
		{"no composition rules - no digit needed", "abcdefghijklmno", nil},
		{"no composition rules - no special needed", "abcdefghijklmno", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHash_SaltUniqueness(t *testing.T) {
	password := "my-secure-password!!"
	hash1, err := Hash(password, testPepper)
	require.NoError(t, err)

	hash2, err := Hash(password, testPepper)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "same password hashed twice must produce different results (salt)")
}

func TestHash_And_Verify(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash, err := Hash(password, testPepper)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	match, err := Verify(password, hash, testPepper)
	require.NoError(t, err)
	assert.True(t, match)
}

func TestVerify_WrongPassword(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash, err := Hash(password, testPepper)
	require.NoError(t, err)

	match, err := Verify("wrong-horse-battery-staple", hash, testPepper)
	require.NoError(t, err)
	assert.False(t, match)
}

func TestVerify_WrongPepper(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash, err := Hash(password, testPepper)
	require.NoError(t, err)

	match, err := Verify(password, hash, "different-pepper-also-32-bytes-long-ok")
	require.NoError(t, err)
	assert.False(t, match)
}

func TestHash_ValidationErrors(t *testing.T) {
	_, err := Hash("short", testPepper)
	assert.ErrorIs(t, err, ErrPasswordTooShort)

	_, err = Hash(strings.Repeat("a", 65), testPepper)
	assert.ErrorIs(t, err, ErrPasswordTooLong)
}

func TestHash_EmptyPepper(t *testing.T) {
	_, err := Hash("valid-password-here!", "")
	assert.ErrorIs(t, err, ErrEmptyPepper)
}

func TestVerify_EmptyPepper(t *testing.T) {
	_, err := Verify("valid-password-here!", "$argon2id$v=19$m=65536,t=3,p=1$fakesalt$fakehash", "")
	assert.ErrorIs(t, err, ErrEmptyPepper)
}

func BenchmarkHash(b *testing.B) {
	password := "benchmark-password-here!"
	for b.Loop() {
		_, err := Hash(password, testPepper)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestHash_Benchmark300ms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	password := "benchmark-password-here!"
	const iterations = 5
	var totalDuration time.Duration

	for range iterations {
		start := time.Now()
		_, err := Hash(password, testPepper)
		require.NoError(t, err)
		totalDuration += time.Since(start)
	}

	avg := totalDuration / iterations
	t.Logf("Average hash time: %v", avg)
	// Should be in the ballpark of 300ms (allow wide range for CI variance)
	assert.Greater(t, avg, 50*time.Millisecond, "hash should take meaningful time")
	assert.Less(t, avg, 5*time.Second, "hash should not take too long")
}

func TestVerify_TimingVariance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	password := "correct-horse-battery-staple"
	hash, err := Hash(password, testPepper)
	require.NoError(t, err)

	const iterations = 30

	// Measure correct password verification times
	var correctTimes []time.Duration
	for range iterations {
		start := time.Now()
		_, _ = Verify(password, hash, testPepper)
		correctTimes = append(correctTimes, time.Since(start))
	}

	// Measure wrong password verification times
	var wrongTimes []time.Duration
	for range iterations {
		start := time.Now()
		_, _ = Verify("wrong-horse-battery-staple", hash, testPepper)
		wrongTimes = append(wrongTimes, time.Since(start))
	}

	// Use median instead of mean to reduce outlier impact from OS scheduling
	medCorrect := median(correctTimes)
	medWrong := median(wrongTimes)

	diff := math.Abs(float64(medCorrect-medWrong)) / float64(time.Millisecond)
	t.Logf("Median correct: %v, Median wrong: %v, Diff: %.2fms", medCorrect, medWrong, diff)
	// Argon2id uses constant-time comparison internally.
	// Median reduces OS scheduling noise; < 1ms threshold per spec.
	assert.Less(t, diff, 1.0, "timing variance between correct and wrong password must be < 1ms")
}

func median(durations []time.Duration) time.Duration {
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func TestCheckPasswordHistory_Reused(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash1, err := Hash(password, testPepper)
	require.NoError(t, err)
	hash2, err := Hash("another-valid-password!!", testPepper)
	require.NoError(t, err)

	err = CheckPasswordHistory(password, []string{hash2, hash1}, testPepper)
	assert.ErrorIs(t, err, ErrPasswordReused)
}

func TestCheckPasswordHistory_NotReused(t *testing.T) {
	hash1, err := Hash("old-password-number-one!", testPepper)
	require.NoError(t, err)
	hash2, err := Hash("old-password-number-two!", testPepper)
	require.NoError(t, err)

	err = CheckPasswordHistory("brand-new-password-here!", []string{hash1, hash2}, testPepper)
	assert.NoError(t, err)
}

func TestCheckPasswordHistory_EmptyHistory(t *testing.T) {
	err := CheckPasswordHistory("any-valid-password-here!", nil, testPepper)
	assert.NoError(t, err)
}

func TestCheckPasswordHistory_Last4(t *testing.T) {
	passwords := []string{
		"password-number-one!!",
		"password-number-two!!",
		"password-number-three",
		"password-number-four!",
	}
	var hashes []string
	for _, p := range passwords {
		h, err := Hash(p, testPepper)
		require.NoError(t, err)
		hashes = append(hashes, h)
	}

	// Each of the 4 passwords should be rejected
	for _, p := range passwords {
		err := CheckPasswordHistory(p, hashes, testPepper)
		assert.ErrorIs(t, err, ErrPasswordReused, "password %q should be rejected", p)
	}

	// A new password should pass
	err := CheckPasswordHistory("completely-new-password!", hashes, testPepper)
	assert.NoError(t, err)
}

func TestBreachChecker_KnownBreached(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping HIBP API test in short mode")
	}

	bc := NewBreachChecker()
	breached, err := bc.Check(context.Background(), "password")
	require.NoError(t, err)
	assert.True(t, breached, "'password' should be found in HIBP")
}

func TestBreachChecker_NotBreached(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping HIBP API test in short mode")
	}

	bc := NewBreachChecker()
	token, err := GenerateToken(32)
	require.NoError(t, err)
	breached, err := bc.Check(context.Background(), token)
	require.NoError(t, err)
	assert.False(t, breached)
}

func TestBreachChecker_MockServer_Breached(t *testing.T) {
	// SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	// prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/range/5BAA6", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB:0\r\n"))
	}))
	defer server.Close()

	bc := NewBreachCheckerWithURL(server.URL + "/range/")
	breached, err := bc.Check(context.Background(), "password")
	require.NoError(t, err)
	assert.True(t, breached)
}

func TestBreachChecker_MockServer_NotBreached(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:1\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB:0\r\n"))
	}))
	defer server.Close()

	bc := NewBreachCheckerWithURL(server.URL + "/range/")
	breached, err := bc.Check(context.Background(), "some-unique-password-12345")
	require.NoError(t, err)
	assert.False(t, breached)
}

func TestApplyPepper_Deterministic(t *testing.T) {
	p1 := applyPepper("password", "pepper")
	p2 := applyPepper("password", "pepper")
	assert.Equal(t, p1, p2, "same input must produce same peppered value")
}

func TestApplyPepper_DifferentPeppers(t *testing.T) {
	p1 := applyPepper("password", "pepper1")
	p2 := applyPepper("password", "pepper2")
	assert.NotEqual(t, p1, p2, "different peppers must produce different results")
}

// Property-based tests using rapid

func TestRapid_HashVerifyRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a valid password (15-64 printable ASCII chars)
		length := rapid.IntRange(15, 64).Draw(t, "length")
		chars := make([]byte, length)
		for i := range chars {
			// Printable ASCII range: '!' (33) to '~' (126)
			chars[i] = byte(rapid.IntRange(33, 126).Draw(t, "char"))
		}
		password := string(chars)

		hash, err := Hash(password, testPepper)
		require.NoError(t, err)

		match, err := Verify(password, hash, testPepper)
		require.NoError(t, err)
		assert.True(t, match, "Hash/Verify roundtrip must succeed for any valid password")
	})
}
