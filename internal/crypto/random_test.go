package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestGenerateToken_Length(t *testing.T) {
	tests := []struct {
		name      string
		byteLen   int
		wantChars int
	}{
		{"16 bytes", 16, 32},
		{"32 bytes", 32, 64},
		{"64 bytes", 64, 128},
		{"1 byte", 1, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.byteLen)
			require.NoError(t, err)
			assert.Len(t, token, tt.wantChars)
		})
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for range 1000 {
		token, err := GenerateToken(32)
		require.NoError(t, err)
		assert.False(t, seen[token], "duplicate token generated")
		seen[token] = true
	}
}

func TestGenerateToken_HexChars(t *testing.T) {
	token, err := GenerateToken(32)
	require.NoError(t, err)
	for _, c := range token {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"token should only contain hex characters, got: %c", c)
	}
}

func TestGenerateOTP_DigitCount(t *testing.T) {
	tests := []struct {
		digits int
	}{
		{4},
		{6},
		{8},
	}

	for _, tt := range tests {
		t.Run("digits_"+string(rune('0'+tt.digits)), func(t *testing.T) {
			otp, err := GenerateOTP(tt.digits)
			require.NoError(t, err)
			assert.Len(t, otp, tt.digits)
		})
	}
}

func TestGenerateOTP_OnlyDigits(t *testing.T) {
	for range 100 {
		otp, err := GenerateOTP(6)
		require.NoError(t, err)
		for _, c := range otp {
			assert.True(t, c >= '0' && c <= '9', "OTP should only contain digits, got: %c", c)
		}
	}
}

func TestGenerateOTP_LeadingZeros(t *testing.T) {
	foundLeadingZero := false
	for range 10000 {
		otp, err := GenerateOTP(6)
		require.NoError(t, err)
		if otp[0] == '0' {
			foundLeadingZero = true
			assert.Len(t, otp, 6, "OTP with leading zero must still be 6 digits")
			break
		}
	}
	assert.True(t, foundLeadingZero, "should generate OTPs with leading zeros")
}

func TestGenerateOTP_Unique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for range 100 {
		otp, err := GenerateOTP(8)
		require.NoError(t, err)
		assert.False(t, seen[otp], "duplicate OTP generated")
		seen[otp] = true
	}
}

// Property-based tests using rapid

func TestRapid_GenerateToken_LengthProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		length := rapid.IntRange(1, 128).Draw(t, "length")
		token, err := GenerateToken(length)
		require.NoError(t, err)
		assert.Len(t, token, 2*length, "hex output must be exactly 2x byte count")
	})
}

func TestRapid_GenerateOTP_DigitCountProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		digits := rapid.IntRange(1, 10).Draw(t, "digits")
		otp, err := GenerateOTP(digits)
		require.NoError(t, err)
		assert.Len(t, otp, digits, "OTP must have exactly the requested number of digits")
		for _, c := range otp {
			assert.True(t, c >= '0' && c <= '9', "OTP must only contain digits")
		}
	})
}
