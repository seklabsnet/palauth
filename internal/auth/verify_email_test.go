package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyEmailByToken_EmptyToken(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	err := svc.VerifyEmailByToken(context.Background(), "", "prj_test")
	assert.ErrorIs(t, err, ErrTokenRequired)
}

func TestVerifyEmailByCode_EmptyCode(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	err := svc.VerifyEmailByCode(context.Background(), "", "test@example.com", "prj_test")
	assert.ErrorIs(t, err, ErrTokenRequired)
}

func TestVerifyEmailByCode_EmptyEmail(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	err := svc.VerifyEmailByCode(context.Background(), "123456", "", "prj_test")
	assert.ErrorIs(t, err, ErrEmailRequired)
}

func TestMaxOTPAttempts(t *testing.T) {
	// PSD2 RTS requires max 5 failed attempts.
	assert.Equal(t, int32(5), int32(maxOTPAttempts))
}
