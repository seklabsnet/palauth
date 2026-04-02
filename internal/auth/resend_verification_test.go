package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResendVerification_EmptyEmail(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	_, err := svc.ResendVerification(context.Background(), "", "prj_test")
	assert.ErrorIs(t, err, ErrEmailRequired)
}
