package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogin_EmailRequired(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	_, _, err := svc.Login(context.Background(), &LoginParams{
		Email:     "",
		Password:  "validpassword1234",
		ProjectID: "prj_test",
	})
	assert.ErrorIs(t, err, ErrEmailRequired)
}

func TestLogin_PasswordRequired(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, testPepper, nil, nil)
	_, _, err := svc.Login(context.Background(), &LoginParams{
		Email:     "test@example.com",
		Password:  "",
		ProjectID: "prj_test",
	})
	assert.ErrorIs(t, err, ErrPasswordRequired)
}
