package token

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRevoke_AccessTokenNoOp(t *testing.T) {
	// Revoke for access tokens is a no-op (stateless).
	// We test that the function doesn't panic or error.
	svc := &RefreshService{}
	err := svc.Revoke(context.Background(), "some-access-token", "access_token")
	assert.NoError(t, err)
}
