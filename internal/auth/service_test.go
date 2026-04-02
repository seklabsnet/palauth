package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, "test-pepper-at-least-32-bytes-long!!", nil, nil)
	require.NotNil(t, svc)
	assert.NotEmpty(t, svc.emailHashKey, "email hash key should be derived from pepper")
	assert.Len(t, svc.emailHashKey, 32, "email hash key should be 32 bytes (HMAC-SHA256)")
}
