package apikey

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProjectIDFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", ProjectIDFromContext(ctx))
}

func TestSetProjectID_RoundTrip(t *testing.T) {
	ctx := context.Background()
	projectID := "prj_test-123"
	ctx = SetProjectID(ctx, projectID)
	assert.Equal(t, projectID, ProjectIDFromContext(ctx))
}

func TestSetProjectID_Overwrite(t *testing.T) {
	ctx := context.Background()
	ctx = SetProjectID(ctx, "first")
	ctx = SetProjectID(ctx, "second")
	assert.Equal(t, "second", ProjectIDFromContext(ctx))
}
