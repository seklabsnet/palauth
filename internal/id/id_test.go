package id

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		prefix string
	}{
		{"prj_"},
		{"usr_"},
		{"sess_"},
		{"rt_"},
		{"key_"},
		{"ph_"},
		{"vt_"},
		{"ek_"},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			id := New(tt.prefix)
			require.True(t, strings.HasPrefix(id, tt.prefix))
			// UUIDv7 is 36 chars
			assert.Len(t, id, len(tt.prefix)+36)
		})
	}
}

func TestNew_Unique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for range 1000 {
		id := New("usr_")
		assert.False(t, seen[id], "duplicate ID generated")
		seen[id] = true
	}
}
