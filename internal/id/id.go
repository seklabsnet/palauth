package id

import "github.com/google/uuid"

// New generates a UUIDv7 with the given prefix.
// Example: New("prj_") → "prj_0192f5e0-7c1a-7b3e-8d4f-1a2b3c4d5e6f"
func New(prefix string) string {
	return prefix + uuid.Must(uuid.NewV7()).String()
}
