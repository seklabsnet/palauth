package ratelimit

import (
	"context"
	"net/http"
)

type ctxKey string

const (
	accountCtxKey ctxKey = "ratelimit_account"
	sessionCtxKey ctxKey = "ratelimit_session"
)

// WithAccountKey sets the account identifier (e.g., email hash) in the request context.
// Handlers should call this before the rate limit middleware evaluates the key.
func WithAccountKey(ctx context.Context, account string) context.Context {
	return context.WithValue(ctx, accountCtxKey, account)
}

// GetAccountKey returns the account identifier from the request context.
func GetAccountKey(r *http.Request) string {
	if v, ok := r.Context().Value(accountCtxKey).(string); ok {
		return v
	}
	return ""
}

// WithSessionKey sets the session identifier in the request context.
func WithSessionKey(ctx context.Context, session string) context.Context {
	return context.WithValue(ctx, sessionCtxKey, session)
}

// GetSessionKey returns the session identifier from the request context.
func GetSessionKey(r *http.Request) string {
	if v, ok := r.Context().Value(sessionCtxKey).(string); ok {
		return v
	}
	return ""
}
