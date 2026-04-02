package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/session"
	"github.com/palauth/palauth/internal/token"
)

type sessionCtxKey string

const (
	sessionUserIDCtxKey sessionCtxKey = "session_user_id"
	sessionIDCtxKey     sessionCtxKey = "session_id"
)

// SessionUserIDFromContext returns the authenticated user ID from the request context.
func SessionUserIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sessionUserIDCtxKey).(string); ok {
		return v
	}
	return ""
}

// SessionIDFromContext returns the current session ID from the request context.
func SessionIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sessionIDCtxKey).(string); ok {
		return v
	}
	return ""
}

// sessionMiddleware validates the JWT Bearer token and session, then sets user/session context.
func (s *Server) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			s.WriteError(w, r, http.StatusUnauthorized, "missing_token", "Authorization Bearer token is required")
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := s.jwtSvc.Verify(tokenStr)
		if err != nil {
			if errors.Is(err, token.ErrTokenExpired) {
				s.WriteError(w, r, http.StatusUnauthorized, "token_expired", "The access token has expired")
				return
			}
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "The provided token is invalid")
			return
		}

		if claims.SessionID == "" {
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "Token is missing session information")
			return
		}

		// Validate session and touch (update last_activity).
		sess, err := s.sessionSvc.ValidateAndTouch(r.Context(), claims.SessionID)
		if err != nil {
			if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionRevoked) {
				s.WriteError(w, r, http.StatusUnauthorized, "session_revoked", "The session has been revoked")
				return
			}
			if errors.Is(err, session.ErrSessionExpired) {
				s.WriteError(w, r, http.StatusUnauthorized, "session_expired", "The session has expired")
				return
			}
			s.logger.Error("session validation failed", "error", err, "session_id", claims.SessionID)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
			return
		}

		// Defense-in-depth: verify the session's project matches the JWT's project claim
		// to prevent cross-tenant confusion attacks.
		if sess.ProjectID != claims.ProjectID {
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "Token project mismatch")
			return
		}

		ctx := context.WithValue(r.Context(), sessionUserIDCtxKey, sess.UserID)
		ctx = context.WithValue(ctx, sessionIDCtxKey, sess.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sessionResponse is the JSON shape returned by session listing endpoints.
type sessionResponse struct {
	ID           string   `json:"id"`
	IP           string   `json:"ip,omitempty"`
	UserAgent    string   `json:"user_agent,omitempty"`
	ACR          string   `json:"acr"`
	AMR          []string `json:"amr"`
	LastActivity string   `json:"last_activity"`
	CreatedAt    string   `json:"created_at"`
	Current      bool     `json:"current"`
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID := SessionUserIDFromContext(r.Context())
	projectID := apikey.ProjectIDFromContext(r.Context())
	currentSessionID := SessionIDFromContext(r.Context())

	sessions, err := s.sessionSvc.List(r.Context(), userID, projectID)
	if err != nil {
		s.logger.Error("list sessions failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	resp := make([]sessionResponse, 0, len(sessions))
	for i := range sessions {
		resp = append(resp, sessionResponse{
			ID:           sessions[i].ID,
			IP:           sessions[i].IP,
			UserAgent:    sessions[i].UserAgent,
			ACR:          sessions[i].ACR,
			AMR:          sessions[i].AMR,
			LastActivity: sessions[i].LastActivity.UTC().Format("2006-01-02T15:04:05Z"),
			CreatedAt:    sessions[i].CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Current:      sessions[i].ID == currentSessionID,
		})
	}

	s.WriteJSON(w, http.StatusOK, map[string]any{"sessions": resp})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Session ID is required")
		return
	}

	userID := SessionUserIDFromContext(r.Context())
	projectID := apikey.ProjectIDFromContext(r.Context())

	if err := s.sessionSvc.Revoke(r.Context(), sessionID, projectID, userID); err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			s.WriteError(w, r, http.StatusNotFound, "session_not_found", "Session not found")
			return
		}
		s.logger.Error("revoke session failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	userID := SessionUserIDFromContext(r.Context())
	projectID := apikey.ProjectIDFromContext(r.Context())

	if err := s.sessionSvc.RevokeAll(r.Context(), userID, projectID); err != nil {
		s.logger.Error("revoke all sessions failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := SessionIDFromContext(r.Context())
	userID := SessionUserIDFromContext(r.Context())
	projectID := apikey.ProjectIDFromContext(r.Context())

	if err := s.sessionSvc.Revoke(r.Context(), sessionID, projectID, userID); err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			// Session already revoked — still return success.
			s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
			return
		}
		s.logger.Error("logout failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
