package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/audit"
	"github.com/palauth/palauth/internal/token"
)

// --- Request/Response types ---

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type createCustomTokenRequest struct {
	UserID    string         `json:"user_id"`
	Claims    map[string]any `json:"claims,omitempty"`
	ExpiresIn int            `json:"expires_in,omitempty"` // seconds
}

type createCustomTokenResponse struct {
	CustomToken string `json:"custom_token"`
}

type exchangeCustomTokenRequest struct {
	CustomToken string `json:"custom_token"`
}

type exchangeCustomTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type introspectRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

type revokeRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

// --- Handlers ---

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req refreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.RefreshToken == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	result, err := s.refreshSvc.Rotate(r.Context(), req.RefreshToken, projectID, &token.IssueParams{
		Issuer: s.cfg.Server.Host,
		// AuthTime is set by Rotate() from the session's created_at
		// to preserve the original authentication time per RFC 9068.
	})
	if err != nil {
		switch {
		case errors.Is(err, token.ErrTokenNotFound), errors.Is(err, token.ErrProjectMismatch):
			s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
				EventType: audit.EventTokenRefresh,
				Actor:     audit.ActorInfo{UserID: "unknown"},
				Result:    "failure",
				ProjectID: projectID,
				Metadata:  map[string]any{"reason": "invalid_token"},
			})
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "The provided refresh token is invalid")
		case errors.Is(err, token.ErrTokenStolen):
			s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
				EventType: audit.EventTokenRevoke,
				Actor:     audit.ActorInfo{UserID: "system"},
				Result:    "failure",
				ProjectID: projectID,
				Metadata:  map[string]any{"reason": "token_reuse_detected"},
			})
			s.WriteError(w, r, http.StatusUnauthorized, "token_reuse", "Refresh token reuse detected — all tokens in family revoked")
		case errors.Is(err, token.ErrTokenExpiredRT):
			s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
				EventType: audit.EventTokenRefresh,
				Actor:     audit.ActorInfo{UserID: "unknown"},
				Result:    "failure",
				ProjectID: projectID,
				Metadata:  map[string]any{"reason": "token_expired"},
			})
			s.WriteError(w, r, http.StatusUnauthorized, "token_expired", "The refresh token has expired")
		case errors.Is(err, token.ErrSessionRevoked):
			s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
				EventType: audit.EventTokenRefresh,
				Actor:     audit.ActorInfo{UserID: "unknown"},
				Result:    "failure",
				ProjectID: projectID,
				Metadata:  map[string]any{"reason": "session_revoked"},
			})
			s.WriteError(w, r, http.StatusUnauthorized, "session_revoked", "The session has been revoked")
		default:
			s.logger.Error("token refresh failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// Audit log for successful refresh.
	s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
		EventType: audit.EventTokenRefresh,
		Actor:     audit.ActorInfo{UserID: result.UserID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"session_id": result.SessionID},
	})

	s.WriteJSON(w, http.StatusOK, refreshTokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.cfg.Auth.AccessTokenTTL,
	})
}

func (s *Server) handleCreateCustomToken(w http.ResponseWriter, r *http.Request) {
	var req createCustomTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.UserID == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}

	var expiresIn time.Duration
	if req.ExpiresIn > 0 {
		expiresIn = time.Duration(req.ExpiresIn) * time.Second
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	customToken, err := s.customSvc.CreateCustomToken(token.CreateCustomTokenParams{
		UserID:    req.UserID,
		ProjectID: projectID,
		Issuer:    s.cfg.Server.Host,
		Claims:    req.Claims,
		ExpiresIn: expiresIn,
	})
	if err != nil {
		switch {
		case errors.Is(err, token.ErrCustomTokenTTLExceeded):
			s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "expires_in exceeds maximum of 3600 seconds")
		case errors.Is(err, token.ErrUserIDRequired):
			s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "user_id is required")
		default:
			s.logger.Error("create custom token failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
		EventType: audit.EventTokenIssue,
		Actor:     audit.ActorInfo{UserID: req.UserID},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"token_type": "custom"},
	})

	s.WriteJSON(w, http.StatusCreated, createCustomTokenResponse{
		CustomToken: customToken,
	})
}

func (s *Server) handleExchangeCustomToken(w http.ResponseWriter, r *http.Request) {
	var req exchangeCustomTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.CustomToken == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "custom_token is required")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	claims, err := s.customSvc.ExchangeCustomToken(r.Context(), req.CustomToken)
	if err != nil {
		switch {
		case errors.Is(err, token.ErrInvalidToken),
			errors.Is(err, token.ErrTokenExpired),
			errors.Is(err, token.ErrCustomTokenExpired),
			errors.Is(err, token.ErrInvalidSignature):
			s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
				EventType: audit.EventTokenIssue,
				Actor:     audit.ActorInfo{UserID: "unknown"},
				Result:    "failure",
				ProjectID: projectID,
				Metadata:  map[string]any{"token_type": "exchange", "reason": "invalid_or_expired"},
			})
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "The provided custom token is invalid or expired")
		case errors.Is(err, token.ErrCustomTokenAlreadyUsed):
			s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
				EventType: audit.EventTokenIssue,
				Actor:     audit.ActorInfo{UserID: "unknown"},
				Result:    "failure",
				ProjectID: projectID,
				Metadata:  map[string]any{"token_type": "exchange", "reason": "already_used"},
			})
			s.WriteError(w, r, http.StatusUnauthorized, "token_used", "The custom token has already been used")
		default:
			s.logger.Error("exchange custom token failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// Validate that the custom token belongs to this project (multi-tenant isolation).
	if claims.ProjectID != projectID {
		s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
			EventType: audit.EventTokenIssue,
			Actor:     audit.ActorInfo{UserID: claims.Subject},
			Result:    "failure",
			ProjectID: projectID,
			Metadata:  map[string]any{"token_type": "exchange", "reason": "project_mismatch"},
		})
		s.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "The provided custom token is invalid or expired")
		return
	}

	// Create session for the user.
	session, err := s.createSessionForCustomToken(r, claims, projectID)
	if err != nil {
		s.logger.Error("create session for custom token failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	// Issue normal tokens.
	accessToken, err := s.jwtSvc.Issue(&token.IssueParams{
		UserID:    claims.Subject,
		SessionID: session.ID,
		ProjectID: projectID,
		Issuer:    s.cfg.Server.Host,
		AuthTime:  time.Now(),
	})
	if err != nil {
		s.logger.Error("issue access token failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	refreshToken, err := s.refreshSvc.Issue(r.Context(), claims.Subject, session.ID, projectID)
	if err != nil {
		s.logger.Error("issue refresh token failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
		EventType: audit.EventTokenIssue,
		Actor:     audit.ActorInfo{UserID: claims.Subject},
		Result:    "success",
		ProjectID: projectID,
		Metadata:  map[string]any{"token_type": "exchange", "session_id": session.ID},
	})

	s.WriteJSON(w, http.StatusOK, exchangeCustomTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.cfg.Auth.AccessTokenTTL,
	})
}

func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	var req introspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Token == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	resp := s.jwtSvc.IntrospectAccessToken(req.Token)
	s.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Per RFC 7009, always return 200.
		s.WriteJSON(w, http.StatusOK, map[string]string{})
		return
	}

	if req.Token == "" {
		// Per RFC 7009, always return 200.
		s.WriteJSON(w, http.StatusOK, map[string]string{})
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	if err := s.refreshSvc.Revoke(r.Context(), req.Token, req.TokenTypeHint); err != nil {
		s.logger.Error("token revoke failed", "error", err)
		// Per RFC 7009, always return 200 — no info leakage.
	} else {
		s.auditSvc.Log(r.Context(), &audit.Event{ //nolint:errcheck // best-effort audit
			EventType: audit.EventTokenRevoke,
			Actor:     audit.ActorInfo{UserID: "system"},
			Result:    "success",
			ProjectID: projectID,
		})
	}

	// Always return 200 per RFC 7009.
	s.WriteJSON(w, http.StatusOK, map[string]string{})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwks := s.jwtSvc.PublicKeys()
	w.Header().Set("Cache-Control", "public, max-age=3600")
	s.WriteJSON(w, http.StatusOK, jwks)
}

// createSessionForCustomToken creates a minimal session for a custom token exchange.
func (s *Server) createSessionForCustomToken(r *http.Request, claims *token.Claims, projectID string) (*sessionResult, error) {
	q := s.newQueries()

	ip := r.RemoteAddr
	ua := r.UserAgent()

	now := time.Now()
	sess, err := q.CreateSession(r.Context(), s.createSessionParams(projectID, claims.Subject, &ip, &ua, "aal1", []string{"custom_token"}, now))
	if err != nil {
		return nil, err
	}

	return &sessionResult{
		ID:        sess.ID,
		ProjectID: sess.ProjectID,
		UserID:    sess.UserID,
	}, nil
}

// sessionResult is a lightweight session info return type.
type sessionResult struct {
	ID        string
	ProjectID string
	UserID    string
}
