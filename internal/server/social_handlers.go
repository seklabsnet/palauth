package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/social"
)

type credentialExchangeRequest struct {
	Provider   string `json:"provider"`
	Credential string `json:"credential"` // id_token or access_token
}

type linkIdentityRequest struct {
	Provider   string `json:"provider"`
	Credential string `json:"credential"`
}

func (s *Server) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.socialSvc == nil {
		s.WriteError(w, r, http.StatusNotImplemented, "not_implemented", "Social login is not configured")
		return
	}

	providerName := chi.URLParam(r, "provider")
	if !social.ValidProviders[providerName] {
		s.WriteError(w, r, http.StatusBadRequest, "unsupported_provider", "Unsupported social provider")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}

	authURL, err := s.socialSvc.Authorize(r.Context(), projectID, providerName, redirectURI)
	if err != nil {
		switch {
		case errors.Is(err, social.ErrUnsupportedProvider):
			s.WriteError(w, r, http.StatusBadRequest, "unsupported_provider", "Provider is not supported")
		case errors.Is(err, social.ErrProviderNotEnabled):
			s.WriteError(w, r, http.StatusBadRequest, "provider_not_enabled", "Provider is not enabled for this project")
		case errors.Is(err, social.ErrInvalidRedirectURI):
			s.WriteError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "The redirect_uri is not in the project's allowed list")
		default:
			s.logger.Error("oauth authorize failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]string{"url": authURL})
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.socialSvc == nil {
		s.WriteError(w, r, http.StatusNotImplemented, "not_implemented", "Social login is not configured")
		return
	}

	providerName := chi.URLParam(r, "provider")
	if !social.ValidProviders[providerName] {
		s.WriteError(w, r, http.StatusBadRequest, "unsupported_provider", "Unsupported social provider")
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		// Check if provider returned an error.
		errParam := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		if errParam != "" {
			s.WriteError(w, r, http.StatusBadRequest, "oauth_error", errDesc)
			return
		}
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "code and state are required")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())
	ip := r.RemoteAddr
	userAgent := r.UserAgent()

	result, err := s.socialSvc.Callback(r.Context(), projectID, providerName, code, state, ip, userAgent)
	if err != nil {
		switch {
		case errors.Is(err, social.ErrInvalidState):
			s.WriteError(w, r, http.StatusBadRequest, "invalid_state", "Invalid or expired OAuth state")
		case errors.Is(err, social.ErrProviderExchange):
			s.WriteError(w, r, http.StatusBadRequest, "exchange_failed", "Failed to exchange authorization code")
		case errors.Is(err, social.ErrUnsupportedProvider):
			s.WriteError(w, r, http.StatusBadRequest, "unsupported_provider", "Provider is not supported")
		default:
			s.logger.Error("oauth callback failed", "error", err, "provider", providerName)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleCredentialExchange(w http.ResponseWriter, r *http.Request) {
	if s.socialSvc == nil {
		s.WriteError(w, r, http.StatusNotImplemented, "not_implemented", "Social login is not configured")
		return
	}

	var req credentialExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Provider == "" || req.Credential == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "provider and credential are required")
		return
	}

	if !social.ValidProviders[req.Provider] {
		s.WriteError(w, r, http.StatusBadRequest, "unsupported_provider", "Unsupported social provider")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())
	ip := r.RemoteAddr
	userAgent := r.UserAgent()

	result, err := s.socialSvc.ExchangeCredential(r.Context(), projectID, req.Provider, req.Credential, ip, userAgent)
	if err != nil {
		switch {
		case errors.Is(err, social.ErrInvalidCredential):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_credential", "The provided credential is invalid")
		case errors.Is(err, social.ErrUnsupportedProvider):
			s.WriteError(w, r, http.StatusBadRequest, "unsupported_provider", "Provider is not supported")
		default:
			s.logger.Error("credential exchange failed", "error", err, "provider", req.Provider)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	if s.socialSvc == nil {
		s.WriteError(w, r, http.StatusNotImplemented, "not_implemented", "Social login is not configured")
		return
	}

	userID := SessionUserIDFromContext(r.Context())
	projectID := apikey.ProjectIDFromContext(r.Context())

	identities, err := s.socialSvc.ListIdentities(r.Context(), projectID, userID)
	if err != nil {
		s.logger.Error("list identities failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]any{"identities": identities})
}

func (s *Server) handleLinkIdentity(w http.ResponseWriter, r *http.Request) {
	if s.socialSvc == nil {
		s.WriteError(w, r, http.StatusNotImplemented, "not_implemented", "Social login is not configured")
		return
	}

	var req linkIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Provider == "" || req.Credential == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "provider and credential are required")
		return
	}

	if !social.ValidProviders[req.Provider] {
		s.WriteError(w, r, http.StatusBadRequest, "unsupported_provider", "Unsupported social provider")
		return
	}

	userID := SessionUserIDFromContext(r.Context())
	projectID := apikey.ProjectIDFromContext(r.Context())

	err := s.socialSvc.LinkIdentity(r.Context(), projectID, userID, req.Provider, req.Credential)
	if err != nil {
		switch {
		case errors.Is(err, social.ErrInvalidCredential):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_credential", "The provided credential is invalid")
		case errors.Is(err, social.ErrIdentityAlreadyLinked):
			s.WriteError(w, r, http.StatusConflict, "identity_already_linked", "This social identity is already linked to another account")
		case errors.Is(err, social.ErrUnsupportedProvider):
			s.WriteError(w, r, http.StatusBadRequest, "unsupported_provider", "Provider is not supported")
		default:
			s.logger.Error("link identity failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleUnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	if s.socialSvc == nil {
		s.WriteError(w, r, http.StatusNotImplemented, "not_implemented", "Social login is not configured")
		return
	}

	identityID := chi.URLParam(r, "id")
	if identityID == "" {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Identity ID is required")
		return
	}

	userID := SessionUserIDFromContext(r.Context())
	projectID := apikey.ProjectIDFromContext(r.Context())

	err := s.socialSvc.UnlinkIdentity(r.Context(), projectID, userID, identityID)
	if err != nil {
		switch {
		case errors.Is(err, social.ErrCannotUnlinkLast):
			s.WriteError(w, r, http.StatusBadRequest, "cannot_unlink_last", "Cannot unlink the last authentication method")
		case errors.Is(err, social.ErrIdentityNotFound):
			s.WriteError(w, r, http.StatusNotFound, "identity_not_found", "Identity not found")
		default:
			s.logger.Error("unlink identity failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
