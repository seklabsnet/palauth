package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/palauth/palauth/internal/admin"
	"github.com/palauth/palauth/internal/crypto"
)

type adminSetupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type adminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type adminLoginResponse struct {
	Token string `json:"token"`
}

func (s *Server) handleAdminSetup(w http.ResponseWriter, r *http.Request) {
	var req adminSetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	result, err := s.adminSvc.Setup(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrAdminAlreadyExists):
			s.WriteError(w, r, http.StatusConflict, "admin_exists", "Admin user already exists")
		case errors.Is(err, admin.ErrEmailRequired):
			s.WriteError(w, r, http.StatusBadRequest, "email_required", "Email is required")
		case errors.Is(err, admin.ErrPasswordRequired):
			s.WriteError(w, r, http.StatusBadRequest, "password_required", "Password is required")
		case errors.Is(err, crypto.ErrPasswordTooShort):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_short", "Password must be at least 15 characters")
		case errors.Is(err, crypto.ErrPasswordTooLong):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_long", "Password must be at most 64 characters")
		default:
			s.logger.Error("admin setup failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusCreated, result)
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req adminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	token, err := s.adminSvc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrInvalidCredentials):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "Email or password is incorrect")
		case errors.Is(err, admin.ErrEmailRequired):
			s.WriteError(w, r, http.StatusBadRequest, "email_required", "Email is required")
		case errors.Is(err, admin.ErrPasswordRequired):
			s.WriteError(w, r, http.StatusBadRequest, "password_required", "Password is required")
		default:
			s.logger.Error("admin login failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, adminLoginResponse{Token: token})
}
