package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/palauth/palauth/internal/admin"
	"github.com/palauth/palauth/internal/crypto"
)

type adminCreateUserRequest struct {
	Email    string           `json:"email"`
	Password string           `json:"password,omitempty"`
	Metadata json.RawMessage  `json:"metadata,omitempty"`
}

type adminUpdateUserRequest struct {
	EmailVerified *bool            `json:"email_verified,omitempty"`
	Metadata      *json.RawMessage `json:"metadata,omitempty"`
}

type adminBanUserRequest struct {
	Reason string `json:"reason"`
}

type adminInviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type deactivateInactiveRequest struct {
	Days int32 `json:"days"`
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req adminCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	projectID := chi.URLParam(r, "id")
	claims := admin.ClaimsFromContext(r.Context())

	user, err := s.adminUserSvc.CreateUser(r.Context(), projectID, req.Email, req.Password, req.Metadata, claims.Sub)
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrEmailRequired):
			s.WriteError(w, r, http.StatusBadRequest, "email_required", "Email is required")
		case errors.Is(err, admin.ErrInvalidEmail):
			s.WriteError(w, r, http.StatusBadRequest, "invalid_email", "Invalid email address")
		case errors.Is(err, admin.ErrDuplicateEmail):
			s.WriteError(w, r, http.StatusConflict, "duplicate_email", "A user with this email already exists in this project")
		case errors.Is(err, crypto.ErrPasswordTooShort):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_short", "Password must be at least 15 characters")
		case errors.Is(err, crypto.ErrPasswordTooLong):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_long", "Password must be at most 64 characters")
		case errors.Is(err, crypto.ErrPasswordBreached):
			s.WriteError(w, r, http.StatusBadRequest, "password_breached", "This password has been found in a data breach and cannot be used")
		default:
			s.logger.Error("admin create user failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusCreated, user)
}

func (s *Server) handleAdminGetUser(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "uid")

	user, err := s.adminUserSvc.GetUser(r.Context(), projectID, userID)
	if err != nil {
		if errors.Is(err, admin.ErrUserNotFound) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "User not found")
			return
		}
		s.logger.Error("admin get user failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, user)
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	opts := admin.UserListOptions{}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err == nil && limit > 0 {
			opts.Limit = int32(limit) //nolint:gosec // bounded by service layer
		}
	}

	if cursorTime := r.URL.Query().Get("cursor_created_at"); cursorTime != "" {
		if cursorID := r.URL.Query().Get("cursor_id"); cursorID != "" {
			t, err := time.Parse(time.RFC3339, cursorTime)
			if err == nil {
				opts.Cursor = &admin.UserCursor{
					CreatedAt: t,
					ID:        cursorID,
				}
			}
		}
	}

	if bannedStr := r.URL.Query().Get("banned"); bannedStr != "" {
		banned := bannedStr == "true"
		opts.Banned = &banned
	}

	opts.EmailQuery = r.URL.Query().Get("email")

	result, err := s.adminUserSvc.ListUsers(r.Context(), projectID, opts)
	if err != nil {
		s.logger.Error("admin list users failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req adminUpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	projectID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "uid")
	claims := admin.ClaimsFromContext(r.Context())

	user, err := s.adminUserSvc.UpdateUser(r.Context(), projectID, userID, admin.UpdateUserParams{
		EmailVerified: req.EmailVerified,
		Metadata:      req.Metadata,
	}, claims.Sub)
	if err != nil {
		if errors.Is(err, admin.ErrUserNotFound) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "User not found")
			return
		}
		s.logger.Error("admin update user failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, user)
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "uid")
	claims := admin.ClaimsFromContext(r.Context())

	err := s.adminUserSvc.DeleteUser(r.Context(), projectID, userID, claims.Sub)
	if err != nil {
		if errors.Is(err, admin.ErrUserNotFound) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "User not found")
			return
		}
		s.logger.Error("admin delete user failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminBanUser(w http.ResponseWriter, r *http.Request) {
	var req adminBanUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	projectID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "uid")
	claims := admin.ClaimsFromContext(r.Context())

	err := s.adminUserSvc.BanUser(r.Context(), projectID, userID, req.Reason, claims.Sub)
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrUserNotFound):
			s.WriteError(w, r, http.StatusNotFound, "not_found", "User not found")
		case errors.Is(err, admin.ErrUserAlreadyBanned):
			s.WriteError(w, r, http.StatusConflict, "already_banned", "User is already banned")
		case errors.Is(err, admin.ErrBanReasonRequired):
			s.WriteError(w, r, http.StatusBadRequest, "reason_required", "Ban reason is required")
		default:
			s.logger.Error("admin ban user failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "banned"})
}

func (s *Server) handleAdminUnbanUser(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "uid")
	claims := admin.ClaimsFromContext(r.Context())

	err := s.adminUserSvc.UnbanUser(r.Context(), projectID, userID, claims.Sub)
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrUserNotFound):
			s.WriteError(w, r, http.StatusNotFound, "not_found", "User not found")
		case errors.Is(err, admin.ErrUserNotBanned):
			s.WriteError(w, r, http.StatusConflict, "not_banned", "User is not banned")
		default:
			s.logger.Error("admin unban user failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "unbanned"})
}

func (s *Server) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "uid")
	claims := admin.ClaimsFromContext(r.Context())

	err := s.adminUserSvc.ResetUserPassword(r.Context(), projectID, userID, claims.Sub)
	if err != nil {
		if errors.Is(err, admin.ErrUserNotFound) {
			s.WriteError(w, r, http.StatusNotFound, "not_found", "User not found")
			return
		}
		s.logger.Error("admin reset password failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleProjectAnalytics(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")

	analytics, err := s.adminUserSvc.GetProjectAnalytics(r.Context(), projectID)
	if err != nil {
		s.logger.Error("get project analytics failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, analytics)
}

func (s *Server) handleAdminInvite(w http.ResponseWriter, r *http.Request) {
	var req adminInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	claims := admin.ClaimsFromContext(r.Context())

	result, err := s.adminSvc.InviteAdmin(r.Context(), req.Email, req.Role, claims.Sub, claims.Role)
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrEmailRequired):
			s.WriteError(w, r, http.StatusBadRequest, "email_required", "Email is required")
		case errors.Is(err, admin.ErrInvalidRole):
			s.WriteError(w, r, http.StatusBadRequest, "invalid_role", "Role must be 'owner' or 'admin'")
		case errors.Is(err, admin.ErrAdminEmailExists):
			s.WriteError(w, r, http.StatusConflict, "admin_exists", "An admin with this email already exists")
		case errors.Is(err, admin.ErrInsufficientPrivilege):
			s.WriteError(w, r, http.StatusForbidden, "insufficient_privilege", "You cannot invite an admin with a higher role than your own")
		default:
			s.logger.Error("admin invite failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusCreated, result)
}

func (s *Server) handleDeactivateInactive(w http.ResponseWriter, r *http.Request) {
	var req deactivateInactiveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Days <= 0 {
		req.Days = 90
	}
	if req.Days < 30 {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_days", "Minimum deactivation threshold is 30 days")
		return
	}

	count, err := s.adminUserSvc.DeactivateInactiveUsers(r.Context(), req.Days)
	if err != nil {
		s.logger.Error("deactivate inactive users failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]int{"deactivated_count": count})
}
