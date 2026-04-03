package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/auth"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/token"
)

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type verifyEmailRequest struct {
	Token string `json:"token,omitempty"` // link-based verification
	Code  string `json:"code,omitempty"`  // OTP-based verification
	Email string `json:"email,omitempty"` // required for OTP
}

type resendVerificationRequest struct {
	Email string `json:"email"`
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

type passwordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	result, err := s.authSvc.Signup(r.Context(), req.Email, req.Password, projectID)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrEmailRequired):
			s.WriteError(w, r, http.StatusBadRequest, "email_required", "A valid email address is required")
		case errors.Is(err, auth.ErrPasswordRequired):
			s.WriteError(w, r, http.StatusBadRequest, "password_required", "Password is required")
		case errors.Is(err, crypto.ErrPasswordTooShort):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_short", "Password must be at least 15 characters")
		case errors.Is(err, crypto.ErrPasswordTooLong):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_long", "Password must be at most 64 characters")
		case errors.Is(err, crypto.ErrPasswordBreached):
			s.WriteError(w, r, http.StatusBadRequest, "password_breached", "This password has been found in a data breach and cannot be used")
		case errors.Is(err, auth.ErrSignupFailed):
			// Generic error for duplicate email — same as any validation error
			// to prevent user enumeration.
			s.WriteError(w, r, http.StatusBadRequest, "signup_failed", "Unable to create account with the provided information")
		case errors.Is(err, auth.ErrHIBPUnavailable):
			s.WriteError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Password breach check is temporarily unavailable, please retry")
		default:
			s.logger.Error("signup failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusCreated, result)
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	var err error
	switch {
	case req.Token != "":
		// Link-based verification.
		err = s.authSvc.VerifyEmailByToken(r.Context(), req.Token, projectID)
	case req.Code != "" && req.Email != "":
		// OTP-based verification.
		err = s.authSvc.VerifyEmailByCode(r.Context(), req.Code, req.Email, projectID)
	default:
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Either token or code+email is required")
		return
	}

	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTokenNotFound):
			s.WriteError(w, r, http.StatusBadRequest, "invalid_token", "The verification token is invalid")
		case errors.Is(err, auth.ErrTokenExpired):
			s.WriteError(w, r, http.StatusBadRequest, "token_expired", "The verification token has expired")
		case errors.Is(err, auth.ErrTokenUsed):
			s.WriteError(w, r, http.StatusBadRequest, "token_used", "The verification token has already been used")
		case errors.Is(err, auth.ErrOTPMaxAttempts):
			s.WriteError(w, r, http.StatusTooManyRequests, "max_attempts_exceeded", "Maximum verification attempts exceeded, please request a new code")
		default:
			s.logger.Error("verify email failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	ip := r.RemoteAddr
	ua := r.Header.Get("User-Agent")

	result, retryAfter, err := s.authSvc.Login(r.Context(), &auth.LoginParams{
		Email:     req.Email,
		Password:  req.Password,
		ProjectID: projectID,
		IP:        &ip,
		UserAgent: &ua,
	})
	if err != nil {
		// Check if MFA is required.
		var mfaErr *auth.MFARequiredError
		if errors.As(err, &mfaErr) {
			s.WriteJSON(w, http.StatusOK, map[string]any{
				"mfa_required": true,
				"mfa_token":    mfaErr.MFAToken,
				"factors":      mfaErr.Factors,
			})
			return
		}

		switch {
		case errors.Is(err, auth.ErrEmailRequired):
			s.WriteError(w, r, http.StatusBadRequest, "email_required", "A valid email address is required")
		case errors.Is(err, auth.ErrPasswordRequired):
			s.WriteError(w, r, http.StatusBadRequest, "password_required", "Password is required")
		case errors.Is(err, auth.ErrInvalidCredentials):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "Email or password is incorrect")
		case errors.Is(err, auth.ErrUserBanned):
			s.WriteError(w, r, http.StatusForbidden, "user_banned", "This account has been suspended")
		case errors.Is(err, auth.ErrAccountLocked):
			retrySeconds := int(retryAfter.Seconds())
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySeconds))
			s.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":             "account_locked",
				"error_description": fmt.Sprintf("Account is temporarily locked due to too many failed login attempts. Try again in %d seconds", retrySeconds),
				"status":            http.StatusTooManyRequests,
				"request_id":        GetRequestID(r.Context()),
				"retry_after":       retrySeconds,
			})
		default:
			s.logger.Error("login failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	var req resendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Email == "" {
		s.WriteError(w, r, http.StatusBadRequest, "email_required", "Email is required")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	result, err := s.authSvc.ResendVerification(r.Context(), req.Email, projectID)
	if err != nil {
		if errors.Is(err, auth.ErrEmailRequired) {
			s.WriteError(w, r, http.StatusBadRequest, "email_required", "Email is required")
			return
		}
		s.logger.Error("resend verification failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	// Always return 200 — enumeration prevention.
	s.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	// Always returns nil for enumeration prevention.
	_ = s.authSvc.RequestReset(r.Context(), projectID, req.Email)

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req passwordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	err := s.authSvc.ConfirmReset(r.Context(), projectID, req.Token, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTokenRequired):
			s.WriteError(w, r, http.StatusBadRequest, "token_required", "Reset token is required")
		case errors.Is(err, auth.ErrTokenNotFound):
			s.WriteError(w, r, http.StatusBadRequest, "invalid_token", "The reset token is invalid")
		case errors.Is(err, auth.ErrTokenUsed):
			s.WriteError(w, r, http.StatusBadRequest, "token_used", "The reset token has already been used")
		case errors.Is(err, auth.ErrTokenExpired):
			s.WriteError(w, r, http.StatusBadRequest, "token_expired", "The reset token has expired")
		case errors.Is(err, crypto.ErrPasswordTooShort):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_short", "Password must be at least 15 characters")
		case errors.Is(err, crypto.ErrPasswordTooLong):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_long", "Password must be at most 64 characters")
		case errors.Is(err, crypto.ErrPasswordBreached):
			s.WriteError(w, r, http.StatusBadRequest, "password_breached", "This password has been found in a data breach and cannot be used")
		case errors.Is(err, crypto.ErrPasswordReused):
			s.WriteError(w, r, http.StatusBadRequest, "password_reused", "This password was recently used and cannot be reused")
		case errors.Is(err, auth.ErrHIBPUnavailable):
			s.WriteError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Password breach check is temporarily unavailable, please retry")
		default:
			s.logger.Error("password reset confirm failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// extractBearerClaims extracts and verifies a JWT Bearer token from the Authorization header.
// Returns nil claims and writes an error response if the token is missing or invalid.
func (s *Server) extractBearerClaims(w http.ResponseWriter, r *http.Request) *token.Claims {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		s.WriteError(w, r, http.StatusUnauthorized, "unauthorized", "Bearer token is required")
		return nil
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := s.jwtSvc.Verify(tokenStr)
	if err != nil {
		s.WriteError(w, r, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
		return nil
	}
	return claims
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	var req passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	claims := s.extractBearerClaims(w, r)
	if claims == nil {
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	err := s.authSvc.ChangePassword(r.Context(), projectID, claims.Subject, req.CurrentPassword, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrCurrentPasswordRequired):
			s.WriteError(w, r, http.StatusBadRequest, "current_password_required", "Current password is required")
		case errors.Is(err, auth.ErrNewPasswordRequired):
			s.WriteError(w, r, http.StatusBadRequest, "new_password_required", "New password is required")
		case errors.Is(err, auth.ErrInvalidCredentials):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "Current password is incorrect")
		case errors.Is(err, crypto.ErrPasswordTooShort):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_short", "Password must be at least 15 characters")
		case errors.Is(err, crypto.ErrPasswordTooLong):
			s.WriteError(w, r, http.StatusBadRequest, "password_too_long", "Password must be at most 64 characters")
		case errors.Is(err, crypto.ErrPasswordBreached):
			s.WriteError(w, r, http.StatusBadRequest, "password_breached", "This password has been found in a data breach and cannot be used")
		case errors.Is(err, crypto.ErrPasswordReused):
			s.WriteError(w, r, http.StatusBadRequest, "password_reused", "This password was recently used and cannot be reused")
		case errors.Is(err, auth.ErrHIBPUnavailable):
			s.WriteError(w, r, http.StatusServiceUnavailable, "service_unavailable", "Password breach check is temporarily unavailable, please retry")
		default:
			s.logger.Error("password change failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
