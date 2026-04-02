package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/auth"
	"github.com/palauth/palauth/internal/crypto"
)

type signupRequest struct {
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
