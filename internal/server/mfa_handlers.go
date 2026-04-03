package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/palauth/palauth/internal/apikey"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/id"
	"github.com/palauth/palauth/internal/mfa"
	"github.com/palauth/palauth/internal/session"
	"github.com/palauth/palauth/internal/token"
)

// MFA enrollment requests/responses.

type mfaEnrollRequest struct {
	Type string `json:"type"` // "totp" or "email"
}

type mfaChallengeRequest struct {
	MFAToken string `json:"mfa_token"`
	Type     string `json:"type"` // "totp" or "email"
	Code     string `json:"code"`
}

type mfaRecoveryRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

type mfaEmailChallengeRequest struct {
	MFAToken string `json:"mfa_token"`
}

type mfaEmailVerifyRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

type mfaVerifyEnrollmentRequest struct {
	Code string `json:"code"`
}

type mfaRemoveRequest struct {
	CurrentPassword string `json:"current_password"` // re-auth
}

// handleMFAEnroll handles MFA enrollment for TOTP or Email OTP.
// Requires a valid session (authenticated user).
func (s *Server) handleMFAEnroll(w http.ResponseWriter, r *http.Request) {
	var req mfaEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	claims := s.extractBearerClaims(w, r)
	if claims == nil {
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	switch req.Type {
	case "totp":
		// Get user's email for the TOTP account name.
		userEmail, err := s.mfaSvc.GetDecryptedEmail(r.Context(), projectID, claims.Subject)
		if err != nil {
			s.logger.Error("failed to get user email for TOTP enrollment", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
			return
		}

		result, err := s.mfaSvc.EnrollTOTP(r.Context(), projectID, claims.Subject, userEmail)
		if err != nil {
			switch {
			case errors.Is(err, mfa.ErrMFAAlreadyVerified):
				s.WriteError(w, r, http.StatusConflict, "mfa_already_enrolled", "TOTP MFA is already enrolled and verified")
			default:
				s.logger.Error("totp enrollment failed", "error", err)
				s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
			}
			return
		}

		// Generate recovery codes on first MFA enrollment.
		recoveryCodes, err := s.mfaSvc.GenerateRecoveryCodes(r.Context(), projectID, claims.Subject)
		if err != nil {
			s.logger.Error("failed to generate recovery codes", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
			return
		}

		s.WriteJSON(w, http.StatusOK, map[string]any{
			"enrollment_id":  result.EnrollmentID,
			"secret":         result.Secret,
			"otp_url":        result.OTPURL,
			"qr_code":        result.QRCode,
			"recovery_codes": recoveryCodes,
		})

	case "email":
		err := s.mfaSvc.EnrollEmail(r.Context(), projectID, claims.Subject)
		if err != nil {
			switch {
			case errors.Is(err, mfa.ErrMFAAlreadyVerified):
				s.WriteError(w, r, http.StatusConflict, "mfa_already_enrolled", "Email OTP MFA is already enrolled")
			case errors.Is(err, mfa.ErrEmailNotVerified):
				s.WriteError(w, r, http.StatusBadRequest, "email_not_verified", "Email must be verified before enrolling email OTP")
			default:
				s.logger.Error("email otp enrollment failed", "error", err)
				s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
			}
			return
		}

		s.WriteJSON(w, http.StatusOK, map[string]string{"status": "enrolled"})

	default:
		s.WriteError(w, r, http.StatusBadRequest, "invalid_type", "MFA type must be 'totp' or 'email'")
	}
}

// handleMFAVerifyEnrollment verifies a TOTP enrollment by checking the code.
func (s *Server) handleMFAVerifyEnrollment(w http.ResponseWriter, r *http.Request) {
	var req mfaVerifyEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.Code == "" {
		s.WriteError(w, r, http.StatusBadRequest, "code_required", "Verification code is required")
		return
	}

	claims := s.extractBearerClaims(w, r)
	if claims == nil {
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	err := s.mfaSvc.VerifyTOTPEnrollment(r.Context(), projectID, claims.Subject, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrMFANotEnrolled):
			s.WriteError(w, r, http.StatusNotFound, "mfa_not_enrolled", "No TOTP enrollment found")
		case errors.Is(err, mfa.ErrMFAAlreadyVerified):
			s.WriteError(w, r, http.StatusConflict, "mfa_already_verified", "TOTP enrollment is already verified")
		case errors.Is(err, mfa.ErrInvalidCode):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_code", "The verification code is incorrect")
		default:
			s.logger.Error("totp verify enrollment failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

// handleMFAChallenge handles MFA challenge during login flow.
// Requires a valid mfa_token (not a session token).
func (s *Server) handleMFAChallenge(w http.ResponseWriter, r *http.Request) {
	var req mfaChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.MFAToken == "" {
		s.WriteError(w, r, http.StatusBadRequest, "mfa_token_required", "MFA token is required")
		return
	}
	if req.Code == "" {
		s.WriteError(w, r, http.StatusBadRequest, "code_required", "Verification code is required")
		return
	}

	// Validate MFA token (don't consume yet — only consume on success).
	tokenData, err := s.mfaSvc.ValidateMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrMFATokenInvalid):
			s.WriteError(w, r, http.StatusUnauthorized, "mfa_token_invalid", "MFA token is invalid or expired")
		default:
			s.logger.Error("mfa token validation failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// Verify the MFA code based on type.
	// Use tokenData.ProjectID (from when the MFA token was issued) for consistency.
	switch req.Type {
	case "totp":
		err = s.mfaSvc.ValidateTOTPChallenge(r.Context(), tokenData.ProjectID, tokenData.UserID, req.Code)
	case "email":
		err = s.mfaSvc.VerifyEmailChallenge(r.Context(), tokenData.ProjectID, tokenData.UserID, req.Code)
	default:
		s.WriteError(w, r, http.StatusBadRequest, "invalid_type", "MFA type must be 'totp' or 'email'")
		return
	}

	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrInvalidCode):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_code", "The verification code is incorrect")
		case errors.Is(err, mfa.ErrMFALockout):
			s.WriteError(w, r, http.StatusTooManyRequests, "mfa_locked", "MFA is locked due to too many failed attempts. Try again later")
		case errors.Is(err, mfa.ErrMFANotEnrolled):
			s.WriteError(w, r, http.StatusBadRequest, "mfa_not_enrolled", "No MFA enrollment found for this type")
		case errors.Is(err, mfa.ErrReplayDetected):
			s.WriteError(w, r, http.StatusUnauthorized, "replay_detected", "This code has already been used")
		case errors.Is(err, mfa.ErrMFATokenExpired):
			s.WriteError(w, r, http.StatusUnauthorized, "otp_expired", "The OTP has expired, request a new one")
		case errors.Is(err, mfa.ErrMaxOTPAttempts):
			s.WriteError(w, r, http.StatusTooManyRequests, "max_attempts", "Maximum OTP attempts exceeded, request a new code")
		default:
			s.logger.Error("mfa challenge failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// MFA verified — consume the token and issue access + refresh tokens.
	_, err = s.mfaSvc.ConsumeMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		s.logger.Error("failed to consume mfa token", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	// Complete login: create session and issue tokens.
	s.completeMFALogin(w, r, tokenData.ProjectID, tokenData, req.Type)
}

// handleMFARecovery handles recovery code usage during MFA challenge.
func (s *Server) handleMFARecovery(w http.ResponseWriter, r *http.Request) {
	var req mfaRecoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.MFAToken == "" {
		s.WriteError(w, r, http.StatusBadRequest, "mfa_token_required", "MFA token is required")
		return
	}
	if req.Code == "" {
		s.WriteError(w, r, http.StatusBadRequest, "code_required", "Recovery code is required")
		return
	}

	// Atomically consume MFA token FIRST to prevent TOCTOU race (single-use).
	tokenData, err := s.mfaSvc.ConsumeMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrMFATokenInvalid):
			s.WriteError(w, r, http.StatusUnauthorized, "mfa_token_invalid", "MFA token is invalid or expired")
		default:
			s.logger.Error("mfa token consumption failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// Use recovery code. Use tokenData.ProjectID for consistency.
	err = s.mfaSvc.UseRecoveryCode(r.Context(), tokenData.ProjectID, tokenData.UserID, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrInvalidCode):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_code", "The recovery code is incorrect")
		case errors.Is(err, mfa.ErrMFALockout):
			s.WriteError(w, r, http.StatusTooManyRequests, "mfa_locked", "MFA is locked due to too many failed attempts. Try again later")
		case errors.Is(err, mfa.ErrNoRecoveryCodesLeft):
			s.WriteError(w, r, http.StatusBadRequest, "no_recovery_codes", "No recovery codes remaining")
		default:
			s.logger.Error("mfa recovery failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// Complete login with aal1 (recovery code = single factor bypass).
	s.completeMFALogin(w, r, tokenData.ProjectID, tokenData, "recovery")
}

// handleMFAFactors lists enrolled MFA factors.
func (s *Server) handleMFAFactors(w http.ResponseWriter, r *http.Request) {
	claims := s.extractBearerClaims(w, r)
	if claims == nil {
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	factors, err := s.mfaSvc.ListFactors(r.Context(), projectID, claims.Subject)
	if err != nil {
		s.logger.Error("list mfa factors failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]any{"factors": factors})
}

// handleMFARemoveFactor removes an MFA factor. Requires re-authentication.
func (s *Server) handleMFARemoveFactor(w http.ResponseWriter, r *http.Request) {
	var req mfaRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.CurrentPassword == "" {
		s.WriteError(w, r, http.StatusBadRequest, "password_required", "Current password is required for re-authentication")
		return
	}

	claims := s.extractBearerClaims(w, r)
	if claims == nil {
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())
	factorID := chi.URLParam(r, "id")

	// Re-authenticate: verify current password.
	if err := s.authSvc.VerifyPassword(r.Context(), projectID, claims.Subject, req.CurrentPassword); err != nil {
		s.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "Current password is incorrect")
		return
	}

	err := s.mfaSvc.RemoveFactor(r.Context(), projectID, claims.Subject, factorID)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrMFANotEnrolled):
			s.WriteError(w, r, http.StatusNotFound, "mfa_not_found", "MFA enrollment not found")
		default:
			s.logger.Error("remove mfa factor failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// handleMFARegenerateRecoveryCodes regenerates recovery codes.
func (s *Server) handleMFARegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	claims := s.extractBearerClaims(w, r)
	if claims == nil {
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	codes, err := s.mfaSvc.RegenerateRecoveryCodes(r.Context(), projectID, claims.Subject)
	if err != nil {
		s.logger.Error("regenerate recovery codes failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handleMFAEmailEnroll handles email OTP enrollment.
func (s *Server) handleMFAEmailEnroll(w http.ResponseWriter, r *http.Request) {
	claims := s.extractBearerClaims(w, r)
	if claims == nil {
		return
	}

	projectID := apikey.ProjectIDFromContext(r.Context())

	err := s.mfaSvc.EnrollEmail(r.Context(), projectID, claims.Subject)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrMFAAlreadyVerified):
			s.WriteError(w, r, http.StatusConflict, "mfa_already_enrolled", "Email OTP MFA is already enrolled")
		case errors.Is(err, mfa.ErrEmailNotVerified):
			s.WriteError(w, r, http.StatusBadRequest, "email_not_verified", "Email must be verified before enrolling email OTP")
		default:
			s.logger.Error("email otp enrollment failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "enrolled"})
}

// handleMFAEmailChallenge sends an email OTP for MFA challenge.
func (s *Server) handleMFAEmailChallenge(w http.ResponseWriter, r *http.Request) {
	var req mfaEmailChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.MFAToken == "" {
		s.WriteError(w, r, http.StatusBadRequest, "mfa_token_required", "MFA token is required")
		return
	}

	// Validate MFA token.
	tokenData, err := s.mfaSvc.ValidateMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrMFATokenInvalid):
			s.WriteError(w, r, http.StatusUnauthorized, "mfa_token_invalid", "MFA token is invalid or expired")
		default:
			s.logger.Error("mfa token validation failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// Get user email. Use tokenData.ProjectID for consistency.
	userEmail, err := s.mfaSvc.GetDecryptedEmail(r.Context(), tokenData.ProjectID, tokenData.UserID)
	if err != nil {
		s.logger.Error("failed to get user email for OTP", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	// Send OTP.
	err = s.mfaSvc.SendEmailChallenge(r.Context(), tokenData.ProjectID, tokenData.UserID, userEmail)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrMFANotEnrolled):
			s.WriteError(w, r, http.StatusBadRequest, "mfa_not_enrolled", "Email OTP is not enrolled for this user")
		default:
			s.logger.Error("send email otp failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// handleMFAEmailVerify verifies an email OTP during MFA challenge.
func (s *Server) handleMFAEmailVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaEmailVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.MFAToken == "" {
		s.WriteError(w, r, http.StatusBadRequest, "mfa_token_required", "MFA token is required")
		return
	}
	if req.Code == "" {
		s.WriteError(w, r, http.StatusBadRequest, "code_required", "Verification code is required")
		return
	}

	// Validate MFA token.
	tokenData, err := s.mfaSvc.ValidateMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrMFATokenInvalid):
			s.WriteError(w, r, http.StatusUnauthorized, "mfa_token_invalid", "MFA token is invalid or expired")
		default:
			s.logger.Error("mfa token validation failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// Verify code. Use tokenData.ProjectID for consistency.
	err = s.mfaSvc.VerifyEmailChallenge(r.Context(), tokenData.ProjectID, tokenData.UserID, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, mfa.ErrInvalidCode):
			s.WriteError(w, r, http.StatusUnauthorized, "invalid_code", "The verification code is incorrect")
		case errors.Is(err, mfa.ErrMFALockout):
			s.WriteError(w, r, http.StatusTooManyRequests, "mfa_locked", "MFA is locked due to too many failed attempts")
		case errors.Is(err, mfa.ErrMFATokenExpired):
			s.WriteError(w, r, http.StatusUnauthorized, "otp_expired", "The OTP has expired, request a new one")
		case errors.Is(err, mfa.ErrMaxOTPAttempts):
			s.WriteError(w, r, http.StatusTooManyRequests, "max_attempts", "Maximum OTP attempts exceeded, request a new code")
		default:
			s.logger.Error("email otp verify failed", "error", err)
			s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
		return
	}

	// Consume MFA token and complete login.
	_, err = s.mfaSvc.ConsumeMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		s.logger.Error("failed to consume mfa token", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.completeMFALogin(w, r, tokenData.ProjectID, tokenData, "email")
}

// completeMFALogin creates a session and issues tokens after successful MFA verification.
func (s *Server) completeMFALogin(w http.ResponseWriter, r *http.Request, projectID string, tokenData *mfa.TokenData, mfaType string) {
	now := time.Now()

	// Determine ACR and AMR based on MFA type.
	acr := "aal2"
	amr := []string{"pwd", "otp"}
	if mfaType == "recovery" {
		// Recovery code = single factor bypass, not aal2.
		acr = "aal1"
		amr = []string{"pwd", "recovery"}
	}

	idleTimeout, absTimeout := session.AALTimeouts(acr)

	var idleTimeoutAt pgtype.Timestamptz
	if idleTimeout > 0 {
		idleTimeoutAt = pgtype.Timestamptz{Time: now.Add(idleTimeout), Valid: true}
	}

	sessionID := id.New("sess_")
	amrJSON, _ := json.Marshal(amr)

	q := s.newQueries()
	_, err := q.CreateSession(r.Context(), sqlc.CreateSessionParams{
		ID:            sessionID,
		ProjectID:     projectID,
		UserID:        tokenData.UserID,
		Ip:            strPtr(tokenData.IP),
		UserAgent:     strPtr(tokenData.UserAgent),
		Acr:           acr,
		Amr:           amrJSON,
		IdleTimeoutAt: idleTimeoutAt,
		AbsTimeoutAt:  pgtype.Timestamptz{Time: now.Add(absTimeout), Valid: true},
	})
	if err != nil {
		s.logger.Error("create session after MFA failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	// Update last_login_at.
	if err := q.UpdateUserLastLogin(r.Context(), sqlc.UpdateUserLastLoginParams{
		ID:        tokenData.UserID,
		ProjectID: projectID,
	}); err != nil {
		s.logger.Error("update last login after MFA failed", "error", err)
	}

	// Issue JWT access token.
	accessToken, err := s.jwtSvc.Issue(&token.IssueParams{
		UserID:    tokenData.UserID,
		SessionID: sessionID,
		ProjectID: projectID,
		AuthTime:  now,
		ACR:       acr,
		AMR:       amr,
	})
	if err != nil {
		s.logger.Error("issue access token after MFA failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	// Issue refresh token.
	refreshToken, err := s.refreshSvc.Issue(r.Context(), tokenData.UserID, sessionID, projectID)
	if err != nil {
		s.logger.Error("issue refresh token after MFA failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    1800,
	})
}

// strPtr returns a pointer to the string, or nil if empty.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
