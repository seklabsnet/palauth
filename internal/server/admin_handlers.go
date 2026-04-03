package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/palauth/palauth/internal/admin"
	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
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

type adminMFARequiredResponse struct {
	MFARequired bool     `json:"mfa_required"`
	MFAEnrolled bool     `json:"mfa_enrolled"`
	MFAToken    string   `json:"mfa_token"`
	Factors     []string `json:"factors,omitempty"`
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

	ip := r.RemoteAddr
	userAgent := r.UserAgent()

	token, err := s.adminSvc.Login(r.Context(), req.Email, req.Password, ip, userAgent)
	if err != nil {
		var mfaErr *admin.MFARequiredError
		if errors.As(err, &mfaErr) {
			resp := adminMFARequiredResponse{
				MFARequired: true,
				MFAEnrolled: mfaErr.MFAEnrolled,
				MFAToken:    mfaErr.MFAToken,
			}
			// If MFA is enrolled, list the factor types.
			if mfaErr.MFAEnrolled && s.mfaSvc != nil {
				_, factors, fErr := s.mfaSvc.HasMFA(r.Context(), admin.AdminProjectID, mfaErr.AdminID)
				if fErr == nil {
					resp.Factors = factors
				}
			}
			s.WriteJSON(w, http.StatusOK, resp)
			return
		}

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

// handleAdminMFAEnroll enrolls an admin in TOTP MFA during the forced enrollment flow.
// Requires a valid MFA token (issued at login when admin has no MFA).
func (s *Server) handleAdminMFAEnroll(w http.ResponseWriter, r *http.Request) {
	if s.mfaSvc == nil {
		s.WriteError(w, r, http.StatusServiceUnavailable, "mfa_unavailable", "MFA service is not available")
		return
	}

	var req struct {
		MFAToken string `json:"mfa_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.MFAToken == "" {
		s.WriteError(w, r, http.StatusBadRequest, "mfa_token_required", "MFA token is required")
		return
	}

	// Validate MFA token (don't consume — enrollment is multi-step).
	tokenData, err := s.mfaSvc.ValidateMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		s.WriteError(w, r, http.StatusUnauthorized, "invalid_mfa_token", "MFA token is invalid or expired")
		return
	}

	if tokenData.ProjectID != admin.AdminProjectID {
		s.WriteError(w, r, http.StatusForbidden, "invalid_mfa_token", "MFA token is not for admin")
		return
	}

	// Look up admin email for TOTP enrollment (used in QR code issuer).
	q := sqlc.New(s.db)
	adminRow, err := q.GetAdminByID(r.Context(), tokenData.UserID)
	if err != nil {
		s.logger.Error("failed to get admin for MFA enrollment", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "Failed to enroll MFA")
		return
	}

	result, err := s.mfaSvc.EnrollTOTP(r.Context(), admin.AdminProjectID, tokenData.UserID, adminRow.Email)
	if err != nil {
		s.logger.Error("admin MFA enrollment failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "Failed to enroll MFA")
		return
	}

	s.WriteJSON(w, http.StatusOK, result)
}

// handleAdminMFAVerifyEnrollment verifies the admin's first TOTP code to confirm enrollment.
func (s *Server) handleAdminMFAVerifyEnrollment(w http.ResponseWriter, r *http.Request) {
	if s.mfaSvc == nil {
		s.WriteError(w, r, http.StatusServiceUnavailable, "mfa_unavailable", "MFA service is not available")
		return
	}

	var req struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.MFAToken == "" || req.Code == "" {
		s.WriteError(w, r, http.StatusBadRequest, "missing_fields", "MFA token and code are required")
		return
	}

	tokenData, err := s.mfaSvc.ValidateMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		s.WriteError(w, r, http.StatusUnauthorized, "invalid_mfa_token", "MFA token is invalid or expired")
		return
	}

	if tokenData.ProjectID != admin.AdminProjectID {
		s.WriteError(w, r, http.StatusForbidden, "invalid_mfa_token", "MFA token is not for admin")
		return
	}

	// Atomically consume MFA token FIRST to prevent TOCTOU race.
	// Must happen before any irreversible side effects (enrollment verify, recovery codes, has_mfa update).
	_, err = s.mfaSvc.ConsumeMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		s.WriteError(w, r, http.StatusUnauthorized, "mfa_token_invalid", "MFA token is invalid or expired")
		return
	}

	// Verify TOTP enrollment.
	if err := s.mfaSvc.VerifyTOTPEnrollment(r.Context(), admin.AdminProjectID, tokenData.UserID, req.Code); err != nil {
		s.logger.Error("admin MFA verify enrollment failed", "error", err)
		s.WriteError(w, r, http.StatusBadRequest, "invalid_code", "Invalid TOTP code")
		return
	}

	// Generate recovery codes.
	recoveryCodes, err := s.mfaSvc.GenerateRecoveryCodes(r.Context(), admin.AdminProjectID, tokenData.UserID)
	if err != nil {
		s.logger.Error("admin MFA recovery code generation failed", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "Failed to generate recovery codes")
		return
	}

	// Mark admin as having MFA.
	q := sqlc.New(s.db)
	if err := q.UpdateAdminHasMFA(r.Context(), sqlc.UpdateAdminHasMFAParams{
		ID:     tokenData.UserID,
		HasMfa: true,
	}); err != nil {
		s.logger.Error("failed to update admin has_mfa", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "Failed to update MFA status")
		return
	}

	adminToken, err := s.adminSvc.IssueTokenAfterMFA(r.Context(), tokenData.UserID)
	if err != nil {
		s.logger.Error("failed to issue admin token after MFA enrollment", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "Failed to issue admin token")
		return
	}

	s.WriteJSON(w, http.StatusOK, map[string]any{
		"token":          adminToken,
		"recovery_codes": recoveryCodes,
	})
}

// handleAdminMFAChallenge verifies a TOTP code for admin login MFA challenge.
func (s *Server) handleAdminMFAChallenge(w http.ResponseWriter, r *http.Request) {
	if s.mfaSvc == nil {
		s.WriteError(w, r, http.StatusServiceUnavailable, "mfa_unavailable", "MFA service is not available")
		return
	}

	var req struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.WriteError(w, r, http.StatusBadRequest, "invalid_request", "Invalid JSON body")
		return
	}

	if req.MFAToken == "" || req.Code == "" {
		s.WriteError(w, r, http.StatusBadRequest, "missing_fields", "MFA token and code are required")
		return
	}

	tokenData, err := s.mfaSvc.ValidateMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		s.WriteError(w, r, http.StatusUnauthorized, "invalid_mfa_token", "MFA token is invalid or expired")
		return
	}

	if tokenData.ProjectID != admin.AdminProjectID {
		s.WriteError(w, r, http.StatusForbidden, "invalid_mfa_token", "MFA token is not for admin")
		return
	}

	// Atomically consume MFA token FIRST to prevent TOCTOU race.
	_, err = s.mfaSvc.ConsumeMFAToken(r.Context(), req.MFAToken)
	if err != nil {
		s.WriteError(w, r, http.StatusUnauthorized, "mfa_token_invalid", "MFA token is invalid or expired")
		return
	}

	// Validate TOTP code.
	if err := s.mfaSvc.ValidateTOTPChallenge(r.Context(), admin.AdminProjectID, tokenData.UserID, req.Code); err != nil {
		s.WriteError(w, r, http.StatusUnauthorized, "invalid_code", "Invalid TOTP code")
		return
	}

	adminToken, err := s.adminSvc.IssueTokenAfterMFA(r.Context(), tokenData.UserID)
	if err != nil {
		s.logger.Error("failed to issue admin token after MFA", "error", err)
		s.WriteError(w, r, http.StatusInternalServerError, "internal_error", "Failed to issue admin token")
		return
	}

	s.WriteJSON(w, http.StatusOK, adminLoginResponse{Token: adminToken})
}
