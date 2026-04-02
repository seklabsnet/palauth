package auth

import (
	"context"
	"fmt"

	"github.com/palauth/palauth/internal/crypto"
	"github.com/palauth/palauth/internal/database/sqlc"
	"github.com/palauth/palauth/internal/email"
)

// sendVerificationEmail sends a verification email (link or code) to the user.
func (s *Service) sendVerificationEmail(ctx context.Context, toEmail, projectName, verificationMethod, token, code string) {
	if s.emailSender == nil || s.emailRenderer == nil {
		return
	}

	var (
		tt      email.TemplateType
		subject string
		data    *email.TemplateData
	)

	switch verificationMethod {
	case "link":
		tt = email.TemplateVerificationLink
		subject = "Verify your email address"
		data = &email.TemplateData{
			ProjectName:   projectName,
			UserEmail:     toEmail,
			Token:         token,
			Link:          token, // TODO(T1.X): construct full verification URL from project base URL config
			ExpiryMinutes: 1440, // 24 hours
		}
	default: // "code" or "otp"
		tt = email.TemplateVerificationCode
		subject = "Your verification code"
		data = &email.TemplateData{
			ProjectName:   projectName,
			UserEmail:     toEmail,
			Code:          code,
			ExpiryMinutes: 5,
		}
	}

	htmlBody, textBody, err := s.emailRenderer.Render(tt, data)
	if err != nil {
		s.logger.Error("failed to render verification email template", "error", err, "template", string(tt))
		return
	}

	if err := s.emailSender.Send(ctx, toEmail, subject, htmlBody, textBody); err != nil {
		s.logger.Error("failed to send verification email", "error", err, "to", toEmail)
	}
}

// sendPasswordResetEmail sends a password reset email with a link.
func (s *Service) sendPasswordResetEmail(ctx context.Context, toEmail, projectName, resetToken string) {
	if s.emailSender == nil || s.emailRenderer == nil {
		return
	}

	data := &email.TemplateData{
		ProjectName:   projectName,
		UserEmail:     toEmail,
		Token:         resetToken,
		Link:          resetToken, // TODO(T1.X): construct full reset URL from project base URL config
		ExpiryMinutes: 15,
	}

	htmlBody, textBody, err := s.emailRenderer.Render(email.TemplatePasswordReset, data)
	if err != nil {
		s.logger.Error("failed to render password reset email template", "error", err)
		return
	}

	subject := fmt.Sprintf("Reset your password for %s", projectName)
	if err := s.emailSender.Send(ctx, toEmail, subject, htmlBody, textBody); err != nil {
		s.logger.Error("failed to send password reset email", "error", err, "to", toEmail)
	}
}

// sendVerificationEmailForResend decrypts the user email and sends a verification email.
func (s *Service) sendVerificationEmailForResend(ctx context.Context, user *sqlc.User, projectID, projectName, method, token, code string) {
	if s.emailSender == nil || s.emailRenderer == nil {
		return
	}

	projectDEK, err := s.getOrCreateProjectDEK(ctx, sqlc.New(s.db), projectID)
	if err != nil {
		s.logger.Error("failed to get project DEK for resend email", "error", err)
		return
	}

	emailAAD := []byte("email:" + projectID)
	decryptedEmail, err := crypto.Decrypt(user.EmailEncrypted, projectDEK, emailAAD)
	if err != nil {
		s.logger.Error("failed to decrypt email for resend", "error", err)
		return
	}

	s.sendVerificationEmail(ctx, string(decryptedEmail), projectName, method, token, code)
}
