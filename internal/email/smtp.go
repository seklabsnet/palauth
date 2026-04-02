package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"strings"
)

// SMTPSender sends emails via SMTP.
type SMTPSender struct {
	cfg    *SMTPConfig
	from   string
	logger *slog.Logger
}

// NewSMTPSender creates a new SMTPSender.
func NewSMTPSender(cfg *SMTPConfig, from string, logger *slog.Logger) (*SMTPSender, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("smtp host is required")
	}
	if cfg.Port == 0 {
		return nil, fmt.Errorf("smtp port is required")
	}
	if from == "" {
		return nil, fmt.Errorf("from address is required")
	}
	return &SMTPSender{cfg: cfg, from: from, logger: logger}, nil
}

// Send sends an email via SMTP with proper MIME multipart.
func (s *SMTPSender) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	addr := net.JoinHostPort(s.cfg.Host, fmt.Sprintf("%d", s.cfg.Port))

	msg := buildMIMEMessage(s.from, to, subject, htmlBody, textBody)

	var c *smtp.Client
	var err error

	if s.cfg.Port == 465 {
		// Direct TLS (implicit TLS).
		tlsConfig := &tls.Config{
			ServerName: s.cfg.Host,
			MinVersion: tls.VersionTLS12,
		}
		dialer := &tls.Dialer{Config: tlsConfig}
		conn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			return fmt.Errorf("smtp tls dial: %w", dialErr)
		}
		c, err = smtp.NewClient(conn, s.cfg.Host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("smtp new client: %w", err)
		}
	} else {
		// STARTTLS (port 587 or others).
		c, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		tlsConfig := &tls.Config{
			ServerName: s.cfg.Host,
			MinVersion: tls.VersionTLS12,
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			c.Close()
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	defer c.Close()

	// Authenticate if credentials provided.
	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := c.Mail(s.from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}

	if err := c.Quit(); err != nil {
		s.logger.Warn("smtp quit error (non-fatal)", "error", err)
	}

	s.logger.Debug("email sent via SMTP", "to", to, "subject", subject)
	return nil
}

// generateBoundary creates a unique MIME boundary using crypto/rand.
func generateBoundary() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) //nolint:errcheck // fallback is still unique enough
	return "palauth-" + hex.EncodeToString(b)
}

// sanitizeHeaderValue strips CRLF characters to prevent email header injection (CWE-93).
func sanitizeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

// buildMIMEMessage constructs a multipart/alternative MIME message with plaintext and HTML parts.
func buildMIMEMessage(from, to, subject, htmlBody, textBody string) string {
	boundary := generateBoundary()

	var b strings.Builder
	b.WriteString("From: " + sanitizeHeaderValue(from) + "\r\n")
	b.WriteString("To: " + sanitizeHeaderValue(to) + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n")
	b.WriteString("\r\n")

	// Plaintext part.
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("\r\n")
	b.WriteString(textBody)
	b.WriteString("\r\n")

	// HTML part.
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("\r\n")
	b.WriteString(htmlBody)
	b.WriteString("\r\n")

	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}
