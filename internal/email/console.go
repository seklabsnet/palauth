package email

import (
	"context"
	"log/slog"
)

// ConsoleSender logs emails to slog instead of sending them.
// Used in development and testing.
type ConsoleSender struct {
	logger *slog.Logger
}

// NewConsoleSender creates a new ConsoleSender.
func NewConsoleSender(logger *slog.Logger) *ConsoleSender {
	return &ConsoleSender{logger: logger}
}

// Send logs the email details.
func (c *ConsoleSender) Send(_ context.Context, to, subject, htmlBody, textBody string) error {
	preview := textBody
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}

	c.logger.Info("email sent (console)",
		"to", to,
		"subject", subject,
		"body_preview", preview,
		"html_length", len(htmlBody),
		"text_length", len(textBody),
	)
	return nil
}
