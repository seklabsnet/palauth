package email

import (
	"context"
	"fmt"
	"log/slog"
)

// Sender sends emails.
type Sender interface {
	Send(ctx context.Context, to, subject, htmlBody, textBody string) error
}

// NewSender creates a Sender based on config.
func NewSender(cfg *Config, logger *slog.Logger) (Sender, error) {
	switch cfg.Provider {
	case "console", "":
		return NewConsoleSender(logger), nil
	case "smtp":
		return NewSMTPSender(&cfg.SMTP, cfg.From, logger)
	default:
		return nil, fmt.Errorf("unsupported email provider: %s", cfg.Provider)
	}
}
