package email

// Config holds email service configuration.
type Config struct {
	Provider string     `koanf:"provider"` // "console" or "smtp"
	From     string     `koanf:"from"`
	SMTP     SMTPConfig `koanf:"smtp"`
}

// SMTPConfig holds SMTP-specific configuration.
type SMTPConfig struct {
	Host     string `koanf:"host"`
	Port     int    `koanf:"port"`
	Username string `koanf:"username"`
	Password string `koanf:"password"`
}
