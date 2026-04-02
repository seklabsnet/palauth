package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/palauth/palauth/internal/email"
)

type Config struct {
	Server   ServerConfig   `koanf:"server"`
	Database DatabaseConfig `koanf:"database"`
	Redis    RedisConfig    `koanf:"redis"`
	Auth     AuthConfig     `koanf:"auth"`
	Email    email.Config   `koanf:"email"`
	Log      LogConfig      `koanf:"log"`
	FIPS     bool           `koanf:"fips"`
}

type ServerConfig struct {
	Port               int      `koanf:"port"`
	Host               string   `koanf:"host"`
	CORSAllowedOrigins []string `koanf:"cors_allowed_origins"`
}

type DatabaseConfig struct {
	URL             string `koanf:"url"`
	MaxOpenConns    int    `koanf:"max_open_conns"`
	MaxIdleConns    int    `koanf:"max_idle_conns"`
	ConnMaxLifetime int    `koanf:"conn_max_lifetime"`
}

type RedisConfig struct {
	URL          string `koanf:"url"`
	PoolSize     int    `koanf:"pool_size"`
	MinIdleConns int    `koanf:"min_idle_conns"`
}

type AuthConfig struct {
	Pepper           string `koanf:"pepper"`
	PasswordMinLen   int    `koanf:"password_min_length"`
	PasswordMaxLen   int    `koanf:"password_max_length"`
	AccessTokenTTL   int    `koanf:"access_token_ttl"`
	RefreshTokenTTL  int    `koanf:"refresh_token_ttl"`
	LockoutThreshold int    `koanf:"lockout_threshold"`
	LockoutDuration  int    `koanf:"lockout_duration"`
	MFALockout       int    `koanf:"mfa_lockout_threshold"`
	InactiveDays     int    `koanf:"inactive_days"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

func Load(configPath string) (*Config, error) {
	k := koanf.New(".")

	// Defaults
	defaults := map[string]any{
		"server.port":                 3000,
		"server.host":                 "0.0.0.0",
		"server.cors_allowed_origins": []string{"http://localhost:3001"},
		"database.max_open_conns":  25,
		"database.max_idle_conns":  5,
		"database.conn_max_lifetime": 300,
		"auth.password_min_length": 15,
		"auth.password_max_length": 64,
		"auth.access_token_ttl":    1800,
		"auth.refresh_token_ttl":   2592000,
		"auth.lockout_threshold":   10,
		"auth.lockout_duration":    1800,
		"auth.mfa_lockout_threshold": 5,
		"auth.inactive_days":       90,
		"redis.pool_size":          10,
		"redis.min_idle_conns":     2,
		"email.provider":           "console",
		"log.level":                "info",
		"log.format":               "json",
	}
	for key, val := range defaults {
		if err := k.Set(key, val); err != nil {
			return nil, fmt.Errorf("setting default %s: %w", key, err)
		}
	}

	// YAML config file (optional)
	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("loading config file: %w", err)
		}
	}

	// Environment variables: PALAUTH_SERVER_PORT -> server.port
	// Only the first underscore after prefix is a level separator.
	// PALAUTH_AUTH_PEPPER -> auth.pepper
	// PALAUTH_AUTH_PASSWORD_MIN_LENGTH -> auth.password_min_length
	if err := k.Load(env.Provider("PALAUTH_", ".", func(s string) string {
		key := strings.ToLower(strings.TrimPrefix(s, "PALAUTH_"))
		// Split on first underscore only: "auth_pepper" -> "auth" + "pepper"
		if idx := strings.Index(key, "_"); idx != -1 {
			return key[:idx] + "." + key[idx+1:]
		}
		return key
	}), nil); err != nil {
		return nil, fmt.Errorf("loading env vars: %w", err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Auth.Pepper == "" {
		return errors.New("PALAUTH_PEPPER is required — server cannot start without it")
	}
	if len(c.Auth.Pepper) < 32 {
		return fmt.Errorf("PALAUTH_PEPPER must be at least 32 bytes, got %d", len(c.Auth.Pepper))
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	for _, origin := range c.Server.CORSAllowedOrigins {
		if origin == "*" {
			return errors.New("wildcard CORS origin '*' is not allowed")
		}
	}
	return nil
}
