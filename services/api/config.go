package main

import (
	"log/slog"
	"os"
	"time"
)

// Config holds every setting; all come from environment variables (12-factor).
// Secrets are NEVER hard-coded: inject them via your platform's secret manager.
type Config struct {
	Addr         string
	DatabaseURL  string
	JWTSecret    string        // HS256 signing key shared with the MCP + agent services
	TokenTTL     time.Duration // short-lived access tokens limit damage if one leaks
	SlackWebhook string        // optional third-party integration
	DataDir      string        // where seed CSVs live
}

func loadConfig() Config {
	c := Config{
		Addr:         env("ADDR", ":8080"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		JWTSecret:    os.Getenv("JWT_SECRET"),
		TokenTTL:     15 * time.Minute,
		SlackWebhook: os.Getenv("SLACK_WEBHOOK_URL"),
		DataDir:      env("DATA_DIR", "/data"),
	}
	// Fail fast on insecure configuration instead of running unsafely.
	if c.DatabaseURL == "" {
		fatal("DATABASE_URL is required", nil)
	}
	if len(c.JWTSecret) < 32 {
		fatal("JWT_SECRET must be at least 32 characters", nil)
	}
	return c
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(msg string, err error) {
	slog.Error(msg, "err", err)
	os.Exit(1)
}
