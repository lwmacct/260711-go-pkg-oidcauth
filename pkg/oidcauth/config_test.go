package oidcauth

import (
	"errors"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	valid := Config{
		Issuer:        "https://auth.example.com/",
		ClientID:      "tool",
		CallbackURL:   "https://tool.example.com/auth/callback",
		PublicURL:     "https://tool.example.com/",
		AfterLoginURL: "https://tool.example.com/#/console",
		SessionTTL:    time.Hour,
	}
	validated, err := valid.Validate()
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if validated.Issuer != "https://auth.example.com" || validated.PublicURL != "https://tool.example.com" {
		t.Fatalf("config was not normalized: %#v", validated)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "http issuer", mutate: func(c *Config) { c.Issuer = "http://auth.example.com" }},
		{name: "remote http callback", mutate: func(c *Config) { c.CallbackURL = "http://tool.example.com/auth/callback" }},
		{name: "different callback host", mutate: func(c *Config) { c.CallbackURL = "https://other.example.com/auth/callback" }},
		{name: "cross-origin redirect", mutate: func(c *Config) { c.AfterLoginURL = "https://evil.example.com/" }},
		{name: "zero ttl", mutate: func(c *Config) { c.SessionTTL = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected invalid config, got %v", err)
			}
		})
	}
}

func TestConfigAllowsLoopbackHTTPWithDifferentPorts(t *testing.T) {
	_, err := (Config{
		Issuer:      "https://auth.example.com",
		ClientID:    "tool-local",
		CallbackURL: "http://localhost:8080/auth/callback",
		PublicURL:   "http://localhost:5173",
		SessionTTL:  time.Hour,
	}).Validate()
	if err != nil {
		t.Fatalf("validate loopback config: %v", err)
	}
}
