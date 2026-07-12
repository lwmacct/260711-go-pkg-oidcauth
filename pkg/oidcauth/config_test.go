package oidcauth

import (
	"errors"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	valid := Config{
		Issuer:       "https://auth.example.com/",
		ClientID:     "tool",
		ExternalURLs: []string{"https://tool.example.com/", "https://tool-alt.example.com/"},
		SessionTTL:   time.Hour,
	}
	validated, err := valid.Validate()
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if validated.Issuer != "https://auth.example.com" || validated.ExternalURLs[0] != "https://tool.example.com" || validated.ExternalURLs[1] != "https://tool-alt.example.com" {
		t.Fatalf("config was not normalized: %#v", validated)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "http issuer", mutate: func(c *Config) { c.Issuer = "http://auth.example.com" }},
		{name: "missing external URLs", mutate: func(c *Config) { c.ExternalURLs = nil }},
		{name: "remote http external URL", mutate: func(c *Config) { c.ExternalURLs = []string{"http://tool.example.com"} }},
		{name: "external URL path", mutate: func(c *Config) { c.ExternalURLs = []string{"https://tool.example.com/app"} }},
		{name: "duplicate external URL host", mutate: func(c *Config) { c.ExternalURLs = []string{"https://tool.example.com", "https://tool.example.com/"} }},
		{name: "mixed external URL schemes", mutate: func(c *Config) { c.ExternalURLs = []string{"https://tool.example.com", "http://localhost:5173"} }},
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
		Issuer:       "https://auth.example.com",
		ClientID:     "tool-local",
		ExternalURLs: []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		SessionTTL:   time.Hour,
	}).Validate()
	if err != nil {
		t.Fatalf("validate loopback config: %v", err)
	}
}
