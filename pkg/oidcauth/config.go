package oidcauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidConfig = errors.New("invalid oidc auth config")

type Config struct {
	Issuer       string        `json:"issuer"        desc:"OIDC issuer URL"`
	ClientID     string        `json:"client-id"      desc:"OIDC client ID"`
	ClientSecret string        `json:"client-secret"  desc:"OIDC confidential client secret；public client 留空"`
	ExternalURL  string        `json:"external-url"   desc:"浏览器访问应用的外部 origin"`
	SessionTTL   time.Duration `json:"session-ttl"    desc:"身份 Cookie 最长有效时间"`
}

func (c Config) Validate() (Config, error) {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	c.ExternalURL = strings.TrimRight(strings.TrimSpace(c.ExternalURL), "/")
	if c.Issuer == "" || c.ClientID == "" || c.ExternalURL == "" || c.SessionTTL <= 0 {
		return c, ErrInvalidConfig
	}
	issuer, err := parseSecureURL(c.Issuer, false)
	if err != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return c, fmt.Errorf("%w: issuer", ErrInvalidConfig)
	}
	externalURL, err := parseSecureURL(c.ExternalURL, true)
	if err != nil || externalURL.RawQuery != "" || externalURL.Fragment != "" || externalURL.Path != "" {
		return c, fmt.Errorf("%w: external URL", ErrInvalidConfig)
	}
	return c, nil
}

func (c Config) callbackURL(pathPrefix string) string {
	return c.ExternalURL + strings.TrimRight(pathPrefix, "/") + "/callback"
}

func parseSecureURL(value string, allowLoopbackHTTP bool) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return nil, ErrInvalidConfig
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if allowLoopbackHTTP && parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1") {
		return parsed, nil
	}
	return nil, ErrInvalidConfig
}
