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
	Issuer       string        `json:"issuer"         desc:"OIDC issuer URL"`
	ClientID     string        `json:"client-id"       desc:"OIDC client ID"`
	ClientSecret string        `json:"client-secret"   desc:"OIDC confidential client secret；public client 留空"`
	ExternalURLs []string      `json:"external-urls"   desc:"允许浏览器访问应用的可信 origin"`
	SessionTTL   time.Duration `json:"session-ttl"     desc:"身份 Cookie 最长有效时间"`
}

func (c Config) Validate() (Config, error) {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	if c.Issuer == "" || c.ClientID == "" || len(c.ExternalURLs) == 0 || c.SessionTTL <= 0 {
		return c, ErrInvalidConfig
	}
	issuer, err := parseSecureURL(c.Issuer, false)
	if err != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return c, fmt.Errorf("%w: issuer", ErrInvalidConfig)
	}
	secure := false
	hosts := make(map[string]struct{}, len(c.ExternalURLs))
	for i, value := range c.ExternalURLs {
		value = strings.TrimRight(strings.TrimSpace(value), "/")
		externalURL, err := parseSecureURL(value, true)
		if err != nil || externalURL.RawQuery != "" || externalURL.Fragment != "" || externalURL.Path != "" || externalURL.User != nil {
			return c, fmt.Errorf("%w: external URL", ErrInvalidConfig)
		}
		if i == 0 {
			secure = externalURL.Scheme == "https"
		} else if secure != (externalURL.Scheme == "https") {
			return c, fmt.Errorf("%w: external URLs must use the same scheme", ErrInvalidConfig)
		}
		host := strings.ToLower(externalURL.Host)
		if _, exists := hosts[host]; exists {
			return c, fmt.Errorf("%w: duplicate external URL host", ErrInvalidConfig)
		}
		hosts[host] = struct{}{}
		c.ExternalURLs[i] = value
	}
	return c, nil
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
