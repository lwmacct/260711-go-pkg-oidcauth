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
	Issuer        string        `json:"issuer"          desc:"OIDC issuer URL"`
	ClientID      string        `json:"client-id"       desc:"OIDC client ID"`
	ClientSecret  string        `json:"client-secret"   desc:"OIDC confidential client secret；public client 留空"`
	CallbackURL   string        `json:"callback-url"    desc:"OIDC callback URL"`
	PublicURL     string        `json:"public-url"      desc:"浏览器访问应用的公开 URL"`
	AfterLoginURL string        `json:"after-login-url" desc:"登录成功后的同源跳转 URL"`
	SessionTTL    time.Duration `json:"session-ttl"     desc:"身份 Cookie 最长有效时间"`
}

func (c Config) Validate() (Config, error) {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.ClientSecret = strings.TrimSpace(c.ClientSecret)
	c.CallbackURL = strings.TrimSpace(c.CallbackURL)
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")
	c.AfterLoginURL = strings.TrimSpace(c.AfterLoginURL)
	if c.AfterLoginURL == "" && c.PublicURL != "" {
		c.AfterLoginURL = c.PublicURL + "/"
	}
	if c.Issuer == "" || c.ClientID == "" || c.CallbackURL == "" || c.PublicURL == "" || c.SessionTTL <= 0 {
		return c, ErrInvalidConfig
	}
	issuer, err := parseSecureURL(c.Issuer, false)
	if err != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return c, fmt.Errorf("%w: issuer", ErrInvalidConfig)
	}
	callback, err := parseSecureURL(c.CallbackURL, true)
	if err != nil || callback.RawQuery != "" || callback.Fragment != "" {
		return c, fmt.Errorf("%w: callback URL", ErrInvalidConfig)
	}
	publicURL, err := parseSecureURL(c.PublicURL, true)
	if err != nil || publicURL.RawQuery != "" || publicURL.Fragment != "" || publicURL.Path != "" {
		return c, fmt.Errorf("%w: public URL", ErrInvalidConfig)
	}
	afterLogin, err := url.Parse(c.AfterLoginURL)
	if err != nil || afterLogin.Scheme != publicURL.Scheme || afterLogin.Host != publicURL.Host {
		return c, fmt.Errorf("%w: after-login URL must be same-origin", ErrInvalidConfig)
	}
	if callback.Scheme != publicURL.Scheme || !strings.EqualFold(callback.Hostname(), publicURL.Hostname()) {
		return c, fmt.Errorf("%w: callback and public URL must share scheme and hostname", ErrInvalidConfig)
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
