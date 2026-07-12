package dexgithub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lwmacct/260711-go-pkg-oidcauth/pkg/oidcauth"
)

type Config struct {
	Issuer       string        `json:"issuer"         desc:"Dex issuer URL"`
	ClientID     string        `json:"client-id"       desc:"Dex OIDC client ID"`
	ClientSecret string        `json:"client-secret"   desc:"Dex confidential client secret；public client 留空"`
	ExternalURLs []string      `json:"external-urls"   desc:"允许浏览器访问应用的可信 origin"`
	AllowedUsers []string      `json:"allowed-users"   desc:"允许访问应用的 GitHub 用户名"`
	SessionTTL   time.Duration `json:"session-ttl"      desc:"身份 Cookie 最长有效时间"`
}

type Options struct {
	oidcauth.Options
}

func (c Config) Validate() (Config, error) {
	_, err := normalizeAllowedUsers(c.AllowedUsers)
	if err != nil {
		return c, err
	}
	core, err := c.core().Validate()
	if err != nil {
		return c, err
	}
	c.Issuer = core.Issuer
	c.ClientID = core.ClientID
	c.ClientSecret = core.ClientSecret
	c.ExternalURLs = core.ExternalURLs
	c.SessionTTL = core.SessionTTL
	for i := range c.AllowedUsers {
		c.AllowedUsers[i] = strings.ToLower(strings.TrimSpace(c.AllowedUsers[i]))
	}
	return c, nil
}

func New(ctx context.Context, config Config, options Options) (*oidcauth.Auth, error) {
	config, err := config.Validate()
	if err != nil {
		return nil, err
	}
	allowed, _ := normalizeAllowedUsers(config.AllowedUsers)
	core := config.core()
	coreOptions := options.Options
	coreOptions.IdentityMapper = Mapper{}
	coreOptions.Authorizer = UsernameAuthorizer{allowed: allowed}
	coreOptions.ExtraScopes = append(coreOptions.ExtraScopes, "federated:id")
	return oidcauth.New(ctx, core, coreOptions)
}

func (c Config) core() oidcauth.Config {
	return oidcauth.Config{
		Issuer:       c.Issuer,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		ExternalURLs: c.ExternalURLs,
		SessionTTL:   c.SessionTTL,
	}
}

type Mapper struct{}

type claims struct {
	Subject           string `json:"sub"`
	Username          string `json:"preferred_username"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	FederatedIdentity struct {
		ConnectorID string `json:"connector_id"`
		UserID      string `json:"user_id"`
	} `json:"federated_claims"`
}

func (Mapper) MapIdentity(_ context.Context, raw json.RawMessage) (oidcauth.Identity, error) {
	var value claims
	if err := json.Unmarshal(raw, &value); err != nil {
		return oidcauth.Identity{}, err
	}
	value.Username = strings.TrimSpace(value.Username)
	value.FederatedIdentity.UserID = strings.TrimSpace(value.FederatedIdentity.UserID)
	if value.Subject == "" || value.Username == "" || value.FederatedIdentity.ConnectorID != "github" || value.FederatedIdentity.UserID == "" {
		return oidcauth.Identity{}, errors.New("required Dex GitHub identity claims missing")
	}
	return oidcauth.Identity{
		Subject:        value.Subject,
		Username:       value.Username,
		Name:           value.Name,
		Email:          value.Email,
		AvatarURL:      "https://avatars.githubusercontent.com/u/" + url.PathEscape(value.FederatedIdentity.UserID) + "?v=4",
		Provider:       "github",
		ProviderUserID: value.FederatedIdentity.UserID,
	}, nil
}

type UsernameAuthorizer struct {
	allowed map[string]struct{}
}

func (a UsernameAuthorizer) Authorize(_ context.Context, identity oidcauth.Identity) error {
	if _, ok := a.allowed[strings.ToLower(strings.TrimSpace(identity.Username))]; !ok {
		return oidcauth.ErrForbidden
	}
	return nil
}

func normalizeAllowedUsers(values []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(values))
	for _, value := range values {
		username := strings.ToLower(strings.TrimSpace(value))
		if username == "" {
			return nil, fmt.Errorf("%w: allowed GitHub username", oidcauth.ErrInvalidConfig)
		}
		if _, exists := allowed[username]; exists {
			return nil, fmt.Errorf("%w: duplicate allowed GitHub username %q", oidcauth.ErrInvalidConfig, username)
		}
		allowed[username] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: allowed GitHub users are required", oidcauth.ErrInvalidConfig)
	}
	return allowed, nil
}
