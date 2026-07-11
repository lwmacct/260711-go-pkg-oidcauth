package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
)

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
	ErrInvalidFlow     = errors.New("invalid oidc flow")
	ErrExpiredFlow     = errors.New("expired oidc flow")
)

type Identity struct {
	Subject        string `json:"subject"`
	Username       string `json:"username"`
	Name           string `json:"name,omitempty"`
	Email          string `json:"email,omitempty"`
	AvatarURL      string `json:"avatar_url,omitempty"`
	Provider       string `json:"provider,omitempty"`
	ProviderUserID string `json:"provider_user_id,omitempty"`
}

type IdentityMapper interface {
	MapIdentity(context.Context, json.RawMessage) (Identity, error)
}

type IdentityMapperFunc func(context.Context, json.RawMessage) (Identity, error)

func (f IdentityMapperFunc) MapIdentity(ctx context.Context, claims json.RawMessage) (Identity, error) {
	return f(ctx, claims)
}

type Authorizer interface {
	Authorize(context.Context, Identity) error
}

type AuthorizerFunc func(context.Context, Identity) error

func (f AuthorizerFunc) Authorize(ctx context.Context, identity Identity) error {
	return f(ctx, identity)
}

type identityContextKey struct{}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

func contextWithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}
