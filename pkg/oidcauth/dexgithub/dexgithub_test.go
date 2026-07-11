package dexgithub

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lwmacct/260711-go-pkg-oidcauth/pkg/oidcauth"
)

func TestMapperMapsDexGitHubIdentity(t *testing.T) {
	identity, err := (Mapper{}).MapIdentity(t.Context(), json.RawMessage(`{
		"sub":"subject","preferred_username":"lwmacct","name":"Name","email":"user@example.com",
		"federated_claims":{"connector_id":"github","user_id":"30756209"}
	}`))
	if err != nil {
		t.Fatalf("map identity: %v", err)
	}
	if identity.Username != "lwmacct" || identity.Provider != "github" || identity.ProviderUserID != "30756209" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestMapperRejectsOtherConnector(t *testing.T) {
	_, err := (Mapper{}).MapIdentity(t.Context(), json.RawMessage(`{
		"sub":"subject","preferred_username":"lwmacct",
		"federated_claims":{"connector_id":"gitlab","user_id":"30756209"}
	}`))
	if err == nil {
		t.Fatal("expected non-GitHub connector to fail")
	}
}

func TestUsernameAuthorizerMatchesNormalizedUsername(t *testing.T) {
	allowed, err := normalizeAllowedUsers([]string{" LwMacct "})
	if err != nil {
		t.Fatalf("normalize users: %v", err)
	}
	authorizer := UsernameAuthorizer{allowed: allowed}
	if err := authorizer.Authorize(context.Background(), oidcauth.Identity{Username: "LWMACCT"}); err != nil {
		t.Fatalf("authorize username: %v", err)
	}
	if err := authorizer.Authorize(context.Background(), oidcauth.Identity{Username: "visitor"}); !errors.Is(err, oidcauth.ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestAllowedUsersRejectsDuplicates(t *testing.T) {
	if _, err := normalizeAllowedUsers([]string{"lwmacct", " LwMacct "}); !errors.Is(err, oidcauth.ErrInvalidConfig) {
		t.Fatalf("expected invalid config, got %v", err)
	}
}
