package oidcauth_test

import (
	"fmt"
	"time"

	"github.com/lwmacct/260711-go-pkg-oidcauth/pkg/oidcauth/dexgithub"
)

func Example() {
	config, err := (dexgithub.Config{
		Issuer:       "https://auth.example.com",
		ClientID:     "tool-local",
		ExternalURLs: []string{"http://localhost:5173"},
		AllowedUsers: []string{"octocat"},
		SessionTTL:   24 * time.Hour,
	}).Validate()
	if err != nil {
		fmt.Println("configure OIDC auth failed")
		return
	}
	fmt.Println(config.AllowedUsers[0])

	// Output:
	// octocat
}
