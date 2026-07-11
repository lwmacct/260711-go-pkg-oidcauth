package oidcauth

import (
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type Options struct {
	Logger         *slog.Logger
	HTTPClient     *http.Client
	IdentityMapper IdentityMapper
	Authorizer     Authorizer
	FlowStore      FlowStore
	PathPrefix     string
	FlowTTL        time.Duration
	CookieName     string
	FlowCookieName string
	ExtraScopes    []string
	Random         io.Reader
	Now            func() time.Time
}

func defaultOptions(options Options) Options {
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}
	if options.PathPrefix == "" {
		options.PathPrefix = "/auth"
	}
	if options.FlowTTL <= 0 {
		options.FlowTTL = 5 * time.Minute
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.FlowStore == nil {
		store := NewMemoryFlowStore()
		store.now = options.Now
		options.FlowStore = store
	}
	return options
}
