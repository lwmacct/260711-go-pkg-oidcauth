package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const maxIdentityCookieBytes = 12 << 10

type Auth struct {
	config     Config
	options    Options
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	publicURL  *url.URL
	secure     bool
	cookieName string
	flowCookie string
	pathPrefix string
}

type baseClaims struct {
	IssuedAt int64 `json:"iat"`
}

func New(ctx context.Context, config Config, options Options) (*Auth, error) {
	config, err := config.Validate()
	if err != nil {
		return nil, err
	}
	options = defaultOptions(options)
	if options.IdentityMapper == nil || options.Authorizer == nil {
		return nil, fmt.Errorf("%w: identity mapper and authorizer are required", ErrInvalidConfig)
	}
	pathPrefix := strings.TrimRight(options.PathPrefix, "/")
	if pathPrefix == "" || !strings.HasPrefix(pathPrefix, "/") || strings.Contains(pathPrefix, "?") || strings.Contains(pathPrefix, "#") {
		return nil, fmt.Errorf("%w: path prefix", ErrInvalidConfig)
	}
	callbackURL, _ := url.Parse(config.CallbackURL)
	if callbackURL.Path != pathPrefix+"/callback" {
		return nil, fmt.Errorf("%w: callback path must be %s/callback", ErrInvalidConfig, pathPrefix)
	}
	providerCtx := oidc.ClientContext(ctx, options.HTTPClient)
	provider, err := oidc.NewProvider(providerCtx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}
	endpoint := provider.Endpoint()
	if config.ClientSecret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	} else {
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	callback := callbackURL
	publicURL, _ := url.Parse(config.PublicURL)
	cookieSuffix := shortHash(config.ClientID)
	cookieName := options.CookieName
	flowCookie := options.FlowCookieName
	if cookieName == "" {
		cookieName = "oidcauth_" + cookieSuffix
	}
	if flowCookie == "" {
		flowCookie = "oidcauth_flow_" + cookieSuffix
	}
	secure := callback.Scheme == "https"
	if secure {
		if options.CookieName == "" {
			cookieName = "__Host-" + cookieName
		}
		if options.FlowCookieName == "" {
			flowCookie = "__Host-" + flowCookie
		}
	}
	scopes := append([]string{oidc.ScopeOpenID, "profile"}, options.ExtraScopes...)
	return &Auth{
		config:  config,
		options: options,
		oauth: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  config.CallbackURL,
			Scopes:       scopes,
		},
		verifier:   provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		publicURL:  publicURL,
		secure:     secure,
		cookieName: cookieName,
		flowCookie: flowCookie,
		pathPrefix: pathPrefix,
	}, nil
}

func (a *Auth) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+a.pathPrefix+"/login", a.login)
	mux.HandleFunc("GET "+a.pathPrefix+"/callback", a.callback)
	mux.HandleFunc("GET "+a.pathPrefix+"/session", a.session)
	mux.HandleFunc("POST "+a.pathPrefix+"/logout", a.logout)
	return mux
}

func (a *Auth) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := a.Identity(r)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrForbidden) {
				status = http.StatusForbidden
			}
			writeJSONError(w, status, errorMessage(status))
			return
		}
		if isUnsafeMethod(r.Method) && !a.sameOrigin(r.Header.Get("Origin")) {
			writeJSONError(w, http.StatusForbidden, "invalid request origin")
			return
		}
		next.ServeHTTP(w, r.WithContext(contextWithIdentity(r.Context(), identity)))
	})
}

func (a *Auth) Identity(r *http.Request) (Identity, error) {
	cookie, err := r.Cookie(a.cookieName)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	idToken, identity, claims, err := a.verify(r.Context(), cookie.Value)
	if err != nil || a.cookieMaxAge(time.Unix(claims.IssuedAt, 0), idToken.Expiry) <= 0 {
		return Identity{}, ErrUnauthenticated
	}
	if err := a.options.Authorizer.Authorize(r.Context(), identity); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrForbidden, err)
	}
	return identity, nil
}

func (a *Auth) login(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken(a.options.Random)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken(a.options.Random)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	verifier, err := randomToken(a.options.Random)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	flow := LoginFlow{State: state, Nonce: nonce, Verifier: verifier, ExpiresAt: a.options.Now().Add(a.options.FlowTTL)}
	if err := a.options.FlowStore.Create(r.Context(), flow); err != nil {
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	a.setFlowCookie(w, state, int(a.options.FlowTTL.Seconds()))
	challenge := sha256.Sum256([]byte(verifier))
	location := a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, location, http.StatusFound)
}

func (a *Auth) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	flowCookie, cookieErr := r.Cookie(a.flowCookie)
	a.setFlowCookie(w, "", -1)
	flow, flowErr := a.options.FlowStore.Consume(r.Context(), state)
	if cookieErr != nil || flowCookie.Value != state || flowErr != nil || r.URL.Query().Get("code") == "" {
		http.Error(w, "invalid or expired login", http.StatusBadRequest)
		return
	}
	ctx := oidc.ClientContext(r.Context(), a.options.HTTPClient)
	token, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.SetAuthURLParam("code_verifier", flow.Verifier))
	if err != nil {
		a.logOAuthError(err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" || len(rawIDToken) > maxIdentityCookieBytes {
		http.Error(w, "identity token missing or too large", http.StatusBadGateway)
		return
	}
	idToken, identity, claims, err := a.verify(r.Context(), rawIDToken)
	if err != nil || idToken.Nonce != flow.Nonce {
		a.options.Logger.Warn("OIDC identity validation failed", "error", err)
		http.Error(w, "invalid identity", http.StatusUnauthorized)
		return
	}
	if err := a.options.Authorizer.Authorize(r.Context(), identity); err != nil {
		a.options.Logger.Warn("OIDC user is not authorized", "subject", identity.Subject, "username", identity.Username, "provider", identity.Provider, "provider_user_id", identity.ProviderUserID)
		http.Error(w, "user is not authorized", http.StatusForbidden)
		return
	}
	maxAge := a.cookieMaxAge(time.Unix(claims.IssuedAt, 0), idToken.Expiry)
	if maxAge <= 0 {
		http.Error(w, "identity token expired", http.StatusUnauthorized)
		return
	}
	a.setIdentityCookie(w, rawIDToken, maxAge)
	http.Redirect(w, r, a.config.AfterLoginURL, http.StatusFound)
}

func (a *Auth) session(w http.ResponseWriter, r *http.Request) {
	identity, err := a.Identity(r)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, ErrForbidden) {
			status = http.StatusForbidden
		}
		writeJSONError(w, status, errorMessage(status))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(identity)
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r.Header.Get("Origin")) {
		writeJSONError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	a.setIdentityCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) verify(ctx context.Context, raw string) (*oidc.IDToken, Identity, baseClaims, error) {
	idToken, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, Identity{}, baseClaims{}, err
	}
	var claims baseClaims
	if err := idToken.Claims(&claims); err != nil || claims.IssuedAt == 0 {
		return nil, Identity{}, claims, errors.New("identity token issued-at claim missing")
	}
	var rawClaims json.RawMessage
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, Identity{}, claims, err
	}
	identity, err := a.options.IdentityMapper.MapIdentity(ctx, rawClaims)
	if err != nil || identity.Subject == "" {
		return nil, Identity{}, claims, errors.New("map OIDC identity")
	}
	return idToken, identity, claims, nil
}

func (a *Auth) cookieMaxAge(issuedAt, tokenExpiry time.Time) int {
	expires := issuedAt.Add(a.config.SessionTTL)
	if tokenExpiry.Before(expires) {
		expires = tokenExpiry
	}
	return int(expires.Sub(a.options.Now()).Seconds())
}

func (a *Auth) setIdentityCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: a.cookieName, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode})
}

func (a *Auth) setFlowCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: a.flowCookie, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
}

func (a *Auth) sameOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == a.publicURL.Scheme && parsed.Host == a.publicURL.Host && parsed.Path == ""
}

func (a *Auth) logOAuthError(err error) {
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		a.options.Logger.Warn("OIDC code exchange failed", "status", retrieveErr.Response.StatusCode, "oauth_error", retrieveErr.ErrorCode, "description", retrieveErr.ErrorDescription)
		return
	}
	a.options.Logger.Warn("OIDC code exchange failed", "error", err)
}

func shortHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:6])
}

func errorMessage(status int) string {
	if status == http.StatusForbidden {
		return "access forbidden"
	}
	return "authentication required"
}
