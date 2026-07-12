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
	config       Config
	options      Options
	oauth        oauth2.Config
	verifier     *oidc.IDTokenVerifier
	externalURLs map[string]*url.URL
	secure       bool
	cookieName   string
	flowCookie   string
	pathPrefix   string
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
	externalURLs := make(map[string]*url.URL, len(config.ExternalURLs))
	for _, value := range config.ExternalURLs {
		externalURL, _ := url.Parse(value)
		externalURLs[strings.ToLower(externalURL.Host)] = externalURL
	}
	cookieSuffix := shortHash(config.ClientID)
	cookieName := options.CookieName
	flowCookie := options.FlowCookieName
	if cookieName == "" {
		cookieName = "oidcauth_" + cookieSuffix
	}
	if flowCookie == "" {
		flowCookie = "oidcauth_flow_" + cookieSuffix
	}
	secure := strings.HasPrefix(config.ExternalURLs[0], "https://")
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
			Scopes:       scopes,
		},
		verifier:     provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		externalURLs: externalURLs,
		secure:       secure,
		cookieName:   cookieName,
		flowCookie:   flowCookie,
		pathPrefix:   pathPrefix,
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
		if isUnsafeMethod(r.Method) && !a.sameOrigin(r) {
			a.logRejectedOrigin(r)
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
	externalURL, ok := a.externalURL(r)
	if !ok {
		http.Error(w, "untrusted request host", http.StatusBadRequest)
		return
	}
	returnTo, err := normalizeReturnTo(r.URL.Query().Get("return_to"))
	if err != nil {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}
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
	flow := LoginFlow{State: state, Nonce: nonce, Verifier: verifier, ExternalURL: externalURL.String(), ReturnTo: returnTo, ExpiresAt: a.options.Now().Add(a.options.FlowTTL)}
	if err := a.options.FlowStore.Create(r.Context(), flow); err != nil {
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	a.setFlowCookie(w, state, int(a.options.FlowTTL.Seconds()))
	challenge := sha256.Sum256([]byte(verifier))
	oauth := a.oauthFor(externalURL)
	location := oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, location, http.StatusFound)
}

func (a *Auth) callback(w http.ResponseWriter, r *http.Request) {
	externalURL, ok := a.externalURL(r)
	if !ok {
		http.Error(w, "untrusted request host", http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	flowCookie, cookieErr := r.Cookie(a.flowCookie)
	a.setFlowCookie(w, "", -1)
	flow, flowErr := a.options.FlowStore.Consume(r.Context(), state)
	if cookieErr != nil || flowCookie.Value != state || flowErr != nil || flow.ExternalURL != externalURL.String() || r.URL.Query().Get("code") == "" {
		http.Error(w, "invalid or expired login", http.StatusBadRequest)
		return
	}
	ctx := oidc.ClientContext(r.Context(), a.options.HTTPClient)
	oauth := a.oauthFor(externalURL)
	token, err := oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.SetAuthURLParam("code_verifier", flow.Verifier))
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
	http.Redirect(w, r, flow.ReturnTo, http.StatusFound)
}

func normalizeReturnTo(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" ||
		!strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.Contains(value, "\\") {
		return "", errors.New("return_to must be a same-origin absolute path")
	}
	return parsed.String(), nil
}

func (a *Auth) session(w http.ResponseWriter, r *http.Request) {
	identity, err := a.Identity(r)
	response := SessionResponse{Status: SessionStatusAuthenticated, Identity: &identity}
	if err != nil {
		response = SessionResponse{Status: SessionStatusSignedOut}
		if errors.Is(err, ErrForbidden) {
			response.Status = SessionStatusForbidden
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		a.logRejectedOrigin(r)
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

func (a *Auth) externalURL(r *http.Request) (*url.URL, bool) {
	externalURL, ok := a.externalURLs[strings.ToLower(r.Host)]
	return externalURL, ok
}

func (a *Auth) oauthFor(externalURL *url.URL) oauth2.Config {
	oauth := a.oauth
	oauth.RedirectURL = externalURL.String() + a.pathPrefix + "/callback"
	return oauth
}

func (a *Auth) sameOrigin(r *http.Request) bool {
	expected, ok := a.externalURL(r)
	parsed, err := url.Parse(r.Header.Get("Origin"))
	return ok && err == nil && parsed.User == nil && parsed.Opaque == "" && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.Scheme == expected.Scheme && strings.EqualFold(parsed.Host, expected.Host) && parsed.Path == ""
}

func (a *Auth) logRejectedOrigin(r *http.Request) {
	a.options.Logger.Warn("OIDC request origin rejected",
		"method", r.Method,
		"path", r.URL.Path,
		"origin", r.Header.Get("Origin"),
		"request_host", r.Host,
		"expected_origins", a.config.ExternalURLs,
	)
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
