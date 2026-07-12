package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

func TestOIDCLoginSessionMiddlewareAndLogout(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	provider := newTestProvider(t, now)
	auth := newTestAuth(t, provider, now)

	login := httptest.NewRecorder()
	auth.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://tool.example.com/oidcauth/login?return_to=%2F%23%2Fconsole", nil))
	if login.Code != http.StatusFound {
		t.Fatalf("unexpected login status: %d", login.Code)
	}
	location, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse login redirect: %v", err)
	}
	query := location.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("state") == "" || query.Get("nonce") == "" {
		t.Fatalf("unexpected authorization query: %s", location.RawQuery)
	}
	provider.nonce = query.Get("nonce")
	provider.expectedVerifier = authFlowVerifier(t, auth, query.Get("state"))
	provider.expectedRedirectURI = "https://tool.example.com/oidcauth/callback"
	flowCookie := login.Result().Cookies()[0]

	callbackRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/oidcauth/callback?code=code&state="+url.QueryEscape(query.Get("state")), nil)
	callbackRequest.AddCookie(flowCookie)
	auth.options.Authorizer = AuthorizerFunc(func(context.Context, Identity) error { return ErrForbidden })
	callback := httptest.NewRecorder()
	auth.Handler().ServeHTTP(callback, callbackRequest)
	if callback.Code != http.StatusFound || callback.Header().Get("Location") != "/#/console" {
		t.Fatalf("unexpected callback: status=%d location=%q body=%q", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	identityCookie := findCookie(t, callback.Result().Cookies(), auth.cookieName)
	if !identityCookie.HttpOnly || !identityCookie.Secure || identityCookie.SameSite != http.SameSiteStrictMode || !strings.HasPrefix(identityCookie.Name, "__Host-") {
		t.Fatalf("unexpected identity cookie: %#v", identityCookie)
	}

	deniedSessionRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/oidcauth/session", nil)
	deniedSessionRequest.AddCookie(identityCookie)
	deniedSession := httptest.NewRecorder()
	auth.Handler().ServeHTTP(deniedSession, deniedSessionRequest)
	assertAuthenticatedSession(t, deniedSession, AccessStatusDenied)

	auth.options.Authorizer = AuthorizerFunc(func(context.Context, Identity) error { return nil })
	sessionRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/oidcauth/session", nil)
	sessionRequest.AddCookie(identityCookie)
	session := httptest.NewRecorder()
	auth.Handler().ServeHTTP(session, sessionRequest)
	var sessionResponse SessionResponse
	if err := json.NewDecoder(session.Body).Decode(&sessionResponse); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if session.Code != http.StatusOK || sessionResponse.Status != SessionStatusAuthenticated || sessionResponse.Access != AccessStatusGranted || sessionResponse.Identity == nil || sessionResponse.Identity.Username != "admin" {
		t.Fatalf("unexpected session: status=%d body=%q", session.Code, session.Body.String())
	}

	signedOut := httptest.NewRecorder()
	auth.Handler().ServeHTTP(signedOut, httptest.NewRequest(http.MethodGet, "https://tool.example.com/oidcauth/session", nil))
	assertSignedOutSession(t, signedOut)

	var contextIdentity Identity
	protected := auth.RequireAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextIdentity, _ = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	unauthenticatedResponse := httptest.NewRecorder()
	protected.ServeHTTP(unauthenticatedResponse, httptest.NewRequest(http.MethodGet, "https://tool.example.com/api/settings", nil))
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected unauthenticated API status: %d", unauthenticatedResponse.Code)
	}

	auth.options.Authorizer = AuthorizerFunc(func(context.Context, Identity) error { return ErrForbidden })
	authenticatedOnly := auth.RequireAuthenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	authenticatedOnlyRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/api/profile", nil)
	authenticatedOnlyRequest.AddCookie(identityCookie)
	authenticatedOnlyResponse := httptest.NewRecorder()
	authenticatedOnly.ServeHTTP(authenticatedOnlyResponse, authenticatedOnlyRequest)
	if authenticatedOnlyResponse.Code != http.StatusNoContent {
		t.Fatalf("unexpected authenticated-only API status: %d", authenticatedOnlyResponse.Code)
	}

	forbiddenAPIRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/api/settings", nil)
	forbiddenAPIRequest.AddCookie(identityCookie)
	forbiddenAPIResponse := httptest.NewRecorder()
	protected.ServeHTTP(forbiddenAPIResponse, forbiddenAPIRequest)
	if forbiddenAPIResponse.Code != http.StatusForbidden {
		t.Fatalf("unexpected forbidden API status: %d", forbiddenAPIResponse.Code)
	}
	auth.options.Authorizer = AuthorizerFunc(func(context.Context, Identity) error { return nil })

	protectedRequest := httptest.NewRequest(http.MethodPost, "https://tool.example.com/api/settings", nil)
	protectedRequest.Header.Set("Origin", "https://tool.example.com")
	protectedRequest.AddCookie(identityCookie)
	protectedResponse := httptest.NewRecorder()
	protected.ServeHTTP(protectedResponse, protectedRequest)
	if protectedResponse.Code != http.StatusNoContent || contextIdentity.Username != "admin" {
		t.Fatalf("identity was not injected: status=%d identity=%#v", protectedResponse.Code, contextIdentity)
	}

	csrfRequest := httptest.NewRequest(http.MethodPost, "https://tool.example.com/api/settings", nil)
	csrfRequest.Header.Set("Origin", "https://evil.example.com")
	csrfRequest.AddCookie(identityCookie)
	csrfResponse := httptest.NewRecorder()
	protected.ServeHTTP(csrfResponse, csrfRequest)
	if csrfResponse.Code != http.StatusForbidden {
		t.Fatalf("unexpected CSRF status: %d", csrfResponse.Code)
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "https://tool.example.com/oidcauth/logout", nil)
	logoutRequest.Header.Set("Origin", "https://tool.example.com")
	logoutRequest.AddCookie(identityCookie)
	logout := httptest.NewRecorder()
	auth.Handler().ServeHTTP(logout, logoutRequest)
	if logout.Code != http.StatusNoContent || findCookie(t, logout.Result().Cookies(), auth.cookieName).MaxAge != -1 {
		t.Fatalf("unexpected logout response: status=%d cookies=%#v", logout.Code, logout.Result().Cookies())
	}

	replay := httptest.NewRecorder()
	auth.Handler().ServeHTTP(replay, callbackRequest)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback must fail, got %d", replay.Code)
	}
}

func assertSignedOutSession(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	var response SessionResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if recorder.Code != http.StatusOK || response.Status != SessionStatusSignedOut || response.Access != "" || response.Identity != nil {
		t.Fatalf("unexpected session response: code=%d response=%+v", recorder.Code, response)
	}
}

func assertAuthenticatedSession(t *testing.T, recorder *httptest.ResponseRecorder, wantAccess AccessStatus) {
	t.Helper()
	var response SessionResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if recorder.Code != http.StatusOK || response.Status != SessionStatusAuthenticated || response.Access != wantAccess || response.Identity == nil || response.Identity.Username != "admin" {
		t.Fatalf("unexpected session response: code=%d response=%+v", recorder.Code, response)
	}
}

func TestLoginRejectsUnsafeReturnTo(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	provider := newTestProvider(t, now)
	auth := newTestAuth(t, provider, now)

	for _, value := range []string{"https://evil.example.com/", "//evil.example.com/", `/\\evil`} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://tool.example.com/oidcauth/login?return_to="+url.QueryEscape(value), nil)
		auth.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("return_to %q: unexpected status %d", value, recorder.Code)
		}
	}
}

func TestLoginRejectsUntrustedRequestHost(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	provider := newTestProvider(t, now)
	auth := newTestAuth(t, provider, now)
	recorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://unknown.example.com/oidcauth/login", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
}

func TestLoginDefaultsReturnToRoot(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	provider := newTestProvider(t, now)
	auth := newTestAuth(t, provider, now)
	recorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://tool.example.com/oidcauth/login", nil))
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	store := auth.options.FlowStore.(*MemoryFlowStore)
	store.mu.Lock()
	flow := store.flows[location.Query().Get("state")]
	store.mu.Unlock()
	if flow.ReturnTo != "/" {
		t.Fatalf("unexpected return_to: %q", flow.ReturnTo)
	}
	if flow.ExternalURL != "https://tool.example.com" {
		t.Fatalf("unexpected external URL: %q", flow.ExternalURL)
	}

	other := httptest.NewRecorder()
	auth.Handler().ServeHTTP(other, httptest.NewRequest(http.MethodGet, "https://other.example.com/oidcauth/login", nil))
	otherLocation, err := url.Parse(other.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := otherLocation.Query().Get("redirect_uri"); got != "https://other.example.com/oidcauth/callback" {
		t.Fatalf("unexpected redirect URI: %q", got)
	}
	store.mu.Lock()
	otherFlow := store.flows[otherLocation.Query().Get("state")]
	store.mu.Unlock()
	if otherFlow.ExternalURL != "https://other.example.com" {
		t.Fatalf("unexpected other external URL: %q", otherFlow.ExternalURL)
	}
}

func TestCallbackMustUseLoginOrigin(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	provider := newTestProvider(t, now)
	auth := newTestAuth(t, provider, now)

	login := httptest.NewRecorder()
	auth.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://tool.example.com/oidcauth/login", nil))
	location, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest(http.MethodGet, "https://other.example.com/oidcauth/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callback.AddCookie(login.Result().Cookies()[0])
	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, callback)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unexpected cross-origin callback status: %d", response.Code)
	}
}

func TestSameOriginRequiresExactConfiguredOrigin(t *testing.T) {
	externalURL := &url.URL{Scheme: "https", Host: "tool.example.com:8443"}
	auth := &Auth{externalURLs: map[string]*url.URL{"tool.example.com:8443": externalURL, "other.example.com:8443": {Scheme: "https", Host: "other.example.com:8443"}}}
	for _, test := range []struct {
		host   string
		origin string
		want   bool
	}{
		{host: "tool.example.com:8443", origin: "https://tool.example.com:8443", want: true},
		{host: "tool.example.com:8443", origin: "https://other.example.com:8443"},
		{host: "unknown.example.com:8443", origin: "https://tool.example.com:8443"},
		{origin: ""},
		{origin: "https://tool.example.com"},
		{origin: "http://tool.example.com:8443"},
		{origin: "https://evil.example.com:8443"},
		{origin: "https://user@tool.example.com:8443"},
		{origin: "https://tool.example.com:8443/"},
		{origin: "https://tool.example.com:8443?query"},
	} {
		host := test.host
		if host == "" {
			host = "tool.example.com:8443"
		}
		request := httptest.NewRequest(http.MethodPost, "https://"+host+"/api/settings", nil)
		request.Header.Set("Origin", test.origin)
		if got := auth.sameOrigin(request); got != test.want {
			t.Errorf("sameOrigin(host=%q, origin=%q) = %v, want %v", test.host, test.origin, got, test.want)
		}
	}
}

type testProvider struct {
	server              *httptest.Server
	privateKey          *rsa.PrivateKey
	oidcServer          *oidctest.Server
	now                 time.Time
	nonce               string
	expectedVerifier    string
	expectedRedirectURI string
}

func newTestProvider(t *testing.T, now time.Time) *testProvider {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	provider := &testProvider{privateKey: privateKey, now: now}
	provider.oidcServer = &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: privateKey.Public(), KeyID: "key", Algorithm: oidc.RS256}}}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serveHTTP))
	provider.oidcServer.SetIssuer(provider.server.URL)
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *testProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token" {
		p.oidcServer.ServeHTTP(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	if r.Form.Get("client_id") != "tool" || r.Form.Get("client_secret") != "" || r.Form.Get("code_verifier") != p.expectedVerifier || r.Form.Get("redirect_uri") != p.expectedRedirectURI {
		http.Error(w, "invalid token request", http.StatusUnauthorized)
		return
	}
	claims := fmt.Sprintf(`{
		"iss":%q,"aud":"tool","sub":"subject","iat":%d,"exp":%d,"nonce":%q,
		"preferred_username":"admin","federated_claims":{"connector_id":"github","user_id":"42"}
	}`, p.server.URL, p.now.Unix(), p.now.Add(time.Hour).Unix(), p.nonce)
	raw := oidctest.SignIDToken(p.privateKey, "key", oidc.RS256, claims)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
}

func newTestAuth(t *testing.T, provider *testProvider, now time.Time) *Auth {
	t.Helper()
	auth, err := New(t.Context(), Config{
		Issuer:       provider.server.URL,
		ClientID:     "tool",
		ExternalURLs: []string{"https://tool.example.com", "https://other.example.com"},
		SessionTTL:   30 * time.Minute,
	}, Options{
		HTTPClient: provider.server.Client(),
		Now:        func() time.Time { return now },
		IdentityMapper: IdentityMapperFunc(func(_ context.Context, raw json.RawMessage) (Identity, error) {
			var claims struct {
				Subject  string `json:"sub"`
				Username string `json:"preferred_username"`
			}
			if err := json.Unmarshal(raw, &claims); err != nil {
				return Identity{}, err
			}
			return Identity{Subject: claims.Subject, Username: claims.Username}, nil
		}),
		Authorizer: AuthorizerFunc(func(_ context.Context, identity Identity) error {
			if identity.Username != "admin" {
				return ErrForbidden
			}
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	return auth
}

func authFlowVerifier(t *testing.T, auth *Auth, state string) string {
	t.Helper()
	store, ok := auth.options.FlowStore.(*MemoryFlowStore)
	if !ok {
		t.Fatal("expected memory flow store")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.flows[state].Verifier
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q not found in %s", name, strconv.Itoa(len(cookies)))
	return nil
}
