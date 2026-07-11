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
	auth.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/login", nil))
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
	flowCookie := login.Result().Cookies()[0]

	callbackRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/callback?code=code&state="+url.QueryEscape(query.Get("state")), nil)
	callbackRequest.AddCookie(flowCookie)
	callback := httptest.NewRecorder()
	auth.Handler().ServeHTTP(callback, callbackRequest)
	if callback.Code != http.StatusFound || callback.Header().Get("Location") != "https://tool.example.com/#/console" {
		t.Fatalf("unexpected callback: status=%d location=%q body=%q", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	identityCookie := findCookie(t, callback.Result().Cookies(), auth.cookieName)
	if !identityCookie.HttpOnly || !identityCookie.Secure || identityCookie.SameSite != http.SameSiteStrictMode || !strings.HasPrefix(identityCookie.Name, "__Host-") {
		t.Fatalf("unexpected identity cookie: %#v", identityCookie)
	}

	sessionRequest := httptest.NewRequest(http.MethodGet, "https://tool.example.com/auth/session", nil)
	sessionRequest.AddCookie(identityCookie)
	session := httptest.NewRecorder()
	auth.Handler().ServeHTTP(session, sessionRequest)
	if session.Code != http.StatusOK || !strings.Contains(session.Body.String(), `"username":"admin"`) {
		t.Fatalf("unexpected session: status=%d body=%q", session.Code, session.Body.String())
	}

	var contextIdentity Identity
	protected := auth.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextIdentity, _ = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
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

	logoutRequest := httptest.NewRequest(http.MethodPost, "https://tool.example.com/auth/logout", nil)
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

type testProvider struct {
	server           *httptest.Server
	privateKey       *rsa.PrivateKey
	oidcServer       *oidctest.Server
	now              time.Time
	nonce            string
	expectedVerifier string
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
	if r.Form.Get("client_id") != "tool" || r.Form.Get("client_secret") != "" || r.Form.Get("code_verifier") != p.expectedVerifier {
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
		Issuer:        provider.server.URL,
		ClientID:      "tool",
		CallbackURL:   "https://tool.example.com/auth/callback",
		PublicURL:     "https://tool.example.com",
		AfterLoginURL: "https://tool.example.com/#/console",
		SessionTTL:    30 * time.Minute,
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
