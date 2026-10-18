package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
)

type resourceLoginBoundaryFixture struct {
	*resourceOAuthFixture
	shadowID, shadowClient, redirect, published string
}

func newResourceLoginBoundaryFixture(t *testing.T) *resourceLoginBoundaryFixture {
	t.Helper()
	f := &resourceLoginBoundaryFixture{resourceOAuthFixture: newResourceOAuthFixture(t), shadowID: kernel.NewID().String(), redirect: "https://external-resource-client.example.test/callback", published: "https://metadata.example.test/login-client.json"}
	f.shadowClient = "p93_resource_" + f.shadowID
	f.exec(`UPDATE clients SET client_type='public',secret_digest=NULL,pkce_required=true,authorization_ui='hosted',initiate_login_uri='https://client.example.test/login' WHERE id=$1`, f.client)
	f.exec(`INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes,pkce_required,authorization_ui,initiate_login_uri,resource_only)
VALUES($1,$2,$3,'Metadata shadow','public',ARRAY[$4],ARRAY['authorization_code','refresh_token'],ARRAY['openid','email','profile','offline_access'],true,'hosted','https://external-resource-client.example.test/login',true)`, f.shadowID, f.application, f.shadowClient, f.redirect)
	f.exec(`UPDATE oauth_resources SET allow_client_metadata=true,client_ids=ARRAY[$2] WHERE id=$1`, f.resource, f.published)
	f.exec(`INSERT INTO oauth_resource_clients(application_id,resource_id,client_id,client_database_id,metadata_digest) VALUES($1,$2,$3,$4,$5)`, f.application, f.resource, f.published, f.shadowID, []byte("login-boundary-metadata"))
	return f
}

func (f *resourceLoginBoundaryFixture) jsonCall(target string, body any, browser *http.Cookie, csrf string, bearer ...string) *httptest.ResponseRecorder {
	f.t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	r := httptest.NewRequest("POST", target, strings.NewReader(string(encoded)))
	r.RemoteAddr = "192.0.2.20:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Origin", f.app.PublicURL)
	r.Header.Set("Idempotency-Key", kernel.NewID().String())
	if len(bearer) != 0 {
		r.Header.Set("Authorization", "Bearer "+bearer[0])
	}
	if browser != nil {
		r.AddCookie(browser)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func TestResourceOAuthPostgresShadowCORSBoundary(t *testing.T) {
	f := newResourceLoginBoundaryFixture(t)
	f.exec(`UPDATE clients SET post_logout_redirect_uris=ARRAY['https://shadow-logout.example.test/return'] WHERE id=$1`, f.shadowID)
	for _, path := range []string{"/v1/applications/" + f.application + "/auth/email/start", "/oidc/token"} {
		for _, origin := range []string{"https://external-resource-client.example.test", "https://shadow-logout.example.test", "https://client.example.test"} {
			t.Run(path+"/"+origin, func(t *testing.T) {
				r := httptest.NewRequest("OPTIONS", path, nil)
				r.Header.Set("Origin", origin)
				r.Header.Set("Access-Control-Request-Method", "POST")
				r.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
				w := httptest.NewRecorder()
				f.router.ServeHTTP(w, r)
				if origin == "https://client.example.test" {
					if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != origin {
						t.Fatalf("ordinary public origin rejected: %d %s", w.Code, w.Body)
					}
				} else {
					assertResourceLoginProblem(t, w, http.StatusForbidden, "origin_not_allowed")
					if w.Header().Get("Access-Control-Allow-Origin") != "" {
						t.Fatal("metadata shadow granted cross-origin application access")
					}
				}
			})
		}
	}
}

func TestResourceOAuthPostgresShadowBillingBoundary(t *testing.T) {
	f := newResourceLoginBoundaryFixture(t)
	for _, tc := range []struct {
		name, path string
		body       map[string]string
	}{
		{name: "checkout success", path: "checkout-sessions", body: map[string]string{"success_uri": f.redirect, "cancel_uri": "https://client.example.test/callback"}},
		{name: "checkout cancel", path: "checkout-sessions", body: map[string]string{"success_uri": "https://client.example.test/callback", "cancel_uri": f.redirect}},
		{name: "portal return", path: "portal-sessions", body: map[string]string{"return_uri": f.redirect}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.jsonCall("/v1/applications/"+f.application+"/billing/"+tc.path, tc.body, nil, "", f.accessToken(false))
			assertResourceLoginProblem(t, w, http.StatusUnprocessableEntity, "redirect_not_allowed")
		})
	}
	s := &Server{app: f.app}
	r := requestWithRoute(t, "GET", "/", nil, map[string]string{"application_id": f.application}, kernel.Actor{})
	if s.billingRedirectAllowed(r, f.redirect) {
		t.Error("shadow redirect eligible for billing")
	}
	if !s.billingRedirectAllowed(r, "https://client.example.test/callback") {
		t.Error("ordinary redirect excluded from billing")
	}
	var count int
	if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM checkout_sessions WHERE application_id=$1`, f.application).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected redirect created checkout: %d %v", count, err)
	}
}

func TestResourceOAuthPostgresShadowControlBoundary(t *testing.T) {
	f := newResourceLoginBoundaryFixture(t)
	f.exec(`UPDATE applications SET internal_config=jsonb_set(internal_config,'{delegation_enabled}','true') WHERE id=$1`, f.application)
	f.exec(`INSERT INTO organization_memberships(organization_id,control_user_id,role) SELECT organization_id,$2,'owner' FROM applications WHERE id=$1`, f.application, f.controlUser)
	session := kernel.NewID().String()
	f.exec(`INSERT INTO control_user_sessions(id,control_user_id,refresh_digest,expires_at) VALUES($1,$2,$3,now()+interval '1 hour')`, session, f.controlUser, f.app.Vault.Digest("boundary-control-session"))
	kid, key, err := f.app.ActiveSigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := f.app.Now()
	bearer, err := identity.Sign(key, kid, identity.Claims{Issuer: f.app.Issuer(), Audience: []string{f.app.ControlAudience()}, Subject: f.controlUser, SessionID: session, ActorType: "control_user", TokenKind: "control", Roles: emptyRoleClaims(), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), JWTID: kernel.NewID().String()})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("ordinary client list", func(t *testing.T) {
		w := f.call("GET", "/v1/control/applications/"+f.application+"/clients", nil, bearer, "192.0.2.20")
		if w.Code != http.StatusOK {
			t.Fatalf("list clients: %d %s", w.Code, w.Body)
		}
		items, ok := decodeTestResponse(t, w)["items"].([]any)
		if !ok {
			t.Fatalf("missing client list: %s", w.Body)
		}
		found := false
		for _, value := range items {
			client, ok := value.(map[string]any)
			if !ok {
				t.Fatalf("invalid client item: %#v", value)
			}
			if client["id"] == f.shadowID || client["client_id"] == f.shadowClient {
				t.Error("metadata shadow leaked through ordinary client list")
			}
			if client["id"] == f.client {
				found = true
			}
		}
		if !found {
			t.Error("ordinary client missing from list")
		}
	})
	t.Run("delegation redirect", func(t *testing.T) {
		body := map[string]any{"user_id": f.user, "reason": "Boundary regression", "redirect_uri": f.redirect, "permissions": []string{"billing:read"}}
		w := f.jsonCall("/v1/control/applications/"+f.application+"/delegations", body, nil, "", bearer)
		assertResourceLoginProblem(t, w, http.StatusUnprocessableEntity, "invalid_delegation_target")
		var count int
		if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM delegations WHERE application_id=$1`, f.application).Scan(&count); err != nil || count != 0 {
			t.Fatalf("shadow redirect created delegation: %d %v", count, err)
		}
		body["redirect_uri"] = "https://client.example.test/callback"
		w = f.jsonCall("/v1/control/applications/"+f.application+"/delegations", body, nil, "", bearer)
		if w.Code != http.StatusCreated {
			t.Fatalf("ordinary delegation redirect rejected: %d %s", w.Code, w.Body)
		}
	})
}

func assertResourceLoginProblem(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status || decodeTestResponse(t, w)["code"] != code {
		t.Errorf("want %d %s: got %d %s", status, code, w.Code, w.Body)
	}
}

func TestResourceOAuthPostgresShadowLoginBoundary(t *testing.T) {
	f := newResourceLoginBoundaryFixture(t)
	digest := sha256.Sum256([]byte(resourceOAuthTestVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	for _, provider := range []string{"google", "apple", "microsoft", "facebook", "linkedin"} {
		for _, flow := range []string{"sign_in", "automatic"} {
			t.Run(provider+"/"+flow, func(t *testing.T) {
				path := "/v1/applications/" + f.application + "/auth/providers/" + provider + "/start"
				body := map[string]string{"flow": flow, "redirect_uri": f.redirect, "code_challenge": challenge}
				assertResourceLoginProblem(t, f.jsonCall(path, body, nil, ""), http.StatusUnprocessableEntity, "pkce_or_redirect_invalid")
				// No provider is configured: ordinary redirects reach provider lookup,
				// whereas shadow redirects must fail before any provider work.
				body["redirect_uri"] = "https://client.example.test/callback"
				unavailable := "auth_provider_unavailable"
				if provider == "google" || provider == "apple" {
					unavailable = provider + "_provider_unavailable"
				}
				assertResourceLoginProblem(t, f.jsonCall(path, body, nil, ""), http.StatusServiceUnavailable, unavailable)
			})
		}
	}
	for _, intent := range []string{"sign_in", "automatic"} {
		t.Run("email/"+intent, func(t *testing.T) {
			w := f.jsonCall("/v1/applications/"+f.application+"/auth/email/start", map[string]string{"email": "user@example.test", "intent": intent, "delivery": "both", "redirect_uri": f.redirect}, nil, "")
			assertResourceLoginProblem(t, w, http.StatusUnprocessableEntity, "redirect_uri_not_allowed")
		})
	}
	for _, table := range []string{"external_auth_challenges", "login_challenges", "notifications"} {
		var count int
		if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE application_id=$1`, f.application).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("rejected login created %d %s records", count, table)
		}
	}
}

func TestResourceOAuthPostgresShadowNormalEligibility(t *testing.T) {
	f := newResourceLoginBoundaryFixture(t)
	s := &Server{app: f.app}
	ctx := context.Background()
	t.Run("application flow configuration", func(t *testing.T) {
		config := applicationFlowConfig{OAuthClientID: f.shadowClient, SignInRedirectURI: f.redirect, InvitationRedirectURI: "https://external-resource-client.example.test/invitation"}
		if err := s.validateApplicationFlowConfig(ctx, f.application, config); err == nil {
			t.Error("resource-only internal client accepted as ordinary application flow client")
		}
		config = applicationFlowConfig{OAuthClientID: f.client, SignInRedirectURI: "https://client.example.test/callback", InvitationRedirectURI: "https://client.example.test/invitation"}
		if err := s.validateApplicationFlowConfig(ctx, f.application, config); err != nil {
			t.Fatalf("ordinary public client rejected: %v", err)
		}
	})
	t.Run("hosted invitation eligibility", func(t *testing.T) {
		if _, _, err := s.hostedInvitationClient(ctx, f.application, f.shadowID, f.redirect); err == nil {
			t.Error("resource-only shadow accepted as ordinary hosted invitation client")
		}
		if _, _, err := s.hostedInvitationClient(ctx, f.application, f.client, "https://client.example.test/callback"); err != nil {
			t.Fatalf("ordinary hosted client rejected: %v", err)
		}
	})
	t.Run("normal OAuth application resolution", func(t *testing.T) {
		form := f.authorizationForm("billing:read")
		form.Set("client_id", f.shadowClient)
		form.Set("redirect_uri", f.redirect)
		form.Del("resource")
		w := f.call("GET", "/oidc/authorize?"+form.Encode(), nil, "", "192.0.2.20")
		assertResourceLoginProblem(t, w, http.StatusBadRequest, "oauth_application_unresolved")
	})
}

func TestResourceOAuthPostgresShadowHostedProviderBoundary(t *testing.T) {
	f := newResourceLoginBoundaryFixture(t)
	params := f.authorizationForm("billing:read")
	params.Set("client_id", f.published)
	params.Set("redirect_uri", f.redirect)
	for _, key := range []string{"resource_version", "approved_capabilities", "workspace_ids", "personal_access", "decision"} {
		params.Del(key)
	}
	r := httptest.NewRequest("GET", "/oidc/authorize?"+params.Encode(), nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("resource-only hosted start: %d %s", w.Code, w.Body)
	}
	var browser *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if strings.Contains(cookie.Name, "hosted_browser") {
			browser = cookie
		}
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("interaction") == "" || browser == nil {
		t.Fatal("missing resource-only hosted interaction or cookie")
	}
	interaction := location.Query().Get("interaction")
	base := "/v1/auth/hosted/interactions/" + interaction
	r = httptest.NewRequest("GET", base, nil)
	r.AddCookie(browser)
	w = httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("resource-only hosted view: %d %s", w.Code, w.Body)
	}
	view := decodeTestResponse(t, w)
	csrf, _ := view["csrf_token"].(string)
	if view["stage"] != "login" || csrf == "" {
		t.Fatalf("missing hosted login: %s", w.Body)
	}
	// The internal callback has no ordinary client registration. Only the
	// authenticated hosted interaction may authorize this exact callback.
	callback := strings.TrimRight(f.app.PublicURL, "/") + "/auth/return/" + interaction
	digest := sha256.Sum256([]byte(resourceOAuthTestVerifier))
	for _, provider := range []string{"google", "apple", "microsoft", "facebook", "linkedin"} {
		t.Run(provider, func(t *testing.T) {
			path := "/v1/applications/" + f.application + "/auth/providers/" + provider + "/start"
			assertResourceLoginProblem(t, f.jsonCall(path, map[string]string{"flow": "automatic", "redirect_uri": callback, "code_challenge": base64.RawURLEncoding.EncodeToString(digest[:])}, nil, ""), http.StatusUnprocessableEntity, "pkce_or_redirect_invalid")
			unavailable := "auth_provider_unavailable"
			if provider == "google" || provider == "apple" {
				unavailable = provider + "_provider_unavailable"
			}
			assertResourceLoginProblem(t, f.jsonCall(base+"/actions", map[string]string{"action": "provider", "provider": provider}, browser, csrf), http.StatusServiceUnavailable, unavailable)
		})
	}
}
