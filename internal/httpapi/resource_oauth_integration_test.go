package httpapi

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
)

const resourceOAuthTestURI = "https://resource.example.test"
const resourceOAuthTestVerifier = "resource-oauth-verifier-with-at-least-forty-three-characters-123456789"

type resourceOAuthFixture struct {
	*oauthSecurityFixture
	resource, machine string
}

func newResourceOAuthFixture(t *testing.T) *resourceOAuthFixture {
	t.Helper()
	f := &resourceOAuthFixture{oauthSecurityFixture: newOAuthSecurityFixture(t), resource: kernel.NewID().String(), machine: kernel.NewID().String()}
	f.exec(`UPDATE applications SET internal_config=jsonb_set(internal_config,'{resource_authorization_enabled}','true') WHERE id=$1`, f.application)
	f.exec(`INSERT INTO oauth_resources(id,application_id,uri,name,enabled,client_ids,capabilities) VALUES($1,$2,$3,'Billing resource',true,ARRAY[$4],$5::jsonb)`, f.resource, f.application, resourceOAuthTestURI, f.client, `[{"key":"billing:read","name":"Read billing","context":"personal","permissions":["billing:read"]},{"key":"billing:write","name":"Write billing","context":"personal","permissions":["billing:write"]}]`)
	f.exec(`INSERT INTO clients(id,application_id,client_id,name,client_type,allowed_grants,allowed_scopes,secret_digest) VALUES($1,$2,$1::uuid::text,'Resource checker','machine',ARRAY['client_credentials'],ARRAY[$3],$4)`, f.machine, f.application, f.scope("resource_access/check"), f.app.Vault.Digest("checker-secret"))
	return f
}

func (f *resourceOAuthFixture) authorizationForm(keys ...string) url.Values {
	f.t.Helper()
	digest := sha256.Sum256([]byte(resourceOAuthTestVerifier))
	scopes := []string{"offline_access"}
	for _, key := range keys {
		scopes = append(scopes, f.scope(strings.ReplaceAll(key, ":", "/")))
	}
	approved, err := json.Marshal(keys)
	if err != nil {
		f.t.Fatal(err)
	}
	return url.Values{"client_id": {f.client}, "resource": {resourceOAuthTestURI}, "response_type": {"code"}, "redirect_uri": {"https://client.example.test/callback"}, "scope": {strings.Join(scopes, " ")}, "state": {"resource-fixture-state-with-enough-entropy"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "approved_capabilities": {string(approved)}, "personal_access": {"true"}, "workspace_ids": {"[]"}, "decision": {"approve"}, "resource_version": {"1"}}
}

func (f *resourceOAuthFixture) resourceCode(form url.Values) string {
	f.t.Helper()
	return f.resourceCodeAs(form, f.accessToken(false))
}

func (f *resourceOAuthFixture) resourceCodeAs(form url.Values, bearer string) string {
	f.t.Helper()
	w := f.call("POST", "/oidc/authorize", form, bearer, "192.0.2.1")
	if w.Code != 200 {
		f.t.Fatalf("resource authorize: %d %s Location=%s", w.Code, w.Body, w.Header().Get("Location"))
	}
	redirect, _ := decodeTestResponse(f.t, w)["redirect_to"].(string)
	u, err := url.Parse(redirect)
	if err != nil || u.Query().Get("code") == "" {
		f.t.Fatalf("missing resource code: %s", w.Body)
	}
	if u.Query().Get("iss") != f.app.Issuer() {
		f.t.Fatalf("missing issuer in authorization response: %s", redirect)
	}
	return u.Query().Get("code")
}

func (f *resourceOAuthFixture) exchangeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example.test/callback"}, "resource": {resourceOAuthTestURI}, "code_verifier": {resourceOAuthTestVerifier}}
}

func (f *resourceOAuthFixture) tokenCall(form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/oidc/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(f.client), "fixture-secret")
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func (f *resourceOAuthFixture) resourceTokens(form url.Values) map[string]any {
	f.t.Helper()
	w := f.tokenCall(f.exchangeForm(f.resourceCode(form)))
	if w.Code != 200 {
		f.t.Fatalf("resource exchange: %d %s", w.Code, w.Body)
	}
	return decodeTestResponse(f.t, w)
}

func (f *resourceOAuthFixture) resourceRefresh(token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "resource": {resourceOAuthTestURI}}
}

func (f *resourceOAuthFixture) claims(token string) *identity.Claims {
	f.t.Helper()
	claims, err := identity.Verify(token, func(kid string) (*rsa.PublicKey, error) { return f.app.ResolvePublicKey(context.Background(), kid) }, f.app.Issuer(), resourceOAuthTestURI, f.app.Now())
	if err != nil {
		f.t.Fatalf("verify resource JWT: %v", err)
	}
	return &claims
}

func (f *resourceOAuthFixture) machineToken(scope string) string {
	f.t.Helper()
	kid, key, err := f.app.ActiveSigningKey(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	now := f.app.Now()
	token, err := identity.Sign(key, kid, identity.Claims{Issuer: f.app.Issuer(), Subject: f.machine, ClientID: f.machine, ApplicationID: f.application, Audience: []string{"platform93:application:" + f.application}, ActorType: "client", TokenKind: "machine", Scope: scope, Roles: emptyRoleClaims(), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), JWTID: kernel.NewID().String()})
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

func (f *resourceOAuthFixture) check(token, bearer, capability string, workspace *string) *httptest.ResponseRecorder {
	f.t.Helper()
	body, err := json.Marshal(map[string]any{"token": token, "resource": resourceOAuthTestURI, "capability": capability, "workspace_id": workspace})
	if err != nil {
		f.t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/applications/"+f.application+"/service/resource-access/check", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func (f *resourceOAuthFixture) assertCheck(token, capability string, workspace *string, allowed bool) {
	f.t.Helper()
	w := f.check(token, f.machineToken(f.scope("resource_access/check")), capability, workspace)
	if w.Code != 200 || decodeTestResponse(f.t, w)["allowed"] != allowed {
		f.t.Fatalf("live check want allowed=%v: %d %s", allowed, w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		f.t.Fatal("live check must not be cached")
	}
}

func assertResourceTokenRejected(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code < 400 || w.Code >= 500 {
		t.Fatalf("expected safe OAuth rejection: %d %s", w.Code, w.Body)
	}
}

func TestResourceOAuthPostgresIsolation(t *testing.T) {
	f := newResourceOAuthFixture(t)
	tokens := f.resourceTokens(f.authorizationForm("billing:read"))
	token := tokens["access_token"].(string)
	claims := f.claims(token)
	if !reflect.DeepEqual(claims.Audience, []string{resourceOAuthTestURI}) || claims.TokenKind != "resource_access" || claims.ConnectionID == "" || claims.ClientID != f.client || claims.SessionID != f.session || claims.Subject != f.user {
		t.Fatalf("incorrect resource identity: %+v", claims)
	}
	if len(claims.Roles.Application) != 0 || len(claims.Roles.Workspaces) != 0 {
		t.Fatalf("resource JWT leaked roles: %+v", claims.Roles)
	}
	scopes := strings.Fields(claims.Scope)
	sort.Strings(scopes)
	want := []string{f.scope("billing/read"), "offline_access"}
	sort.Strings(want)
	if !reflect.DeepEqual(scopes, want) {
		t.Fatalf("resource JWT expanded scopes: %v", scopes)
	}
	for _, path := range []string{"/v1/applications/" + f.application + "/me", "/v1/applications/" + f.application + "/me/connections", "/v1/control/applications/" + f.application + "/oauth-resources", "/oidc/userinfo"} {
		t.Run(path, func(t *testing.T) {
			w := f.call("GET", path, nil, token, "192.0.2.1")
			if w.Code != 401 && w.Code != 403 {
				t.Fatalf("resource credential accepted or route missing: %d %s", w.Code, w.Body)
			}
		})
	}
	f.assertCheck(token, "billing:read", nil, true)
	f.assertCheck(token, "billing:write", nil, false)
	for _, bearer := range []string{f.accessToken(false), f.machineToken(f.scope("billing/read")), token} {
		w := f.check(token, bearer, "billing:read", nil)
		if w.Code != 401 && w.Code != 403 {
			t.Fatalf("unauthorized checker: %d %s", w.Code, w.Body)
		}
	}
}

func TestResourceOAuthPostgresConsentVersion(t *testing.T) {
	for _, version := range []string{"", "0", "2"} {
		t.Run("version="+version, func(t *testing.T) {
			f := newResourceOAuthFixture(t)
			form := f.authorizationForm("billing:read")
			form.Set("resource_version", version)
			w := f.call("POST", "/oidc/authorize", form, f.accessToken(false), "192.0.2.1")
			if w.Code == 200 {
				t.Fatalf("unbound consent approved: %s", w.Body)
			}
			var n int
			if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM oauth_connections`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("refused consent persisted connection: %d %v", n, err)
			}
		})
	}
}

func TestResourceOAuthPostgresInteraction(t *testing.T) {
	f := newResourceOAuthFixture(t)
	form := f.authorizationForm("billing:read")
	w := f.call("GET", "/oidc/authorize?"+form.Encode(), nil, "", "192.0.2.1")
	if w.Code != 200 {
		t.Fatalf("interaction: %d %s", w.Code, w.Body)
	}
	view := decodeTestResponse(t, w)
	resource, ok := view["resource"].(map[string]any)
	if !ok || resource["version"] != float64(1) || resource["uri"] != resourceOAuthTestURI || resource["id"] != f.resource {
		t.Fatalf("resource consent snapshot missing: %s", w.Body)
	}
	requested, ok := view["requested_scopes"].([]any)
	if !ok || !reflect.DeepEqual(requested, []any{"offline_access", f.scope("billing/read")}) {
		t.Fatalf("incorrect requested canonical scopes: %s", w.Body)
	}
	// A resource changed after rendering must not accept the old approval.
	f.exec(`UPDATE oauth_resources SET version=version+1 WHERE id=$1`, f.resource)
	w = f.call("POST", "/oidc/authorize", form, f.accessToken(false), "192.0.2.1")
	if w.Code == 200 {
		t.Fatalf("stale consent snapshot approved: %s", w.Body)
	}
}

func TestResourceOAuthPostgresPublishedClientAcrossApplications(t *testing.T) {
	f := newResourceOAuthFixture(t)
	published := "https://metadata.example.test/oauth-client.json"
	for i := 0; i < 2; i++ {
		current := f.oauthSecurityFixture
		resourceID, resourceURI := f.resource, resourceOAuthTestURI
		if i == 1 {
			current = &oauthSecurityFixture{t: t, app: f.app, router: f.router, application: kernel.NewID().String(), user: kernel.NewID().String(), session: kernel.NewID().String(), client: published}
			f.exec(`INSERT INTO applications(id,organization_id,name,slug,internal_config) SELECT $1,organization_id,'Second owner',$1::uuid::text,internal_config FROM applications WHERE id=$2`, current.application, f.application)
			f.exec(`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'second@example.test','second@example.test')`, current.user, current.application)
			f.exec(`INSERT INTO user_sessions(id,application_id,user_id,refresh_digest,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 day')`, current.session, current.application, current.user, f.app.Vault.Digest("second-session"))
			role := kernel.NewID().String()
			f.exec(`INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,'billing','Billing','application',ARRAY['billing:read'])`, role, current.application)
			f.exec(`INSERT INTO role_assignments(id,application_id,role_id,user_id) VALUES($1,$2,$3,$4)`, kernel.NewID(), current.application, role, current.user)
			resourceID, resourceURI = kernel.NewID().String(), "https://second-resource.example.test"
			f.exec(`INSERT INTO oauth_resources(id,application_id,uri,name,enabled,allow_client_metadata,client_ids,capabilities) SELECT $1,$2,$3,'Second owner',true,true,ARRAY[$4],capabilities FROM oauth_resources WHERE id=$5`, resourceID, current.application, resourceURI, published, f.resource)
		} else {
			f.exec(`UPDATE oauth_resources SET allow_client_metadata=true,client_ids=ARRAY[$2] WHERE id=$1`, resourceID, published)
		}
		shadow := kernel.NewID().String()
		f.exec(`INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes,pkce_required,resource_only,disabled_at) VALUES($1,$2,$3,'Published client','public','{}','{}','{}',true,true,now())`, shadow, current.application, "p93_resource_"+shadow)
		f.exec(`INSERT INTO oauth_resource_clients(application_id,resource_id,client_id,client_database_id,metadata_digest,name,redirect_uris,allowed_grants) VALUES($1,$2,$3,$4,$5,'Published client',ARRAY['https://client.example.test/callback'],ARRAY['authorization_code','refresh_token'])`, current.application, resourceID, published, shadow, []byte("fixture-metadata"))
		rf := &resourceOAuthFixture{oauthSecurityFixture: current, resource: resourceID}
		form := rf.authorizationForm("billing:read")
		form.Set("client_id", published)
		form.Set("resource", resourceURI)
		w := f.call("GET", "/oidc/authorize?"+form.Encode(), nil, "", "192.0.2.1")
		if w.Code != 200 {
			t.Fatalf("app %d metadata interaction: %d %s", i, w.Code, w.Body)
		}
		view := decodeTestResponse(t, w)
		resource, ok := view["resource"].(map[string]any)
		if !ok || resource["id"] != resourceID || resource["uri"] != resourceURI || view["client_id"] != published || !reflect.DeepEqual(view["requested_scopes"], []any{"offline_access", current.scope("billing/read")}) {
			t.Fatalf("app %d metadata client resolved wrong owner: %s", i, w.Body)
		}
		// Stale metadata must not trigger outbound I/O during either POST.
		// This .test metadata URL is deliberately not network-resolvable.
		f.exec(`UPDATE oauth_resource_clients SET fetched_at=now()-interval '1 day' WHERE client_database_id=$1`, shadow)
		code := rf.resourceCode(form)
		body := rf.exchangeForm(code)
		body.Set("client_id", published)
		body.Set("resource", resourceURI)
		w = f.call("POST", "/oidc/token", body, "", "192.0.2.1")
		if w.Code != 200 {
			t.Errorf("app %d enrolled stale metadata token exchange: %d %s", i, w.Code, w.Body)
			continue
		}
		tokens := decodeTestResponse(t, w)
		claims, err := identity.Verify(tokens["access_token"].(string), func(kid string) (*rsa.PublicKey, error) { return f.app.ResolvePublicKey(context.Background(), kid) }, f.app.Issuer(), resourceURI, f.app.Now())
		if err != nil || claims.ApplicationID != current.application || claims.ClientID != published || len(claims.Audience) != 1 {
			t.Fatalf("app %d metadata token identity: %+v %v", i, claims, err)
		}
	}
}

func TestResourceOAuthPostgresPublishedClientRequiresEnrollment(t *testing.T) {
	f := newResourceOAuthFixture(t)
	published := "https://metadata.example.test/unenrolled-client.json"
	f.exec(`UPDATE oauth_resources SET allow_client_metadata=true,client_ids=ARRAY[$2] WHERE id=$1`, f.resource, published)
	// Neither a token POST nor a consent POST may enroll a remote identity.
	body := f.exchangeForm("unknown-code")
	body.Set("client_id", published)
	assertResourceTokenRejected(t, f.call("POST", "/oidc/token", body, "", "192.0.2.1"))
	form := f.authorizationForm("billing:read")
	form.Set("client_id", published)
	assertResourceTokenRejected(t, f.call("POST", "/oidc/authorize", form, f.accessToken(false), "192.0.2.1"))
	var count int
	if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM oauth_resource_clients`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("POST enrolled metadata client: %d %v", count, err)
	}
}

func TestResourceOAuthPostgresRefreshNarrowing(t *testing.T) {
	f := newResourceOAuthFixture(t)
	tokens := f.resourceTokens(f.authorizationForm("billing:read", "billing:write"))
	body := f.resourceRefresh(tokens["refresh_token"].(string))
	body.Set("scope", f.scope("billing/read")+" offline_access")
	for i := 0; i < 3; i++ {
		w := f.tokenCall(body)
		if w.Code != 200 {
			t.Fatalf("refresh %d: %d %s", i, w.Code, w.Body)
		}
		tokens = decodeTestResponse(t, w)
		claims := f.claims(tokens["access_token"].(string))
		if strings.Contains(claims.Scope, "billing/write") || !strings.Contains(claims.Scope, f.scope("billing/read")) {
			t.Fatalf("refresh %d lost narrowing: %s", i, claims.Scope)
		}
		f.assertCheck(tokens["access_token"].(string), "billing:write", nil, false)
		body = f.resourceRefresh(tokens["refresh_token"].(string))
	}
	body.Set("scope", f.scope("billing/write")+" offline_access")
	assertResourceTokenRejected(t, f.tokenCall(body))
}

func TestResourceOAuthPostgresApprovedCapabilityCeiling(t *testing.T) {
	f := newResourceOAuthFixture(t)
	form := f.authorizationForm("billing:read", "billing:write")
	form.Set("approved_capabilities", `["billing:read"]`)
	tokens := f.resourceTokens(form)
	for i := 0; i < 2; i++ {
		claims := f.claims(tokens["access_token"].(string))
		if strings.Contains(claims.Scope, "billing/write") {
			t.Fatalf("requested but unapproved capability leaked on rotation %d: %s", i, claims.Scope)
		}
		f.assertCheck(tokens["access_token"].(string), "billing:write", nil, false)
		w := f.tokenCall(f.resourceRefresh(tokens["refresh_token"].(string)))
		if w.Code != 200 {
			t.Fatalf("refresh: %d %s", w.Code, w.Body)
		}
		tokens = decodeTestResponse(t, w)
	}
}

func TestResourceOAuthPostgresClientGrantPolicy(t *testing.T) {
	f := newResourceOAuthFixture(t)
	f.exec(`UPDATE clients SET allowed_grants=ARRAY['authorization_code'] WHERE id=$1`, f.client)
	tokens := f.resourceTokens(f.authorizationForm("billing:read"))
	if _, present := tokens["refresh_token"]; present {
		t.Fatal("resource authorization expanded the registered client's grant types")
	}
	f.assertCheck(tokens["access_token"].(string), "billing:read", nil, true)
}

func TestResourceOAuthPostgresRejectsPersonalWorkspaceSelection(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		f := newResourceOAuthFixture(t)
		workspace := kernel.NewID().String()
		if !foreign {
			f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'selected','Selected workspace')`, workspace, f.application, f.user)
		}
		form := f.authorizationForm("billing:read")
		form.Set("workspace_ids", `["`+workspace+`"]`)
		w := f.call("POST", "/oidc/authorize", form, f.accessToken(false), "192.0.2.1")
		destination, _ := url.Parse(w.Header().Get("Location"))
		if destination == nil || destination.Query().Get("error") != "invalid_request" {
			t.Fatalf("personal-only workspace selection must be invalid_request, not server_error: %d %s %s", w.Code, w.Body, w.Header().Get("Location"))
		}
		var count int
		if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM oauth_connections`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("invalid selection persisted a connection: %d %v", count, err)
		}
	}
}

func TestResourceOAuthPostgresInvalidConsent(t *testing.T) {
	cases := map[string]func(*resourceOAuthFixture, url.Values){
		"unrequested capability": func(f *resourceOAuthFixture, v url.Values) { v.Set("approved_capabilities", `["billing:write"]`) },
		"duplicate capabilities": func(f *resourceOAuthFixture, v url.Values) {
			v.Set("approved_capabilities", `["billing:read","billing:read"]`)
		},
		"canonical approval instead of relative key": func(f *resourceOAuthFixture, v url.Values) {
			v.Set("approved_capabilities", `["`+f.scope("billing/read")+`"]`)
		},
		"no personal context": func(f *resourceOAuthFixture, v url.Values) { v.Set("personal_access", "false") },
		"PKCE missing":        func(f *resourceOAuthFixture, v url.Values) { v.Del("code_challenge"); v.Del("code_challenge_method") },
		"PKCE plain":          func(f *resourceOAuthFixture, v url.Values) { v.Set("code_challenge_method", "plain") },
		"duplicate resource":  func(f *resourceOAuthFixture, v url.Values) { v.Add("resource", resourceOAuthTestURI) },
		"application disabled": func(f *resourceOAuthFixture, v url.Values) {
			f.exec(`UPDATE applications SET internal_config=jsonb_set(internal_config,'{resource_authorization_enabled}','false') WHERE id=$1`, f.application)
		},
		"resource disabled": func(f *resourceOAuthFixture, v url.Values) {
			f.exec(`UPDATE oauth_resources SET enabled=false WHERE id=$1`, f.resource)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newResourceOAuthFixture(t)
			form := f.authorizationForm("billing:read")
			mutate(f, form)
			w := f.call("POST", "/oidc/authorize", form, f.accessToken(false), "192.0.2.1")
			if w.Code == 200 || w.Code >= 500 {
				t.Fatalf("unsafe consent result: %d %s", w.Code, w.Body)
			}
			location, _ := url.Parse(w.Header().Get("Location"))
			if location != nil && location.Query().Get("code") != "" {
				t.Fatal("invalid consent issued code")
			}
			var count int
			if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM oauth_connections`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid consent persisted connection: %d %v", count, err)
			}
		})
	}
}

func TestResourceOAuthPostgresResourceBinding(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		for _, target := range []string{"", "https://other-resource.example.test"} {
			t.Run(grant+"/"+target, func(t *testing.T) {
				f := newResourceOAuthFixture(t)
				f.exec(`INSERT INTO oauth_resources(application_id,uri,name,enabled,client_ids,capabilities) SELECT application_id,$2,'Other resource',true,client_ids,capabilities FROM oauth_resources WHERE id=$1`, f.resource, "https://other-resource.example.test")
				var body url.Values
				if grant == "authorization_code" {
					body = f.exchangeForm(f.resourceCode(f.authorizationForm("billing:read")))
				} else {
					body = f.resourceRefresh(f.resourceTokens(f.authorizationForm("billing:read"))["refresh_token"].(string))
				}
				if target == "" {
					body.Del("resource")
				} else {
					body.Set("resource", target)
				}
				assertResourceTokenRejected(t, f.tokenCall(body))
			})
		}
	}
}

func TestResourceOAuthPostgresLiveInvalidation(t *testing.T) {
	mutations := map[string]func(*resourceOAuthFixture){
		"application disabled": func(f *resourceOAuthFixture) {
			f.exec(`UPDATE applications SET internal_config=jsonb_set(internal_config,'{resource_authorization_enabled}','false') WHERE id=$1`, f.application)
		},
		"resource disabled": func(f *resourceOAuthFixture) {
			f.exec(`UPDATE oauth_resources SET enabled=false WHERE id=$1`, f.resource)
		},
		"resource version changed": func(f *resourceOAuthFixture) {
			f.exec(`UPDATE oauth_resources SET version=version+1 WHERE id=$1`, f.resource)
		},
		"session revoked": func(f *resourceOAuthFixture) {
			f.exec(`UPDATE user_sessions SET revoked_at=now() WHERE id=$1`, f.session)
		},
		"connection revoked": func(f *resourceOAuthFixture) { f.exec(`UPDATE oauth_connections SET revoked_at=now()`) },
		"permission removed": func(f *resourceOAuthFixture) { f.exec(`DELETE FROM role_assignments WHERE user_id=$1`, f.user) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newResourceOAuthFixture(t)
			tokens := f.resourceTokens(f.authorizationForm("billing:read"))
			token := tokens["access_token"].(string)
			f.assertCheck(token, "billing:read", nil, true)
			mutate(f)
			f.assertCheck(token, "billing:read", nil, false)
			if name != "permission removed" {
				assertResourceTokenRejected(t, f.tokenCall(f.resourceRefresh(tokens["refresh_token"].(string))))
			}
		})
	}
}

func TestResourceOAuthPostgresRevocationAndReplay(t *testing.T) {
	t.Run("access revocation is live", func(t *testing.T) {
		f := newResourceOAuthFixture(t)
		tokens := f.resourceTokens(f.authorizationForm("billing:read"))
		token := tokens["access_token"].(string)
		f.assertCheck(token, "billing:read", nil, true)
		r := httptest.NewRequest("POST", "/oidc/revoke", strings.NewReader(url.Values{"token": {token}, "token_type_hint": {"access_token"}, "resource": {resourceOAuthTestURI}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(f.client, "fixture-secret")
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("revoke: %d %s", w.Code, w.Body)
		}
		f.assertCheck(token, "billing:read", nil, false)
	})
	t.Run("code replay invalidates access", func(t *testing.T) {
		f := newResourceOAuthFixture(t)
		body := f.exchangeForm(f.resourceCode(f.authorizationForm("billing:read")))
		w := f.tokenCall(body)
		if w.Code != 200 {
			t.Fatalf("exchange: %d %s", w.Code, w.Body)
		}
		token := decodeTestResponse(t, w)["access_token"].(string)
		f.assertCheck(token, "billing:read", nil, true)
		assertResourceTokenRejected(t, f.tokenCall(body))
		f.assertCheck(token, "billing:read", nil, false)
	})
	t.Run("refresh has one concurrent winner", func(t *testing.T) {
		f := newResourceOAuthFixture(t)
		tokens := f.resourceTokens(f.authorizationForm("billing:read"))
		body := f.resourceRefresh(tokens["refresh_token"].(string))
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		lock, err := f.app.DB.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(context.Background())
		if _, err = lock.Exec(ctx, `SELECT id FROM oauth_sessions WHERE kind='refresh' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		results := make(chan *httptest.ResponseRecorder, 2)
		waitBlocked := func(want int) {
			t.Helper()
			for {
				var count int
				if err := f.app.DB.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count >= want {
					return
				}
				select {
				case <-ctx.Done():
					t.Fatal("refresh did not reach the database barrier")
				case <-time.After(10 * time.Millisecond):
				}
			}
		}
		go func() { results <- f.tokenCall(body) }()
		waitBlocked(1)
		// Separate JWT timestamps so signature collisions cannot hide a replay race.
		time.Sleep(1100 * time.Millisecond)
		go func() { results <- f.tokenCall(body) }()
		waitBlocked(2)
		if err = lock.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		wins := 0
		var winner map[string]any
		for i := 0; i < 2; i++ {
			select {
			case w := <-results:
				if w.Code == 200 {
					wins++
					winner = decodeTestResponse(t, w)
				} else {
					assertResourceTokenRejected(t, w)
				}
			case <-ctx.Done():
				t.Fatal("concurrent refresh timed out")
			}
		}
		if wins != 1 {
			t.Fatalf("refresh succeeded %d times", wins)
		}
		f.assertResourceFamilyRevoked(winner)
	})
}

func (f *resourceOAuthFixture) assertResourceFamilyRevoked(tokens map[string]any) {
	f.t.Helper()
	// Check storage before probing R1: a failed probe must not hide active successors.
	var access, refresh int
	if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE kind='access'),count(*) FILTER (WHERE kind='refresh') FROM oauth_sessions WHERE active AND kind IN ('access','refresh')`).Scan(&access, &refresh); err != nil {
		f.t.Fatal(err)
	}
	if access != 0 || refresh != 0 {
		f.t.Errorf("revoked refresh family retained active successors: access=%d refresh=%d", access, refresh)
	}
	w := f.check(tokens["access_token"].(string), f.machineToken(f.scope("resource_access/check")), "billing:read", nil)
	if w.Code != 200 || decodeTestResponse(f.t, w)["allowed"] != false {
		f.t.Errorf("successor access token survived family revocation: %d %s", w.Code, w.Body)
	}
	w = f.tokenCall(f.resourceRefresh(tokens["refresh_token"].(string)))
	if w.Code != 400 || decodeTestResponse(f.t, w)["error"] != "invalid_grant" && decodeTestResponse(f.t, w)["error"] != "invalid_request" {
		f.t.Errorf("successor refresh token survived family revocation: %d %s", w.Code, w.Body)
	}
}

func TestResourceOAuthPostgresRevokeRacesRefresh(t *testing.T) {
	f := newResourceOAuthFixture(t)
	tokens := f.resourceTokens(f.authorizationForm("billing:read"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	barrier, err := f.app.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Rollback(context.Background())
	if _, err = barrier.Exec(ctx, `SELECT pg_advisory_xact_lock(930093)`); err != nil {
		t.Fatal(err)
	}
	// R0 and A0 have been deactivated and A1 inserted when R1 reaches this barrier.
	f.exec(`CREATE FUNCTION block_refresh_successor() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='refresh' THEN PERFORM pg_advisory_xact_lock(930093); END IF; RETURN NEW; END $$`)
	f.exec(`CREATE TRIGGER block_refresh_successor BEFORE INSERT ON oauth_sessions FOR EACH ROW EXECUTE FUNCTION block_refresh_successor()`)
	refreshResults := make(chan *httptest.ResponseRecorder, 1)
	go func() { refreshResults <- f.tokenCall(f.resourceRefresh(tokens["refresh_token"].(string))) }()
	waitBlocked := func(want int) {
		t.Helper()
		for {
			var count int
			if err := f.app.DB.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count >= want {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("requests did not reach refresh/revoke storage barriers")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	waitBlocked(1)
	revokeResults := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "/oidc/revoke", strings.NewReader(url.Values{"token": {tokens["refresh_token"].(string)}, "token_type_hint": {"refresh_token"}, "resource": {resourceOAuthTestURI}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(f.client, "fixture-secret")
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, r)
		revokeResults <- w
	}()
	// Revocation must be in flight before rotation commits its successors.
	waitBlocked(2)
	if err = barrier.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var successors map[string]any
	select {
	case w := <-refreshResults:
		if w.Code != 200 {
			t.Fatalf("barrier-controlled rotation: %d %s", w.Code, w.Body)
		}
		successors = decodeTestResponse(t, w)
	case <-ctx.Done():
		t.Fatal("rotation did not finish")
	}
	select {
	case w := <-revokeResults:
		if w.Code != 200 {
			t.Fatalf("concurrent R0 revocation: %d %s", w.Code, w.Body)
		}
	case <-ctx.Done():
		t.Fatal("revocation did not finish")
	}
	f.assertResourceFamilyRevoked(successors)
}

func TestResourceOAuthPostgresWorkspaceOwner(t *testing.T) {
	f := newResourceOAuthFixture(t)
	f.exec(`UPDATE oauth_resources SET capabilities='[{"key":"billing:read","name":"Read workspace billing","context":"workspace","permissions":["billing:read"]}]' WHERE id=$1`, f.resource)
	workspace := kernel.NewID().String()
	f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'owned','Owned workspace')`, workspace, f.application, f.user)
	f.exec(`DELETE FROM role_assignments WHERE user_id=$1`, f.user)
	form := f.authorizationForm("billing:read")
	form.Set("personal_access", "false")
	form.Set("workspace_ids", `["`+workspace+`"]`)
	tokens := f.resourceTokens(form)
	token := tokens["access_token"].(string)
	f.assertCheck(token, "billing:read", &workspace, true)
	f.assertCheck(token, "billing:read", nil, false)
	other := kernel.NewID().String()
	f.assertCheck(token, "billing:read", &other, false)
	f.exec(`UPDATE workspaces SET deleted_at=now() WHERE id=$1`, workspace)
	f.assertCheck(token, "billing:read", &workspace, false)
}

func (f *resourceOAuthFixture) identityOnlyUserToken() string {
	f.t.Helper()
	kid, key, err := f.app.ActiveSigningKey(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	now := f.app.Now()
	token, err := identity.Sign(key, kid, identity.Claims{
		Issuer: f.app.Issuer(), Subject: f.user, ApplicationID: f.application, SessionID: f.session,
		Audience: []string{"platform93:application:" + f.application}, ActorType: "user", TokenKind: "access",
		Scope: "", Roles: emptyRoleClaims(), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), JWTID: kernel.NewID().String(),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

func TestResourceOAuthPostgresIdentityOnlyPersonalCapability(t *testing.T) {
	f := newResourceOAuthFixture(t)
	f.exec(`DELETE FROM role_assignments WHERE user_id=$1`, f.user)
	f.exec(`UPDATE oauth_resources SET capabilities='[{"key":"identity:read","name":"Identify user","context":"personal","permissions":[]}]' WHERE id=$1`, f.resource)
	code := f.resourceCodeAs(f.authorizationForm("identity:read"), f.identityOnlyUserToken())
	w := f.tokenCall(f.exchangeForm(code))
	if w.Code != 200 {
		t.Fatalf("identity-only exchange: %d %s", w.Code, w.Body)
	}
	tokens := decodeTestResponse(t, w)
	for rotation := 0; rotation < 2; rotation++ {
		token := tokens["access_token"].(string)
		claims := f.claims(token)
		if claims.Subject != f.user || claims.TokenKind != "resource_access" || !reflect.DeepEqual(claims.Audience, []string{resourceOAuthTestURI}) || claims.ConnectionID == "" {
			t.Fatalf("incorrect identity-only token: %+v", claims)
		}
		if len(claims.Roles.Application) != 0 || len(claims.Roles.Workspaces) != 0 {
			t.Fatalf("identity-only token fabricated roles: %+v", claims.Roles)
		}
		scopes := strings.Fields(claims.Scope)
		sort.Strings(scopes)
		want := []string{f.scope("identity/read"), "offline_access"}
		sort.Strings(want)
		if !reflect.DeepEqual(scopes, want) {
			t.Fatalf("identity-only capability fabricated authority: %v", scopes)
		}
		f.assertCheck(token, "identity:read", nil, true)
		f.assertCheck(token, "billing:read", nil, false)
		for _, path := range []string{"/v1/applications/" + f.application + "/me", "/oidc/userinfo"} {
			w := f.call("GET", path, nil, token, "192.0.2.1")
			if w.Code != 401 && w.Code != 403 {
				t.Fatalf("identity-only resource token escaped isolation: %d %s", w.Code, w.Body)
			}
		}
		if rotation == 0 {
			w = f.tokenCall(f.resourceRefresh(tokens["refresh_token"].(string)))
			if w.Code != 200 {
				t.Fatalf("identity-only refresh: %d %s", w.Code, w.Body)
			}
			tokens = decodeTestResponse(t, w)
		}
	}
	var assignments int
	if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM role_assignments WHERE user_id=$1`, f.user).Scan(&assignments); err != nil || assignments != 0 {
		t.Fatalf("identity-only flow required or created a default role: %d %v", assignments, err)
	}
}

func TestResourceOAuthPostgresIdentityOnlyWorkspaceCapability(t *testing.T) {
	for _, relationship := range []string{"owner", "member"} {
		t.Run(relationship, func(t *testing.T) {
			f := newResourceOAuthFixture(t)
			f.exec(`DELETE FROM role_assignments WHERE user_id=$1`, f.user)
			f.exec(`UPDATE oauth_resources SET capabilities='[{"key":"identity:read","name":"Identify workspace user","context":"workspace","permissions":[]}]' WHERE id=$1`, f.resource)
			otherUser := kernel.NewID().String()
			f.exec(`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'workspace-owner@example.test','workspace-owner@example.test')`, otherUser, f.application)
			selected, unselected, forbidden := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
			owner := f.user
			if relationship == "member" {
				owner = otherUser
			}
			f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'selected','Selected workspace'),($4,$2,$3,'unselected','Unselected workspace'),($5,$2,$6,'forbidden','Forbidden workspace')`, selected, f.application, owner, unselected, forbidden, otherUser)
			if relationship == "member" {
				f.exec(`INSERT INTO workspace_memberships(application_id,workspace_id,user_id) VALUES($1,$2,$3),($1,$4,$3)`, f.application, selected, f.user, unselected)
			}
			bearer := f.identityOnlyUserToken()
			form := f.authorizationForm("identity:read")
			form.Set("personal_access", "false")
			for _, workspaces := range []string{"[]", `["` + forbidden + `"]`} {
				form.Set("workspace_ids", workspaces)
				w := f.call("POST", "/oidc/authorize", form, bearer, "192.0.2.1")
				if w.Code == 200 || w.Code >= 500 {
					t.Fatalf("empty permissions bypassed workspace consent or membership: %d %s", w.Code, w.Body)
				}
				u, _ := url.Parse(w.Header().Get("Location"))
				if u.Query().Get("code") != "" {
					t.Fatal("unauthorized workspace issued a code")
				}
			}
			form.Set("workspace_ids", `["`+selected+`"]`)
			w := f.tokenCall(f.exchangeForm(f.resourceCodeAs(form, bearer)))
			if w.Code != 200 {
				t.Fatalf("identity-only workspace exchange: %d %s", w.Code, w.Body)
			}
			token := decodeTestResponse(t, w)["access_token"].(string)
			claims := f.claims(token)
			if len(claims.Roles.Application) != 0 || len(claims.Roles.Workspaces) != 0 || strings.Contains(claims.Scope, "*") || strings.Contains(claims.Scope, "/workspaces/") {
				t.Fatalf("workspace identity fabricated authority: %+v", claims)
			}
			f.assertCheck(token, "identity:read", &selected, true)
			f.assertCheck(token, "identity:read", nil, false)
			f.assertCheck(token, "identity:read", &unselected, false)
			f.assertCheck(token, "identity:read", &forbidden, false)
			if relationship == "owner" {
				f.exec(`UPDATE workspaces SET owner_user_id=$2 WHERE id=$1`, selected, otherUser)
			} else {
				f.exec(`DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2`, selected, f.user)
			}
			f.assertCheck(token, "identity:read", &selected, false)
		})
	}
}

func TestResourceOAuthPostgresExplicitEmptyPermissions(t *testing.T) {
	f := newResourceOAuthFixture(t)
	for _, tc := range []struct {
		name, permissions string
		valid             bool
	}{
		{name: "explicit empty", permissions: `,"permissions":[]`, valid: true},
		{name: "null", permissions: `,"permissions":null`},
		{name: "omitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var valid bool
			capabilities := `[{"key":"identity:read","name":"Identify user","context":"personal"` + tc.permissions + `}]`
			if err := f.app.DB.QueryRow(context.Background(), `SELECT valid_resource_capabilities($1::jsonb)`, capabilities).Scan(&valid); err != nil {
				t.Fatal(err)
			}
			if valid != tc.valid {
				t.Fatalf("capability permissions validation = %v, want %v", valid, tc.valid)
			}
		})
	}
}
