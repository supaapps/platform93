package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
)

func TestResourceOAuthHostedPostgresJourney(t *testing.T) {
	for _, reset := range []string{"", "restart", "switch_account", "logout"} {
		name := reset
		if name == "" {
			name = "password consent"
		}
		t.Run(name, func(t *testing.T) {
			f := newResourceOAuthFixture(t)
			const password = "Disposable hosted resource password!"
			hash, err := identity.HashPassword(password)
			if err != nil {
				t.Fatal(err)
			}
			f.exec(`UPDATE users SET password_hash=$2 WHERE id=$1`, f.user, hash)
			f.exec(`UPDATE clients SET authorization_ui='hosted',pkce_required=true WHERE id=$1`, f.client)
			f.exec(`UPDATE oauth_resources SET capabilities='[
				{"key":"billing:read","name":"Read personal billing","context":"personal","permissions":["billing:read"]},
				{"key":"billing:write","name":"Write personal billing","context":"personal","permissions":["billing:write"]},
				{"key":"billing:workspace_read","name":"Read workspace billing","context":"workspace","permissions":["billing:read"]}
			]' WHERE id=$1`, f.resource)
			selected, unselected := kernel.NewID().String(), kernel.NewID().String()
			f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'selected','Selected workspace'),($4,$2,$3,'unselected','Unselected workspace')`, selected, f.application, f.user, unselected)

			var browser *http.Cookie
			call := func(method, target, body, csrf, accept string) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, target, strings.NewReader(body))
				r.RemoteAddr = "192.0.2.10:1234"
				r.Header.Set("Origin", f.app.PublicURL)
				r.Header.Set("Accept", accept)
				if body != "" {
					r.Header.Set("Content-Type", "application/json")
				}
				if csrf != "" {
					r.Header.Set("X-CSRF-Token", csrf)
				}
				if browser != nil {
					r.AddCookie(browser)
				}
				w := httptest.NewRecorder()
				f.router.ServeHTTP(w, r)
				for _, cookie := range w.Result().Cookies() {
					if strings.Contains(cookie.Name, "hosted_browser") {
						browser = cookie
					}
				}
				return w
			}
			view := func(w *httptest.ResponseRecorder, stage string) map[string]any {
				t.Helper()
				if w.Code != http.StatusOK {
					t.Fatalf("hosted %s: %d %s", stage, w.Code, w.Body)
				}
				result := decodeTestResponse(t, w)
				if result["stage"] != stage {
					t.Fatalf("want hosted stage %s: %s", stage, w.Body)
				}
				if strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "refresh_token") {
					t.Fatal("hosted view leaked bearer credentials")
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("hosted view must not be cached")
				}
				return result
			}
			assertConsent := func(result map[string]any) {
				t.Helper()
				consent, ok := result["resource_consent"].(map[string]any)
				if !ok {
					t.Fatalf("resource consent missing: %#v", result)
				}
				resource, ok := consent["resource"].(map[string]any)
				if !ok || resource["id"] != f.resource || resource["uri"] != resourceOAuthTestURI || resource["version"] != float64(1) {
					t.Fatalf("resource snapshot lost: %#v", consent)
				}
				if consent["personal_access_available"] != true {
					t.Fatal("personal capability unavailable")
				}
				capabilities, ok := consent["capabilities"].([]any)
				if !ok || len(capabilities) != 3 {
					t.Fatalf("incorrect consent capabilities: %#v", consent)
				}
				contexts := map[string]string{}
				for _, value := range capabilities {
					capability, ok := value.(map[string]any)
					if !ok {
						t.Fatalf("invalid capability: %#v", value)
					}
					key, _ := capability["key"].(string)
					capContext, _ := capability["context"].(string)
					contexts[key] = capContext
				}
				if !reflect.DeepEqual(contexts, map[string]string{"billing:read": "personal", "billing:write": "personal", "billing:workspace_read": "workspace"}) {
					t.Fatalf("incorrect capability contexts: %#v", contexts)
				}
				workspaces, ok := consent["workspaces"].([]any)
				if !ok || len(workspaces) != 2 {
					t.Fatalf("available workspaces missing: %#v", consent)
				}
				ids := map[string]bool{}
				for _, value := range workspaces {
					workspace, ok := value.(map[string]any)
					if !ok {
						t.Fatalf("invalid workspace: %#v", value)
					}
					id, _ := workspace["id"].(string)
					ids[id] = true
				}
				if !ids[selected] || !ids[unselected] {
					t.Fatalf("incorrect workspace selection: %#v", workspaces)
				}
			}

			params := f.authorizationForm("billing:read", "billing:write", "billing:workspace_read")
			// Hosted approvals must use the server's snapshot, not headless consent fields.
			for _, key := range []string{"resource_version", "approved_capabilities", "personal_access", "workspace_ids", "decision"} {
				params.Del(key)
			}
			if reset == "switch_account" {
				params.Set("prompt", "select_account")
			}
			w := call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
			if w.Code != http.StatusSeeOther || browser == nil {
				t.Fatalf("hosted resource start: %d %s Location=%s", w.Code, w.Body, w.Header().Get("Location"))
			}
			if !browser.HttpOnly || !browser.Secure {
				t.Fatal("hosted browser cookie is not protected")
			}
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil || location.Path != "/auth/" || location.Query().Get("interaction") == "" {
				t.Fatalf("invalid hosted interaction redirect: %s", w.Header().Get("Location"))
			}
			interaction := location.Query().Get("interaction")
			base := "/v1/auth/hosted/interactions/" + interaction
			loginView := view(call("GET", base, "", "", "application/json"), "login")
			csrf, ok := loginView["csrf_token"].(string)
			if !ok || csrf == "" {
				t.Fatal("missing hosted CSRF token")
			}
			login := func() map[string]any {
				t.Helper()
				body, err := json.Marshal(map[string]string{"action": "password", "email": "user@example.test", "password": password})
				if err != nil {
					t.Fatal(err)
				}
				return view(call("POST", base+"/actions", string(body), csrf, "application/json"), "consent")
			}
			resetInteraction := func() {
				t.Helper()
				body, err := json.Marshal(map[string]string{"action": reset})
				if err != nil {
					t.Fatal(err)
				}
				loginView = view(call("POST", base+"/actions", string(body), csrf, "application/json"), "login")
				csrf, ok = loginView["csrf_token"].(string)
				if !ok || csrf == "" {
					t.Fatal("reset lost CSRF token")
				}
				view(call("GET", base, "", "", "application/json"), "login")
			}
			if reset == "restart" {
				resetInteraction()
			}
			assertConsent(login())
			if reset == "switch_account" || reset == "logout" {
				resetInteraction()
				assertConsent(login())
			}
			assertConsent(view(call("GET", base, "", "", "application/json"), "consent"))
			body, err := json.Marshal(map[string]any{"action": "approve", "approved_capabilities": []string{"billing:read", "billing:workspace_read"}, "personal_access": true, "workspace_ids": []string{selected}})
			if err != nil {
				t.Fatal(err)
			}
			w = call("POST", base+"/actions", string(body), csrf, "application/json")
			if w.Code != http.StatusOK {
				t.Fatalf("hosted resource approve: %d %s", w.Code, w.Body)
			}
			redirect, _ := decodeTestResponse(t, w)["redirect_url"].(string)
			callback, err := url.Parse(redirect)
			if err != nil || callback.Query().Get("code") == "" || callback.Query().Get("error") != "" || callback.Query().Get("state") != params.Get("state") || callback.Query().Get("iss") != f.app.Issuer() {
				t.Fatalf("hosted resource approval did not issue a bound code: %s", redirect)
			}
			w = f.tokenCall(f.exchangeForm(callback.Query().Get("code")))
			if w.Code != http.StatusOK {
				t.Fatalf("hosted resource exchange: %d %s", w.Code, w.Body)
			}
			tokens := decodeTestResponse(t, w)
			token := tokens["access_token"].(string)
			claims := f.claims(token)
			if claims.Subject != f.user || claims.ApplicationID != f.application || claims.ClientID != f.client || claims.TokenKind != "resource_access" || claims.ConnectionID == "" || !reflect.DeepEqual(claims.Audience, []string{resourceOAuthTestURI}) {
				t.Fatalf("incorrect hosted resource identity: %+v", claims)
			}
			if len(claims.Roles.Application) != 0 || len(claims.Roles.Workspaces) != 0 {
				t.Fatalf("hosted resource token leaked roles: %+v", claims.Roles)
			}
			scopes := strings.Fields(claims.Scope)
			sort.Strings(scopes)
			want := []string{f.scope("billing/read"), f.scope("billing/workspace_read"), "offline_access"}
			sort.Strings(want)
			if !reflect.DeepEqual(scopes, want) {
				t.Fatalf("hosted approval lost capability narrowing: %v", scopes)
			}
			var hostedSession string
			if err := f.app.DB.QueryRow(context.Background(), `SELECT session_id FROM hosted_auth_interactions WHERE id=$1 AND consumed_at IS NOT NULL`, interaction).Scan(&hostedSession); err != nil {
				t.Fatal(err)
			}
			if claims.SessionID != hostedSession || claims.SessionID == f.session {
				t.Fatal("resource token did not bind the password-authenticated hosted session")
			}
			f.assertCheck(token, "billing:read", nil, true)
			f.assertCheck(token, "billing:write", nil, false)
			f.assertCheck(token, "billing:workspace_read", &selected, true)
			f.assertCheck(token, "billing:workspace_read", &unselected, false)
		})
	}
}
