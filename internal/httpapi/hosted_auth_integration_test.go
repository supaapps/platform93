package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestHostedAuthenticationCodeFlow(t *testing.T) {
	dsn := os.Getenv("PLATFORM93_DATABASE_URL")
	if dsn == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(dsn); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := database.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app := platform.New(db, vault, "https://platform93.test")
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = app.EnsureSigningKey(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	org, application, user, client := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	email := "hosted+" + application + "@example.test"
	password := "A disposable test password!"
	hash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Hosted test',$1::uuid::text)`, []any{org}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Hosted test',$1::uuid::text)`, []any{application, org}},
		{`INSERT INTO users(id,application_id,email,normalized_email,first_name,last_name,password_hash,email_verified_at) VALUES($1,$2,$4,$4,'Hosted','User',$3,now())`, []any{user, application, hash, email}},
		{`INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes,secret_digest,authorization_ui,pkce_required) VALUES($1,$2,$1::uuid::text,'Confidential web app','confidential',ARRAY['https://client.example.test/callback'],ARRAY['authorization_code','refresh_token'],ARRAY['openid','email','profile'],$3,'hosted',false)`, []any{client, application, vault.Digest("test-client-secret")}},
	} {
		if _, err := db.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = db.Exec(ctx, `DELETE FROM hosted_auth_interactions WHERE application_id=$1`, application)
		_, _ = db.Exec(ctx, `DELETE FROM hosted_auth_sessions WHERE application_id=$1`, application)
		_, _ = db.Exec(ctx, `DELETE FROM oauth_consents WHERE application_id=$1`, application)
		_, _ = db.Exec(ctx, `DELETE FROM oauth_sessions WHERE application_id=$1`, application)
		_, _ = db.Exec(ctx, `DELETE FROM user_sessions WHERE application_id=$1`, application)
		_, _ = db.Exec(ctx, `DELETE FROM clients WHERE application_id=$1`, application)
		_, _ = db.Exec(ctx, `DELETE FROM users WHERE application_id=$1`, application)
		_, _ = db.Exec(ctx, `DELETE FROM applications WHERE id=$1`, application)
		_, _ = db.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org)
	}()
	router := New(app, filepath.Join("..", "..", "web", "out"))
	var browser *http.Cookie
	call := func(method, target, body, csrf, accept string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		fixtureIP := sha256.Sum256([]byte(application))
		r.RemoteAddr = fmt.Sprintf("192.0.%d.%d:1234", fixtureIP[0], fixtureIP[1])
		r.Header.Set("Origin", app.PublicURL)
		r.Header.Set("Accept", accept)
		if strings.HasPrefix(body, "{") {
			r.Header.Set("Content-Type", "application/json")
		} else if body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if browser != nil {
			r.AddCookie(browser)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		for _, cookie := range w.Result().Cookies() {
			if strings.Contains(cookie.Name, "hosted_browser") {
				browser = cookie
			}
		}
		return w
	}
	params := url.Values{"client_id": {client}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid email profile"}, "state": {"a-sufficiently-long-rp-state"}, "nonce": {"a-sufficiently-long-rp-nonce"}}
	params.Set("prompt", "none")
	w := call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
	silent, _ := url.Parse(w.Header().Get("Location"))
	if silent.Query().Get("error") != "login_required" || silent.Query().Get("state") != params.Get("state") {
		t.Fatalf("silent unauthenticated: %d %s", w.Code, w.Header().Get("Location"))
	}
	params.Del("prompt")
	t.Run("client patches preserve omitted hosted policy", func(t *testing.T) {
		patch := func(body string) {
			r := httptest.NewRequest("PATCH", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			params := chi.NewRouteContext()
			params.URLParams.Add("application_id", application)
			params.URLParams.Add("client_id", client)
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, params))
			w := httptest.NewRecorder()
			(&Server{app: app}).updateClient(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("patch: %d %s", w.Code, w.Body.String())
			}
		}
		patch(`{"pkce_required":true}`)
		patch(`{"name":"Renamed client"}`)
		var required bool
		var ui string
		if err := db.QueryRow(ctx, `SELECT pkce_required,authorization_ui FROM clients WHERE id=$1`, client).Scan(&required, &ui); err != nil || !required || ui != "hosted" {
			t.Fatalf("omitted policy changed: %v %s %v", required, ui, err)
		}
		patch(`{"pkce_required":false}`)
	})
	w = call("GET", "/oidc/authorize?"+params.Encode(), "", "", "application/json")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"interaction":"consent"`) {
		t.Fatalf("headless: %d %s", w.Code, w.Body.String())
	}
	w = call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
	if w.Code != 303 || browser == nil {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	location, _ := url.Parse(w.Header().Get("Location"))
	interaction := location.Query().Get("interaction")
	base := "/v1/auth/hosted/interactions/" + interaction
	read := func(w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var v map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatalf("json: %d %s", w.Code, w.Body.String())
		}
		return v
	}
	w = call("GET", base, "", "", "application/json")
	if w.Code != 200 {
		t.Fatalf("view: %d %s", w.Code, w.Body.String())
	}
	view := read(w)
	csrf := view["csrf_token"].(string)
	savedBrowser := browser
	browser = nil
	if isolated := call("GET", base, "", "", "application/json"); isolated.Code != 401 {
		t.Fatal("another browser read an interaction")
	}
	browser = savedBrowser
	if !browser.HttpOnly || !browser.Secure {
		t.Fatal("hosted cookie is not protected")
	}
	w = call("POST", base+"/actions", `{"action":"password","email":"`+email+`","password":"`+password+`"}`, "wrong", "application/json")
	if w.Code != 403 {
		t.Fatalf("csrf: %d %s", w.Code, w.Body.String())
	}
	w = call("POST", base+"/actions", `{"action":"password","email":"`+email+`","password":"`+password+`"}`, csrf, "application/json")
	if w.Code != 200 || read(w)["stage"] != "consent" {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "refresh_token") {
		t.Fatal("bearer credentials leaked to hosted browser")
	}
	w = call("POST", base+"/actions", `{"action":"approve"}`, csrf, "application/json")
	if w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	callback, _ := url.Parse(read(w)["redirect_url"].(string))
	code := callback.Query().Get("code")
	if code == "" || callback.Query().Get("state") != params.Get("state") {
		t.Fatalf("callback: %s", callback)
	}
	w = call("POST", base+"/actions", `{"action":"approve"}`, csrf, "application/json")
	if w.Code != 401 {
		t.Fatalf("interaction replay: %d %s", w.Code, w.Body.String())
	}
	tokenBody := url.Values{"client_id": {client}, "client_secret": {"test-client-secret"}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {params.Get("redirect_uri")}}.Encode()
	w = call("POST", "/oidc/token", tokenBody, "", "application/json")
	if w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	tokens := read(w)
	if tokens["id_token"] == nil || tokens["access_token"] == nil {
		t.Fatalf("missing oidc tokens: %s", w.Body.String())
	}
	idClaims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokens["id_token"].(string), idClaims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		return app.ResolvePublicKey(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(app.Issuer()), jwt.WithAudience(client))
	if err != nil || idClaims["sub"] != user || idClaims["nonce"] != params.Get("nonce") || idClaims["name"] != "Hosted User" {
		t.Fatalf("OIDC ID claims: %v %#v", err, idClaims)
	}
	r := httptest.NewRequest("GET", "/oidc/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	info := httptest.NewRecorder()
	router.ServeHTTP(info, r)
	if info.Code != 200 || read(info)["sub"] != user || read(info)["name"] != "Hosted User" {
		t.Fatalf("userinfo: %d %s", info.Code, info.Body.String())
	}
	w = call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
	if w.Code != 303 || strings.HasPrefix(w.Header().Get("Location"), "/auth/") {
		t.Fatalf("session reuse: %d %s", w.Code, w.Header().Get("Location"))
	}
	reused, _ := url.Parse(w.Header().Get("Location"))
	basicBody := url.Values{"grant_type": {"authorization_code"}, "code": {reused.Query().Get("code")}, "redirect_uri": {params.Get("redirect_uri")}}.Encode()
	basicRequest := httptest.NewRequest("POST", "/oidc/token", strings.NewReader(basicBody))
	basicRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basicRequest.SetBasicAuth(client, "test-client-secret")
	basicResponse := httptest.NewRecorder()
	router.ServeHTTP(basicResponse, basicRequest)
	if basicResponse.Code != 200 {
		t.Fatalf("Basic client authentication: %d %s", basicResponse.Code, basicResponse.Body.String())
	}
	t.Run("email code and cross-interaction link rejection", func(t *testing.T) {
		params.Set("prompt", "login")
		defer params.Del("prompt")
		w := call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
		location, _ := url.Parse(w.Header().Get("Location"))
		id := location.Query().Get("interaction")
		base := "/v1/auth/hosted/interactions/" + id
		view := read(call("GET", base, "", "", "application/json"))
		csrf := view["csrf_token"].(string)
		w = call("POST", base+"/actions", `{"action":"email_start","email":"`+email+`"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["stage"] != "email_code" {
			t.Fatalf("email start: %d %s", w.Code, w.Body.String())
		}
		var challenge string
		if err := db.QueryRow(ctx, `SELECT id FROM login_challenges WHERE application_id=$1 AND normalized_email=$2 ORDER BY created_at DESC LIMIT 1`, application, email).Scan(&challenge); err != nil {
			t.Fatal(err)
		}
		w = call("POST", base+"/return", `{"challenge_id":"`+kernel.NewID().String()+`","link_token":"wrong"}`, csrf, "application/json")
		if w.Code != 401 {
			t.Fatal("unrelated email challenge accepted")
		}
		if _, err := db.Exec(ctx, `UPDATE login_challenges SET code_digest=$2 WHERE id=$1`, challenge, vault.Digest("ABCDEFGH")); err != nil {
			t.Fatal(err)
		}
		w = call("POST", base+"/actions", `{"action":"email_verify","code":"ABCDEFGH"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["stage"] != "consent" || strings.Contains(w.Body.String(), "access_token") {
			t.Fatalf("email verify: %d %s", w.Code, w.Body.String())
		}
		w = call("POST", base+"/actions", `{"action":"email_verify","code":"ABCDEFGH"}`, csrf, "application/json")
		if w.Code == 200 {
			t.Fatal("email credential replay accepted")
		}
	})
	t.Run("prompt login and cancellation", func(t *testing.T) {
		params.Set("prompt", "login")
		defer params.Del("prompt")
		w := call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
		location, _ := url.Parse(w.Header().Get("Location"))
		base := "/v1/auth/hosted/interactions/" + location.Query().Get("interaction")
		view := read(call("GET", base, "", "", "application/json"))
		if view["stage"] != "login" {
			t.Fatal("prompt login reused session")
		}
		w = call("POST", base+"/actions", `{"action":"deny"}`, view["csrf_token"].(string), "application/json")
		if w.Code != 200 {
			t.Fatalf("cancel: %s", w.Body.String())
		}
		destination, _ := url.Parse(read(w)["redirect_url"].(string))
		if destination.Query().Get("error") != "access_denied" || destination.Query().Get("state") != params.Get("state") {
			t.Fatalf("cancel target: %s", destination)
		}
	})
	t.Run("required MFA and server-side account switching", func(t *testing.T) {
		method := kernel.NewID().String()
		if _, err := db.Exec(ctx, `INSERT INTO user_authentication_methods(id,application_id,user_id,method_type,status) VALUES($1,$2,$3,'totp','active')`, method, application, user); err != nil {
			t.Fatal(err)
		}
		defer db.Exec(ctx, `DELETE FROM user_authentication_methods WHERE id=$1`, method)
		if _, err := db.Exec(ctx, `INSERT INTO user_recovery_codes(id,application_id,user_id,code_digest) VALUES($1,$2,$3,$4)`, kernel.NewID().String(), application, user, vault.Digest("TEST-RECOVERY")); err != nil {
			t.Fatal(err)
		}
		defer db.Exec(ctx, `DELETE FROM user_recovery_codes WHERE application_id=$1 AND user_id=$2`, application, user)
		params.Set("prompt", "login")
		defer params.Del("prompt")
		w := call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
		location, _ := url.Parse(w.Header().Get("Location"))
		base := "/v1/auth/hosted/interactions/" + location.Query().Get("interaction")
		view := read(call("GET", base, "", "", "application/json"))
		csrf := view["csrf_token"].(string)
		w = call("POST", base+"/actions", `{"action":"password","email":"`+email+`","password":"`+password+`"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["stage"] != "mfa" {
			t.Fatalf("MFA required: %d %s", w.Code, w.Body.String())
		}
		if denied := call("POST", base+"/actions", `{"action":"approve"}`, csrf, "application/json"); denied.Code != 401 {
			t.Fatal("MFA bypassed by consent approval")
		}
		w = call("POST", base+"/actions", `{"action":"mfa","recovery_code":"TEST-RECOVERY"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["stage"] != "consent" {
			t.Fatalf("MFA completion: %d %s", w.Code, w.Body.String())
		}
		w = call("POST", base+"/actions", `{"action":"switch_account"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["stage"] != "login" {
			t.Fatalf("switch account: %d %s", w.Code, w.Body.String())
		}
		var bindings int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM hosted_auth_sessions WHERE application_id=$1 AND browser_digest=$2`, application, vault.Digest(browser.Value)).Scan(&bindings); err != nil || bindings != 0 {
			t.Fatal("switch account retained hosted binding")
		}
		// Restore a normal session for the following public-client test.
		if _, err := db.Exec(ctx, `DELETE FROM user_authentication_methods WHERE id=$1`, method); err != nil {
			t.Fatal(err)
		}
		w = call("POST", base+"/actions", `{"action":"password","email":"`+email+`","password":"`+password+`"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["stage"] != "consent" {
			t.Fatal("account could not sign in again after switching")
		}
	})
	t.Run("strict PKCE with a public hosted client", func(t *testing.T) {
		public := kernel.NewID().String()
		if _, err := db.Exec(ctx, `INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_scopes,authorization_ui) VALUES($1,$2,$1::uuid::text,'Public','public',ARRAY['https://client.example.test/callback'],ARRAY['openid','email','profile'],'hosted')`, public, application); err != nil {
			t.Fatal(err)
		}
		params.Set("client_id", public)
		defer params.Set("client_id", client)
		w := call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
		if strings.HasPrefix(w.Header().Get("Location"), "/auth/") {
			t.Fatal("public client bypassed PKCE")
		}
		verifier := strings.Repeat("a", 43)
		digest := sha256.Sum256([]byte(verifier))
		params.Set("code_challenge", base64.RawURLEncoding.EncodeToString(digest[:]))
		params.Set("code_challenge_method", "S256")
		defer params.Del("code_challenge")
		defer params.Del("code_challenge_method")
		w = call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
		location, _ := url.Parse(w.Header().Get("Location"))
		base := "/v1/auth/hosted/interactions/" + location.Query().Get("interaction")
		view := read(call("GET", base, "", "", "application/json"))
		w = call("POST", base+"/actions", `{"action":"approve"}`, view["csrf_token"].(string), "application/json")
		destination, _ := url.Parse(read(w)["redirect_url"].(string))
		body := url.Values{"client_id": {public}, "grant_type": {"authorization_code"}, "code": {destination.Query().Get("code")}, "redirect_uri": {params.Get("redirect_uri")}, "code_verifier": {strings.Repeat("b", 43)}}.Encode()
		w = call("POST", "/oidc/token", body, "", "application/json")
		if w.Code == 200 {
			t.Fatal("incorrect verifier accepted")
		}
	})
	t.Run("hosted invitation starts fresh application login", func(t *testing.T) {
		if _, err := db.Exec(ctx, `UPDATE clients SET initiate_login_uri='https://client.example.test/auth/start' WHERE id=$1`, client); err != nil {
			t.Fatal(err)
		}
		invitation := kernel.NewID().String()
		credential := kernel.NewID().String()
		if _, err := db.Exec(ctx, `INSERT INTO application_invitations(id,application_id,normalized_email,link_credential_digest,code_credential_digest,hosted_client_id,hosted_redirect_uri,expires_at) VALUES($1,$2,'invited@example.test',$3,$4,$5,'https://client.example.test/callback',now()+interval '1 day')`, invitation, application, vault.Digest(credential), vault.Digest("ABCDEFGH"), client); err != nil {
			t.Fatal(err)
		}
		defer db.Exec(ctx, `DELETE FROM application_invitations WHERE id=$1`, invitation)
		for attempt := 0; attempt < 11; attempt++ {
			invalid := call("GET", "/auth/invitations/"+invitation+"?link_token=invalid-token", "", "", "text/html")
			if attempt == 10 && invalid.Code != http.StatusTooManyRequests {
				t.Fatalf("invalid-token rate limit: %d", invalid.Code)
			}
		}
		w := call("GET", "/auth/invitations/"+invitation+"?link_token="+credential, "", "", "text/html")
		if w.Code != http.StatusSeeOther {
			t.Fatalf("invalid tokens poisoned valid invitation: %d %s", w.Code, w.Body.String())
		}
		location, _ := url.Parse(w.Header().Get("Location"))
		base := "/v1/auth/hosted/interactions/" + location.Query().Get("interaction")
		view := read(call("GET", base, "", "", "application/json"))
		if view["stage"] != "invitation" {
			t.Fatalf("invite stage: %#v", view)
		}
		second := call("GET", "/auth/invitations/"+invitation+"?link_token="+credential, "", "", "text/html")
		secondLocation, _ := url.Parse(second.Header().Get("Location"))
		secondBase := "/v1/auth/hosted/interactions/" + secondLocation.Query().Get("interaction")
		secondView := read(call("GET", secondBase, "", "", "application/json"))
		csrf := view["csrf_token"].(string)
		w = call("POST", base+"/actions", `{"action":"restart"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["stage"] != "invitation" {
			t.Fatalf("restart lost invitation: %d %s", w.Code, w.Body.String())
		}
		w = call("POST", base+"/actions", `{"action":"invitation"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["stage"] != "consent" {
			t.Fatalf("accept: %d %s", w.Code, w.Body.String())
		}
		restarted := call("POST", secondBase+"/actions", `{"action":"restart"}`, secondView["csrf_token"].(string), "application/json")
		if restarted.Code != 200 || read(restarted)["redirect_url"] != "https://client.example.test/auth/start" {
			t.Fatalf("restart after acceptance: %d %s", restarted.Code, restarted.Body.String())
		}
		w = call("POST", base+"/actions", `{"action":"approve"}`, csrf, "application/json")
		if w.Code != 200 || read(w)["redirect_url"] != "https://client.example.test/auth/start" {
			t.Fatalf("invite completion: %d %s", w.Code, w.Body.String())
		}
		w = call("GET", "/auth/invitations/"+invitation+"?link_token="+credential, "", "", "text/html")
		if w.Code != 401 {
			t.Fatal("invite link replay accepted")
		}
	})
	t.Run("branding inheritance", func(t *testing.T) {
		for _, record := range []struct{ scope, id, configuration string }{
			{"installation", "00000000-0000-0000-0000-000000000000", `{"display_name":"Installation","copy":{"en":{"heading":"Welcome","help":"Inherited help"}}}`},
			{"organization", org, `{"display_name":"Organization","layout":"split"}`},
			{"application", application, `{"display_name":"Application","copy":{"en":{"heading":"Application login"}}}`},
		} {
			if _, err := db.Exec(ctx, `INSERT INTO hosted_auth_branding(scope_type,scope_id,configuration) VALUES($1,$2,$3) ON CONFLICT(scope_type,scope_id) DO UPDATE SET configuration=EXCLUDED.configuration`, record.scope, record.id, record.configuration); err != nil {
				t.Fatal(err)
			}
			defer db.Exec(ctx, `DELETE FROM hosted_auth_branding WHERE scope_type=$1 AND scope_id=$2`, record.scope, record.id)
		}
		branding, err := (&Server{app: app}).effectiveHostedBranding(ctx, application)
		if err != nil || branding.DisplayName != "Application" || branding.Layout != "split" || branding.Copy["en"].Heading != "Application login" || branding.Copy["en"].Help != "Inherited help" {
			t.Fatalf("inheritance: %#v %v", branding, err)
		}
		parent, err := (&Server{app: app}).resolveHostedBranding(ctx, "application", application, false)
		if err != nil || parent.DisplayName != "Organization" || parent.Copy["en"].Heading != "Welcome" || parent.Copy["en"].Help != "Inherited help" {
			t.Fatalf("parent inheritance: %#v %v", parent, err)
		}
		defaults, err := (&Server{app: app}).resolveHostedBranding(ctx, "installation", installationBrandingID, false)
		if err != nil || defaults.DisplayName != "Platform93" || defaults.Copy["en"].Heading != "Sign in" {
			t.Fatalf("installation defaults: %#v %v", defaults, err)
		}
	})
	t.Run("recovery stage survives reloading the interaction", func(t *testing.T) {
		params.Set("prompt", "login")
		w := call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
		location, _ := url.Parse(w.Header().Get("Location"))
		base := "/v1/auth/hosted/interactions/" + location.Query().Get("interaction")
		w = call("GET", base, "", "", "application/json")
		var view map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &view)
		csrf, _ := view["csrf_token"].(string)
		w = call("POST", base+"/actions", `{"action":"reset_start","email":"unavailable@example.test"}`, csrf, "application/json")
		if w.Code != 200 {
			t.Fatalf("start recovery: %d %s", w.Code, w.Body.String())
		}
		w = call("GET", base, "", "", "application/json")
		_ = json.Unmarshal(w.Body.Bytes(), &view)
		if view["stage"] != "recovery" {
			t.Fatalf("recovery lost on reload: %s", w.Body.String())
		}
		params.Del("prompt")
	})
	t.Run("consent remains bound to its selected account across tabs", func(t *testing.T) {
		otherUser := kernel.NewID().String()
		otherEmail := "second+" + application + "@example.test"
		if _, err := db.Exec(ctx, `INSERT INTO users(id,application_id,email,normalized_email,password_hash,email_verified_at) VALUES($1,$2,$3,$3,$4,now())`, otherUser, application, otherEmail, hash); err != nil {
			t.Fatal(err)
		}
		start := func(login string) (string, string) {
			params.Set("prompt", "login")
			defer params.Del("prompt")
			response := call("GET", "/oidc/authorize?"+params.Encode(), "", "", "text/html")
			location, _ := url.Parse(response.Header().Get("Location"))
			path := "/v1/auth/hosted/interactions/" + location.Query().Get("interaction")
			view := read(call("GET", path, "", "", "application/json"))
			csrf := view["csrf_token"].(string)
			body, _ := json.Marshal(map[string]string{"action": "password", "email": login, "password": password})
			response = call("POST", path+"/actions", string(body), csrf, "application/json")
			if response.Code != 200 || read(response)["stage"] != "consent" {
				t.Fatalf("login: %d %s", response.Code, response.Body.String())
			}
			return path, csrf
		}
		first, firstCSRF := start(email)
		second, _ := start(otherEmail)
		firstView := read(call("GET", first, "", "", "application/json"))
		if firstView["user"].(map[string]any)["email"] != email {
			t.Fatalf("account changed across tabs: %#v", firstView)
		}
		response := call("POST", first+"/actions", `{"action":"approve"}`, firstCSRF, "application/json")
		callback, _ := url.Parse(read(response)["redirect_url"].(string))
		if callback.Query().Get("code") == "" {
			t.Fatalf("two-tab authorization: %s", callback.Query().Get("error_description"))
		}
		body := url.Values{"client_id": {client}, "client_secret": {"test-client-secret"}, "grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {params.Get("redirect_uri")}}.Encode()
		response = call("POST", "/oidc/token", body, "", "application/json")
		if response.Code != http.StatusOK {
			t.Fatalf("two-tab token exchange: %d %s", response.Code, response.Body.String())
		}
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(read(response)["id_token"].(string), claims, func(token *jwt.Token) (any, error) { return app.ResolvePublicKey(ctx, token.Header["kid"].(string)) }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(app.Issuer()), jwt.WithAudience(client))
		if err != nil || claims["sub"] != user {
			t.Fatalf("wrong consent subject: %#v %v", claims, err)
		}
		secondView := read(call("GET", second, "", "", "application/json"))
		if secondView["user"].(map[string]any)["email"] != otherEmail {
			t.Fatal("second tab session changed")
		}
	})
	t.Run("cleanup drains more than one batch", func(t *testing.T) {
		_, err := db.Exec(ctx, `INSERT INTO hosted_auth_interactions(id,application_id,client_id,browser_digest,csrf_digest,authorization_parameters,pkce_required,private_state_ciphertext,expires_at) SELECT gen_random_uuid(),$1,$2,$3,$3,'{}',true,'expired-fixture',now()-interval '1 minute' FROM generate_series(1,1001)`, application, client, vault.Digest("cleanup-fixture"))
		if err != nil {
			t.Fatal(err)
		}
		if err = RunLifecycleSweep(ctx, app); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = db.QueryRow(ctx, `SELECT count(*) FROM hosted_auth_interactions WHERE application_id=$1 AND expires_at<=now()`, application).Scan(&count); err != nil || count != 0 {
			t.Fatalf("cleanup backlog: %d %v", count, err)
		}
	})
	if os.Getenv("PLATFORM93_HOSTED_BROWSER_TEST") == "1" {
		host := httptest.NewServer(router)
		defer host.Close()
		app.PublicURL = host.URL
		command := exec.Command("pnpm", "exec", "playwright", "test", "e2e/hosted-live.spec.ts")
		command.Dir = filepath.Join("..", "..", "web")
		command.Env = append(os.Environ(), "PLATFORM93_E2E_URL="+host.URL, "PLATFORM93_HOSTED_CLIENT="+client, "PLATFORM93_HOSTED_EMAIL="+email)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("live browser: %v\n%s", err, output)
		}
		t.Log(string(output))
	}
	if os.Getenv("PLATFORM93_POSTAL_COMPAT_TEST") == "1" {
		testHostedPostalCompatibility(t, app, router, application, client, email)
	}
}

func TestHostedClientPolicyAndBrandingValidation(t *testing.T) {
	for _, kind := range []string{"public", "machine"} {
		if validateHostedClientPolicy(kind, "hosted", []string{"authorization_code"}, false) == nil {
			t.Fatalf("%s bypassed PKCE policy", kind)
		}
	}
	if validateHostedClientPolicy("confidential", "hosted", []string{"authorization_code"}, false) != nil {
		t.Fatal("confidential compatibility rejected")
	}
	for _, branding := range []hostedBranding{{LogoURL: "javascript:alert(1)"}, {LogoURL: "https://user:password@example.test/logo"}, {AccentColor: "#ffffff"}, {BackgroundColor: "#111827"}, {Layout: "custom-html"}} {
		if validateHostedBranding(branding) == nil {
			t.Fatalf("unsafe branding accepted: %#v", branding)
		}
	}
	if validateHostedBranding(hostedBranding{AccentColor: "#17261f", BackgroundColor: "#f6f8fa", Copy: map[string]hostedCopy{"de": {Heading: "Willkommen"}}}) != nil {
		t.Fatal("valid branding rejected")
	}
}
