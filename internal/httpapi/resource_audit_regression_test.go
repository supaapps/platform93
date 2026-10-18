package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"github.com/supaapps/platform93/internal/generated"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/oauthserver"
)

func TestOAuthRequestClientIDEncoding(t *testing.T) {
	for _, id := range []string{"ordinary-client", "https://client.example.test/oauth.json", "client+with:reserved%characters"} {
		r := httptest.NewRequest("POST", "/oidc/token", nil)
		r.SetBasicAuth(url.QueryEscape(id), "secret")
		if got := oauthRequestClientID(r); got != id {
			t.Errorf("client ID %q decoded as %q", id, got)
		}
	}
	r := httptest.NewRequest("POST", "/oidc/token?client_id=must-not-fallback", nil)
	r.SetBasicAuth("bad%encoding", "secret")
	if got := oauthRequestClientID(r); got != "" {
		t.Fatalf("invalid Basic identity fell back: %q", got)
	}
}

func enrollAuditMetadataClient(t *testing.T, f *resourceOAuthFixture, id, redirect string) {
	t.Helper()
	s := &Server{app: f.app}
	resource, err := s.loadOAuthResource(context.Background(), f.application, f.resource)
	if err != nil {
		t.Fatal(err)
	}
	metadata := resourceClientMetadata{ClientID: id, ClientName: "Published resource client", RedirectURIs: []string{redirect}, GrantTypes: []string{"authorization_code", "refresh_token"}, TokenEndpointAuthMethod: "none"}
	if err = s.persistResourceMetadataClient(context.Background(), &resource, id, metadata, []byte("synthetic-metadata-digest")); err != nil {
		t.Fatal(err)
	}
}

func TestResourceOAuthPostgresPopulatedRollback(t *testing.T) {
	f := newResourceOAuthFixture(t)
	ctx := context.Background()
	published, redirect := "https://published.example.test/client.json", "https://published.example.test/callback"
	f.exec(`UPDATE oauth_resources SET allow_client_metadata=true,client_ids=ARRAY[$2] WHERE id=$1`, f.resource, published)
	enrollAuditMetadataClient(t, f, published, redirect)
	enrollAuditMetadataClient(t, f, published, redirect+"/updated")
	assertLegacyBoundary := func() {
		t.Helper()
		var allowed, ordinary, anchor bool
		err := f.app.DB.QueryRow(ctx, `SELECT
EXISTS(SELECT 1 FROM clients WHERE application_id=$1 AND disabled_at IS NULL AND $2=ANY(redirect_uris)),
EXISTS(SELECT 1 FROM clients WHERE application_id=$1 AND client_id=$3 AND disabled_at IS NULL),
EXISTS(SELECT 1 FROM clients WHERE application_id=$1 AND client_id LIKE 'p93_resource_%' AND disabled_at IS NOT NULL AND cardinality(redirect_uris)=0 AND cardinality(allowed_grants)=0 AND cardinality(allowed_scopes)=0 AND secret_digest IS NULL)`, f.application, redirect+"/updated", f.client).Scan(&allowed, &ordinary, &anchor)
		if err != nil || allowed || !ordinary || !anchor {
			t.Fatalf("legacy admission: metadata=%v ordinary=%v inert_anchor=%v err=%v", allowed, ordinary, anchor, err)
		}
	}
	assertLegacyBoundary()
	if _, err := f.app.DB.Exec(ctx, `UPDATE clients SET disabled_at=NULL WHERE application_id=$1 AND resource_only`, f.application); err == nil {
		t.Fatal("database allowed a live metadata anchor")
	}
	if _, err := f.app.DB.Exec(ctx, `UPDATE clients SET redirect_uris=ARRAY[$2] WHERE application_id=$1 AND resource_only`, f.application, redirect); err == nil {
		t.Fatal("database allowed a legacy redirect on a metadata anchor")
	}
	form := f.authorizationForm("billing:read")
	form.Set("client_id", published)
	form.Set("redirect_uri", redirect+"/updated")
	code := f.resourceCode(form)
	body := f.exchangeForm(code)
	body.Set("client_id", published)
	body.Set("redirect_uri", redirect+"/updated")
	if w := f.call("POST", "/oidc/token", body, "", "192.0.2.1"); w.Code != http.StatusOK {
		t.Fatalf("metadata exchange: %d %s", w.Code, w.Body)
	}
	db, err := sql.Open("pgx", f.app.DB.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = goose.Down(db, "."); err != nil {
		t.Fatal(err)
	}
	assertLegacyBoundary()
	if err = goose.Up(db, "."); err != nil {
		t.Fatal(err)
	}
	assertLegacyBoundary()
}

func TestResourceOAuthPostgresRegisteredURLClient(t *testing.T) {
	for _, metadataEnabled := range []bool{false, true} {
		name := "metadata_disabled"
		if metadataEnabled {
			name = "metadata_enabled"
		}
		t.Run(name, func(t *testing.T) {
			f := newResourceOAuthFixture(t)
			id := "https://registered.example.test/client.json"
			f.exec(`UPDATE oauth_resources SET client_ids=ARRAY[$2],allow_client_metadata=$3 WHERE id=$1`, f.resource, id, metadataEnabled)
			if metadataEnabled {
				enrollAuditMetadataClient(t, f, id, "https://different.example.test/callback")
			}
			f.exec(`UPDATE clients SET client_id=$2 WHERE id=$1`, f.client, id)
			f.client = id
			form := f.authorizationForm("billing:read")
			if w := f.call("GET", "/oidc/authorize?"+form.Encode(), nil, "", "192.0.2.1"); w.Code != 200 {
				t.Fatalf("registered URL authorization: %d %s", w.Code, w.Body)
			}
			code := f.resourceCode(form)
			body := f.exchangeForm(code)
			body.Set("client_id", id)
			if w := f.call("POST", "/oidc/token", body, "", "192.0.2.1"); w.Code == 200 {
				t.Fatal("confidential client downgraded to public metadata")
			}
			w := f.tokenCall(body)
			if w.Code != 200 {
				t.Fatalf("registered URL exchange: %d %s", w.Code, w.Body)
			}
			tokens := decodeTestResponse(t, w)
			if f.claims(tokens["access_token"].(string)).ClientID != id {
				t.Fatal("client identity changed")
			}
			f.exec(`UPDATE clients SET disabled_at=now() WHERE application_id=$1 AND client_id=$2 AND NOT resource_only`, f.application, id)
			if w = f.call("GET", "/oidc/authorize?"+form.Encode(), nil, "", "192.0.2.1"); w.Code != 400 {
				t.Fatalf("disabled registration fell back: %d %s", w.Code, w.Body)
			}
			store := &oauthserver.Store{DB: f.app.DB, Vault: f.app.Vault, ApplicationID: uuid.MustParse(f.application), ResourceURI: resourceOAuthTestURI}
			if _, err := store.GetClient(context.Background(), id); err == nil {
				t.Fatal("store fell back from disabled registration")
			}
			assertResourceTokenRejected(t, f.tokenCall(f.resourceRefresh(tokens["refresh_token"].(string))))
		})
	}
}

func TestResourceOAuthPostgresRefreshEffectivePermissions(t *testing.T) {
	f := newResourceOAuthFixture(t)
	tokens := f.resourceTokens(f.authorizationForm("billing:read", "billing:write"))
	refresh := func(explicit string, read, write bool) {
		t.Helper()
		body := f.resourceRefresh(tokens["refresh_token"].(string))
		if explicit != "" {
			body.Set("scope", explicit)
		}
		w := f.tokenCall(body)
		if w.Code != 200 {
			t.Fatalf("refresh: %d %s", w.Code, w.Body)
		}
		tokens = decodeTestResponse(t, w)
		claims := f.claims(tokens["access_token"].(string))
		for key, want := range map[string]bool{"billing:read": read, "billing:write": write} {
			if strings.Contains(claims.Scope, f.scope(strings.ReplaceAll(key, ":", "/"))) != want {
				t.Fatalf("%s expected=%v scope=%s", key, want, claims.Scope)
			}
			f.assertCheck(tokens["access_token"].(string), key, nil, want)
		}
	}
	f.exec(`UPDATE roles SET permissions=ARRAY['billing:read'] WHERE application_id=$1`, f.application)
	refresh("", true, false)
	f.exec(`UPDATE roles SET permissions=ARRAY['billing:read','billing:write'] WHERE application_id=$1`, f.application)
	refresh("", true, true)
	f.exec(`UPDATE roles SET permissions=ARRAY['unrelated:read'] WHERE application_id=$1`, f.application)
	refresh("", false, false)
	f.exec(`UPDATE roles SET permissions=ARRAY['billing:read','billing:write'] WHERE application_id=$1`, f.application)
	refresh("", true, true)
	refresh(f.scope("billing/read")+" offline_access", true, false)
	f.exec(`UPDATE roles SET permissions=ARRAY['unrelated:read'] WHERE application_id=$1`, f.application)
	refresh("", false, false)
	f.exec(`UPDATE roles SET permissions=ARRAY['billing:read','billing:write'] WHERE application_id=$1`, f.application)
	refresh("", true, false)
	body := f.resourceRefresh(tokens["refresh_token"].(string))
	body.Set("scope", f.scope("billing/write")+" offline_access")
	assertResourceTokenRejected(t, f.tokenCall(body))
}

func TestResourceOAuthPostgresRefreshWorkspaceContexts(t *testing.T) {
	f := newResourceOAuthFixture(t)
	first, second, other := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	f.exec(`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'other@example.test','other@example.test')`, other, f.application)
	f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'one','One'),($4,$2,$3,'two','Two')`, first, f.application, f.user, second)
	f.exec(`UPDATE oauth_resources SET capabilities='[{"key":"billing:read","name":"Read workspace","context":"workspace","permissions":["billing:read"]}]' WHERE id=$1`, f.resource)
	form := f.authorizationForm("billing:read")
	form.Set("personal_access", "false")
	selected, _ := json.Marshal([]string{first, second})
	form.Set("workspace_ids", string(selected))
	tokens := f.resourceTokens(form)
	refresh := func(want bool) {
		t.Helper()
		w := f.tokenCall(f.resourceRefresh(tokens["refresh_token"].(string)))
		if w.Code != 200 {
			t.Fatalf("workspace refresh: %d %s", w.Code, w.Body)
		}
		tokens = decodeTestResponse(t, w)
		if strings.Contains(f.claims(tokens["access_token"].(string)).Scope, f.scope("billing/read")) != want {
			t.Fatal("wrong workspace capability")
		}
	}
	f.exec(`UPDATE workspaces SET owner_user_id=$2 WHERE id=$1`, first, other)
	refresh(true)
	f.assertCheck(tokens["access_token"].(string), "billing:read", &first, false)
	f.assertCheck(tokens["access_token"].(string), "billing:read", &second, true)
	f.exec(`UPDATE workspaces SET owner_user_id=$2 WHERE id=$1`, second, other)
	refresh(false)
	f.exec(`UPDATE workspaces SET owner_user_id=$2 WHERE id=$1`, first, f.user)
	refresh(true)
	f.assertCheck(tokens["access_token"].(string), "billing:read", &first, true)
}

func TestResourceOAuthPostgresPatchResponseContract(t *testing.T) {
	f := newResourceLoginBoundaryFixture(t)
	path := "/v1/control/applications/" + f.application + "/oauth-resources/" + f.resource
	r := httptest.NewRequest("PATCH", path, strings.NewReader(`{"name":"Updated resource"}`))
	r.Header.Set("Authorization", "Bearer "+f.controlBearer())
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", `"v1"`)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("ETag") != `"v2"` {
		t.Fatalf("PATCH response: %d %s", w.Code, w.Body)
	}
	spec, err := generated.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	response := spec.Paths.Value("/v1/control/applications/{application_id}/oauth-resources/{resource_id}").Patch.Responses.Value("200")
	if response == nil {
		t.Fatal("OpenAPI does not declare the real success status")
	}
	var value any
	if err = json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if err = response.Value.Content["application/json"].Schema.Value.VisitJSON(value); err != nil {
		t.Fatalf("response violates generated OpenAPI: %v", err)
	}
}
