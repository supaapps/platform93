package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
)

func permissionCheckRequest(t *testing.T, f *oauthSecurityFixture, bearer, application string, workspace *string, permissions ...string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"permissions": permissions, "workspace_id": workspace})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/applications/"+application+"/me/permissions/check", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func permissionCheckToken(t *testing.T, f *oauthSecurityFixture, scopes ...string) string {
	t.Helper()
	kid, key, err := f.app.ActiveSigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := f.app.Now()
	token, err := identity.Sign(key, kid, identity.Claims{Issuer: f.app.Issuer(), Subject: f.user,
		Audience: []string{"platform93:application:" + f.application}, ApplicationID: f.application,
		SessionID: f.session, ActorType: "user", TokenKind: "access", Scope: strings.Join(scopes, " "),
		Roles: emptyRoleClaims(), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), JWTID: kernel.NewID().String()})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func assertPermissionDecisions(t *testing.T, w *httptest.ResponseRecorder, want ...bool) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("permission check: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		Results []struct {
			Allowed       bool     `json:"allowed"`
			MatchedScopes []string `json:"matched_scopes"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != len(want) {
		t.Fatalf("wrong result count: %s", w.Body.String())
	}
	for i, expected := range want {
		if response.Results[i].Allowed != expected {
			t.Errorf("decision %d: got %v, want %v: %s", i, response.Results[i].Allowed, expected, w.Body.String())
		}
		if !expected && len(response.Results[i].MatchedScopes) != 0 {
			t.Errorf("denied decision exposed matches: %s", w.Body.String())
		}
	}
}

func TestPermissionCheckCredentialCeilingsPostgres(t *testing.T) {
	t.Run("restricted personal key cannot borrow workspace ownership", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		workspace := kernel.NewID().String()
		f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'documents','Documents')`, workspace, f.application, f.user)
		f.exec(`UPDATE applications SET internal_config=jsonb_set(internal_config,'{personal_api_keys_enabled}','true') WHERE id=$1`, f.application)
		read := f.scope("workspaces/" + workspace + "/documents/read")
		key := "p93_pat_" + kernel.NewID().String()
		f.exec(`INSERT INTO personal_api_keys(id,application_id,user_id,label,token_prefix,token_digest,scopes,expires_at)
VALUES($1,$2,$3,'Read only','p93_pat_test',$4,ARRAY[$5],now()+interval '1 day')`, kernel.NewID(), f.application, f.user, f.app.Vault.Digest(key), read)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, key, f.application, &workspace, "documents:read", "documents:write", "*"), true, false, false)
		response := permissionCheckRequest(t, f, key, f.application, &workspace, "documents:read")
		results := decodeTestResponse(t, response)["results"].([]any)
		matched := results[0].(map[string]any)["matched_scopes"].([]any)
		if len(matched) != 1 || matched[0] != read {
			t.Fatalf("explanation exceeded the key's scope: %s", response.Body.String())
		}
		other := kernel.NewID().String()
		f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'other-documents','Other documents')`, other, f.application, f.user)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, key, f.application, &other, "documents:read"), false)
		for _, permission := range []string{"documents:reader", "documents:read_more", "documents:*"} {
			assertPermissionDecisions(t, permissionCheckRequest(t, f, key, f.application, &workspace, permission), false)
		}
		f.exec(`UPDATE personal_api_keys SET revoked_at=now() WHERE application_id=$1 AND token_digest=$2`, f.application, f.app.Vault.Digest(key))
		if response := permissionCheckRequest(t, f, key, f.application, &workspace, "documents:read"); response.Code != http.StatusUnauthorized {
			t.Fatalf("revoked key accepted: %d", response.Code)
		}
	})
	t.Run("narrow and empty JWT scopes do not inherit live role authority", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, permissionCheckToken(t, f, f.scope("billing/read")), f.application, nil, "billing:read", "billing:write"), true, false)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, permissionCheckToken(t, f), f.application, nil, "billing:read", "billing:write"), false, false)
	})
	t.Run("support delegation cannot borrow target user permissions", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		bearer := f.accessToken(true)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read", "billing:write"), true, false)
		f.exec(`UPDATE delegations SET permissions=ARRAY[$2] WHERE application_id=$1`, f.application, f.scope("*"))
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read", "billing:write"), true, false)
		f.exec(`UPDATE delegations SET permissions=ARRAY[$2] WHERE application_id=$1`, f.application, f.scope("billing/write"))
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read", "billing:write"), false, false)
		f.exec(`UPDATE delegations SET revoked_at=now() WHERE application_id=$1`, f.application)
		if w := permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read"); w.Code != http.StatusUnauthorized {
			t.Fatalf("revoked delegation accepted: %d", w.Code)
		}
	})
	t.Run("live revocation still denies a previously issued scope", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		bearer := permissionCheckToken(t, f, f.scope("billing/read"))
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read"), true)
		f.exec(`DELETE FROM role_assignments WHERE application_id=$1 AND user_id=$2`, f.application, f.user)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read"), false)
	})
	t.Run("broad JWT cannot exceed narrower live roles", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		bearer := permissionCheckToken(t, f, f.scope("*"))
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read", "billing:write", "users:read", "billing:*"), true, true, false, false)
	})
	t.Run("new live permissions require a fresh credential", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		f.exec(`UPDATE roles SET permissions=ARRAY['billing:read'] WHERE application_id=$1`, f.application)
		bearer := permissionCheckToken(t, f, f.scope("billing/read"))
		f.exec(`UPDATE roles SET permissions=ARRAY['billing:read','billing:write'] WHERE application_id=$1`, f.application)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, nil, "billing:write"), false)
		fresh := permissionCheckToken(t, f, f.scope("billing/read"), f.scope("billing/write"))
		assertPermissionDecisions(t, permissionCheckRequest(t, f, fresh, f.application, nil, "billing:write"), true)
	})
	t.Run("unrestricted personal key retains live inheritance", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		f.exec(`UPDATE applications SET internal_config=jsonb_set(internal_config,'{personal_api_keys_enabled}','true') WHERE id=$1`, f.application)
		key := "p93_pat_" + kernel.NewID().String()
		f.exec(`INSERT INTO personal_api_keys(id,application_id,user_id,token_prefix,token_digest,expires_at) VALUES($1,$2,$3,'p93_pat_test',$4,now()+interval '1 day')`, kernel.NewID(), f.application, f.user, f.app.Vault.Digest(key))
		assertPermissionDecisions(t, permissionCheckRequest(t, f, key, f.application, nil, "billing:read", "billing:write"), true, true)
		f.exec(`UPDATE roles SET permissions=ARRAY['billing:read'] WHERE application_id=$1`, f.application)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, key, f.application, nil, "billing:read", "billing:write"), true, false)
		f.exec(`UPDATE applications SET deleted_at=now() WHERE id=$1`, f.application)
		if w := permissionCheckRequest(t, f, key, f.application, nil, "billing:read"); w.Code != http.StatusUnauthorized {
			t.Fatalf("key authenticated to retired application: %d", w.Code)
		}
	})
	t.Run("ownership transfer does not revive stale owner scopes", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		workspace, newOwner := kernel.NewID().String(), kernel.NewID().String()
		f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'owned','Owned')`, workspace, f.application, f.user)
		bearer := permissionCheckToken(t, f, f.scope("workspaces/"+workspace+"/*"))
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, &workspace, "documents:write"), true)
		f.exec(`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'next-owner@example.test','next-owner@example.test')`, newOwner, f.application)
		f.exec(`UPDATE workspaces SET owner_user_id=$1 WHERE id=$2`, newOwner, workspace)
		assertPermissionDecisions(t, permissionCheckRequest(t, f, bearer, f.application, &workspace, "documents:write"), false)
	})
	t.Run("invalid credentials and application boundaries remain rejected", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		bearer := permissionCheckToken(t, f, f.scope("billing/read"))
		for _, credential := range []string{"", "invalid-token"} {
			if w := permissionCheckRequest(t, f, credential, f.application, nil, "billing:read"); w.Code != http.StatusUnauthorized {
				t.Fatalf("invalid credential accepted: %d", w.Code)
			}
		}
		other := kernel.NewID().String()
		f.exec(`INSERT INTO applications(id,organization_id,name,slug) SELECT $1,organization_id,'Other',$1::uuid::text FROM applications WHERE id=$2`, other, f.application)
		if w := permissionCheckRequest(t, f, bearer, other, nil, "billing:read"); w.Code != http.StatusUnauthorized {
			t.Fatalf("cross-application token accepted: %d", w.Code)
		}
		if w := permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read users:read"); w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("scope injection accepted: %d", w.Code)
		}
		f.exec(`UPDATE user_sessions SET revoked_at=now() WHERE id=$1`, f.session)
		if w := permissionCheckRequest(t, f, bearer, f.application, nil, "billing:read"); w.Code != http.StatusUnauthorized {
			t.Fatalf("revoked session accepted: %d", w.Code)
		}
	})
}
