package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestRolePermissionInputRejectsScopeInjection(t *testing.T) {
	server := &Server{}
	for _, permission := range []string{"invoices:read billing:*", "invoices:read\tbilling:*", "members::read", "members:*:read", "members%20read", "../read", "mémbers:read"} {
		request := requestWithRoute(t, http.MethodPost, "/", map[string]any{
			"key": "accountant", "name": "Accountant", "scope": "application", "permissions": []string{permission},
		}, map[string]string{"application_id": kernel.NewID().String()}, kernel.Actor{Type: "control_user"})
		response := httptest.NewRecorder()
		server.createRole(response, request)
		if response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("permission %q returned %d instead of 422", permission, response.Code)
		}
	}
}

func TestPermissionGrantLifecycleAndDatabaseGuards(t *testing.T) {
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := secure.NewVault(make([]byte, 32))
	server := &Server{app: platform.New(db, vault, "https://platform93.test")}
	organizationID, applicationID, userID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Authorization test',$2)`, []any{organizationID, "authorization-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Authorization test',$3)`, []any{applicationID, organizationID, "authorization-" + suffix}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{userID, applicationID, "user-" + suffix + "@example.test"}},
	} {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO roles(application_id,key,name,scope,permissions) VALUES($1,'bad','Bad','application',ARRAY['read write'])`, applicationID); err == nil {
		t.Fatal("database accepted malformed role permission")
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO personal_api_keys(application_id,user_id,token_prefix,token_digest,scopes,expires_at) VALUES($1,$2,'bad',$3,ARRAY[$4],now()+interval '1 day')`, applicationID, userID, []byte("digest"), "/applications/"+applicationID.String()+"/read write"); err == nil {
		t.Fatal("database accepted malformed PAT scope")
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO personal_api_keys(application_id,user_id,token_prefix,token_digest,scopes,expires_at) VALUES($1,$2,'root-wildcard',$3,ARRAY[$4],now()+interval '1 day')`, applicationID, userID, []byte("root-wildcard-"+suffix), "/applications/"+applicationID.String()+"/*"); err != nil {
		t.Fatalf("database rejected canonical root wildcard: %v", err)
	}

	create := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"subject_type": "user", "subject_id": userID, "permission": "invoices:read", "reason": "invoice review",
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "control_user", ID: kernel.NewID().String()})
	create.Header.Set("Idempotency-Key", kernel.NewID().String())
	response := httptest.NewRecorder()
	server.createPermissionGrant(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("grant creation returned %d: %s", response.Code, response.Body.String())
	}
	var created map[string]any
	if err = json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	wanted := "/applications/" + applicationID.String() + "/invoices/read"
	access, err := server.userEffectiveAccess(create, applicationID, userID.String())
	if err != nil || !containsAllowedScope(access.Scopes, wanted) {
		t.Fatalf("direct grant missing from effective access: %#v, %v", access.Scopes, err)
	}

	revoke := requestWithRoute(t, http.MethodDelete, "/", nil, map[string]string{
		"application_id": applicationID.String(), "grant_id": created["id"].(string),
	}, kernel.Actor{Type: "control_user", ID: kernel.NewID().String()})
	revoke.Header.Set("If-Match", `"v1"`)
	response = httptest.NewRecorder()
	server.revokePermissionGrant(response, revoke)
	if response.Code != http.StatusNoContent {
		t.Fatalf("grant revocation returned %d: %s", response.Code, response.Body.String())
	}
	access, err = server.userEffectiveAccess(create, applicationID, userID.String())
	if err != nil || containsAllowedScope(access.Scopes, wanted) {
		t.Fatalf("revoked direct grant remained effective: %#v, %v", access.Scopes, err)
	}
}
