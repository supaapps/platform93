package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ory/fosite"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestPermissionWildcardStopsAtPathBoundary(t *testing.T) {
	granted := "/applications/app/workspaces/one/*"
	for _, allowed := range []string{
		"/applications/app/workspaces/one",
		"/applications/app/workspaces/one/billing/read",
	} {
		if !permissionMatches(granted, allowed) {
			t.Fatalf("expected %q to match %q", granted, allowed)
		}
	}
	for _, denied := range []string{
		"/applications/app/workspaces/one-more/billing/read",
		"/applications/app/workspaces/two/billing/read",
		"/applications/app/billing/read",
	} {
		if permissionMatches(granted, denied) {
			t.Fatalf("did not expect %q to match %q", granted, denied)
		}
	}
}

func TestApplicationScopesReplaceStaleRolePaths(t *testing.T) {
	request := fosite.NewAccessRequest(nil)
	request.GrantScope("openid")
	request.GrantScope("/applications/app/old")
	replaceApplicationScopes(request, []string{"/applications/app/new"})
	if !slices.Equal(request.GetGrantedScopes(), fosite.Arguments{"openid", "/applications/app/new"}) {
		t.Fatalf("unexpected recomputed scopes: %#v", request.GetGrantedScopes())
	}
}

func TestWorkspaceOwnershipAndClientScopeInvariants(t *testing.T) {
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
	organizationID, applicationID, otherApplicationID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	ownerID, suspendedID, workspaceID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	otherUserID, clientID, roleID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Invariant test',$2)`, []any{organizationID, "invariants-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Invariant test',$3)`, []any{applicationID, organizationID, "invariants-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Other application',$3)`, []any{otherApplicationID, organizationID, "other-" + suffix}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{ownerID, applicationID, "owner-" + suffix + "@example.test"}},
		{`INSERT INTO users(id,application_id,email,normalized_email,status) VALUES($1,$2,$3,$3,'suspended')`, []any{suspendedID, applicationID, "suspended-" + suffix + "@example.test"}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{otherUserID, otherApplicationID, "other-" + suffix + "@example.test"}},
		{`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,$4,'Workspace')`, []any{workspaceID, applicationID, ownerID, "workspace-" + suffix}},
		{`INSERT INTO clients(id,application_id,client_id,name,client_type,allowed_grants) VALUES($1,$2,$3,'Worker','machine',ARRAY['client_credentials'])`, []any{clientID, applicationID, "worker-" + suffix}},
		{`INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,$3,'Billing reader','application',ARRAY['billing:read'])`, []any{roleID, applicationID, "billing-reader-" + suffix}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(context.Background(), `UPDATE users SET status='suspended' WHERE id=$1`, ownerID); err == nil {
		t.Fatal("workspace owner was suspended without transferring or archiving ownership")
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,$4,'Invalid')`, kernel.NewID(), applicationID, suspendedID, "invalid-"+suffix); err == nil {
		t.Fatal("suspended user became a workspace owner")
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO billing_profiles(application_id,subject_type,subject_id) VALUES($1,'user',$2)`, applicationID, otherUserID); err == nil {
		t.Fatal("cross-application billing subject was accepted")
	}

	configRequest := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	configResponse := httptest.NewRecorder()
	server.publicConfig(configResponse, configRequest)
	if configResponse.Code != http.StatusOK || !strings.Contains(configResponse.Body.String(), `"issuer":"https://platform93.test/oidc"`) {
		t.Fatalf("public config did not expose the installation issuer: %d %s", configResponse.Code, configResponse.Body.String())
	}

	assignment := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"client_id": clientID, "role_id": roleID,
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "operator"})
	response := httptest.NewRecorder()
	server.assignRole(response, assignment)
	if response.Code != http.StatusCreated {
		t.Fatalf("client role assignment failed: %d %s", response.Code, response.Body.String())
	}
	wanted := "/applications/" + applicationID.String() + "/billing/read"
	if scopes := server.clientScopes(assignment, applicationID, "worker-"+suffix); !slices.Contains(scopes, wanted) {
		t.Fatalf("client scopes do not contain %q: %#v", wanted, scopes)
	}

	if _, err = db.Exec(context.Background(), `UPDATE workspaces SET deleted_at=now() WHERE id=$1`, workspaceID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `UPDATE users SET status='suspended' WHERE id=$1`, ownerID); err != nil {
		t.Fatalf("archived workspace still blocked owner suspension: %v", err)
	}
}

func TestFinalInstallationOwnerCannotBeDemoted(t *testing.T) {
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
	ownerID := kernel.NewID()
	if _, err = db.Exec(context.Background(), `UPDATE installation_operator_roles SET role='admin' WHERE role='owner'`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO operators(id,email,normalized_email) VALUES($1,$2,$2)`, ownerID, "installation-owner-"+ownerID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_operator_roles(operator_id,role) VALUES($1,'owner')`, ownerID); err != nil {
		t.Fatal(err)
	}
	request := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"role": "admin"}, map[string]string{"operator_id": ownerID.String()}, kernel.Actor{Type: "operator", ID: ownerID.String()})
	response := httptest.NewRecorder()
	server.updateInstallationOperator(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("final installation owner demotion returned %d: %s", response.Code, response.Body.String())
	}
}
