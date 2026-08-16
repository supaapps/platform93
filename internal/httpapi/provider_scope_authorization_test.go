package httpapi

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestProviderScopeAuthorization(t *testing.T) {
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
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{app: platform.New(db, vault, "https://platform93.test")}
	organizationID, applicationID, organizationAdminID, organizationAuditorID, installationAuditorID, outsiderID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := organizationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Provider authorization',$2)`, organizationID, "provider-auth-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Provider authorization',$3)`, applicationID, organizationID, "provider-auth-app-"+suffix); err != nil {
		t.Fatal(err)
	}
	for id, prefix := range map[string]string{organizationAdminID.String(): "org-admin", organizationAuditorID.String(): "org-auditor", installationAuditorID.String(): "install-auditor", outsiderID.String(): "outsider"} {
		if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email) VALUES($1,$2,$2)`, id, prefix+"-"+suffix+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO organization_memberships(organization_id,control_user_id,role) VALUES($1,$2,'auditor')`, organizationID, organizationAuditorID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO organization_memberships(organization_id,control_user_id,role) VALUES($1,$2,'admin')`, organizationID, organizationAdminID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,'auditor')`, installationAuditorID); err != nil {
		t.Fatal(err)
	}

	request := requestWithRoute(t, "GET", "/", nil, nil, kernel.Actor{Type: "control_user", ID: organizationAuditorID.String()})
	if !server.authorizeProviderScope(httptest.NewRecorder(), request, organizationProviderScope(organizationID.String()), false) {
		t.Fatal("organization auditor could not read organization providers")
	}
	response := httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, organizationProviderScope(organizationID.String()), true) || response.Code != 403 {
		t.Fatalf("organization auditor could mutate providers: %d", response.Code)
	}
	if !server.authorizeProviderScope(httptest.NewRecorder(), request, applicationProviderScope(applicationID.String()), false) {
		t.Fatal("organization auditor could not read application providers")
	}
	response = httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, applicationProviderScope(applicationID.String()), true) || response.Code != 403 {
		t.Fatalf("organization auditor could mutate application providers: %d", response.Code)
	}
	if server.authorizeApplicationStorageControl(httptest.NewRecorder(), request, applicationID.String(), true) {
		t.Fatal("organization auditor could mutate application storage")
	}

	if _, err = db.Exec(context.Background(), `UPDATE organization_policies SET enabled_settings=jsonb_set(enabled_settings,'{application_provider_overrides}','false') WHERE organization_id=$1`, organizationID); err != nil {
		t.Fatal(err)
	}
	request = requestWithRoute(t, "GET", "/", nil, nil, kernel.Actor{Type: "control_user", ID: organizationAdminID.String()})
	if !server.authorizeApplicationStorageControl(httptest.NewRecorder(), request, applicationID.String(), true) {
		t.Fatal("organization admin could not manage application objects when provider overrides were disabled")
	}
	response = httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, applicationProviderScope(applicationID.String()), true) || response.Code != 403 {
		t.Fatalf("organization admin configured an application provider while overrides were disabled: %d", response.Code)
	}

	request = requestWithRoute(t, "GET", "/", nil, nil, kernel.Actor{Type: "control_user", ID: outsiderID.String()})
	response = httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, organizationProviderScope(organizationID.String()), false) || response.Code != 404 {
		t.Fatalf("organization provider scope leaked to outsider: %d", response.Code)
	}
	response = httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, applicationProviderScope(applicationID.String()), false) || response.Code != 404 {
		t.Fatalf("application provider scope leaked to outsider: %d", response.Code)
	}

	request = requestWithRoute(t, "GET", "/", nil, nil, kernel.Actor{Type: "control_user", ID: installationAuditorID.String()})
	if !server.authorizeProviderScope(httptest.NewRecorder(), request, installationProviderScope(), false) {
		t.Fatal("installation auditor could not read installation providers")
	}
	response = httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, installationProviderScope(), true) || response.Code != 403 {
		t.Fatalf("installation auditor could mutate providers: %d", response.Code)
	}
}
