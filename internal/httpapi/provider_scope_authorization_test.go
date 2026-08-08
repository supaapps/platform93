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
	organizationID, organizationAuditorID, installationAuditorID, outsiderID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := organizationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Provider authorization',$2)`, organizationID, "provider-auth-"+suffix); err != nil {
		t.Fatal(err)
	}
	for id, prefix := range map[string]string{organizationAuditorID.String(): "org-auditor", installationAuditorID.String(): "install-auditor", outsiderID.String(): "outsider"} {
		if _, err = db.Exec(context.Background(), `INSERT INTO operators(id,email,normalized_email) VALUES($1,$2,$2)`, id, prefix+"-"+suffix+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO organization_memberships(organization_id,operator_id,role) VALUES($1,$2,'auditor')`, organizationID, organizationAuditorID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_operator_roles(operator_id,role) VALUES($1,'auditor')`, installationAuditorID); err != nil {
		t.Fatal(err)
	}

	request := requestWithRoute(t, "GET", "/", nil, nil, kernel.Actor{Type: "operator", ID: organizationAuditorID.String()})
	if !server.authorizeProviderScope(httptest.NewRecorder(), request, organizationProviderScope(organizationID.String()), false) {
		t.Fatal("organization auditor could not read organization providers")
	}
	response := httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, organizationProviderScope(organizationID.String()), true) || response.Code != 403 {
		t.Fatalf("organization auditor could mutate providers: %d", response.Code)
	}

	request = requestWithRoute(t, "GET", "/", nil, nil, kernel.Actor{Type: "operator", ID: outsiderID.String()})
	response = httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, organizationProviderScope(organizationID.String()), false) || response.Code != 404 {
		t.Fatalf("organization provider scope leaked to outsider: %d", response.Code)
	}

	request = requestWithRoute(t, "GET", "/", nil, nil, kernel.Actor{Type: "operator", ID: installationAuditorID.String()})
	if !server.authorizeProviderScope(httptest.NewRecorder(), request, installationProviderScope(), false) {
		t.Fatal("installation auditor could not read installation providers")
	}
	response = httptest.NewRecorder()
	if server.authorizeProviderScope(response, request, installationProviderScope(), true) || response.Code != 403 {
		t.Fatalf("installation auditor could mutate providers: %d", response.Code)
	}
}
