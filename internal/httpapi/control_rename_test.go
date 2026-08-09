package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestOrganizationAndApplicationRename(t *testing.T) {
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
	operatorID, organizationID, applicationID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO operators(id,email,normalized_email) VALUES($1,$2,$2)`, []any{operatorID, "rename-" + suffix + "@example.test"}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Before organization',$2)`, []any{organizationID, "rename-" + suffix}},
		{`INSERT INTO organization_memberships(organization_id,operator_id,role) VALUES($1,$2,'admin')`, []any{organizationID, operatorID}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Before application',$3)`, []any{applicationID, organizationID, "rename-" + suffix}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	organizationRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"name": "After organization"}, map[string]string{"organization_id": organizationID.String()}, kernel.Actor{Type: "operator", ID: operatorID.String()})
	organizationRequest.Header.Set("If-Match", kernel.ETag(1))
	response := httptest.NewRecorder()
	server.updateOrganization(response, organizationRequest)
	if response.Code != http.StatusNoContent || response.Header().Get("ETag") != kernel.ETag(2) {
		t.Fatalf("organization rename failed: %d %s", response.Code, response.Body.String())
	}

	applicationRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"name": "After application"}, map[string]string{"organization_id": organizationID.String(), "application_resource_id": applicationID.String()}, kernel.Actor{Type: "operator", ID: operatorID.String()})
	applicationRequest.Header.Set("If-Match", kernel.ETag(1))
	response = httptest.NewRecorder()
	server.updateApplication(response, applicationRequest)
	if response.Code != http.StatusNoContent || response.Header().Get("ETag") != kernel.ETag(2) {
		t.Fatalf("application rename failed: %d %s", response.Code, response.Body.String())
	}

	var organizationName, applicationName string
	var organizationVersion, applicationVersion int64
	if err = db.QueryRow(context.Background(), `SELECT name,version FROM organizations WHERE id=$1`, organizationID).Scan(&organizationName, &organizationVersion); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT name,version FROM applications WHERE id=$1`, applicationID).Scan(&applicationName, &applicationVersion); err != nil {
		t.Fatal(err)
	}
	if organizationName != "After organization" || organizationVersion != 2 || applicationName != "After application" || applicationVersion != 2 {
		t.Fatalf("unexpected renamed boundaries: organization=%q/v%d application=%q/v%d", organizationName, organizationVersion, applicationName, applicationVersion)
	}

	staleRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"name": "Stale"}, map[string]string{"organization_id": organizationID.String(), "application_resource_id": applicationID.String()}, kernel.Actor{Type: "operator", ID: operatorID.String()})
	staleRequest.Header.Set("If-Match", kernel.ETag(1))
	response = httptest.NewRecorder()
	server.updateApplication(response, staleRequest)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale application rename returned %d, want 412", response.Code)
	}
}
