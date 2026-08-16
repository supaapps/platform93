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

func TestRoleWorkspaceAndWebhookLifecycle(t *testing.T) {
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
	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	roleID, workspaceID, webhookID, ownerID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Lifecycle test',$2)`, []any{organizationID, "lifecycle-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Lifecycle test',$3)`, []any{applicationID, organizationID, "lifecycle-" + suffix}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{ownerID, applicationID, "owner-" + suffix + "@example.test"}},
		{`INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,$3,'Custom','application',ARRAY['users:read'])`, []any{roleID, applicationID, "custom-" + suffix}},
		{`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,$4,'Workspace')`, []any{workspaceID, applicationID, ownerID, "workspace-" + suffix}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	secret, _ := vault.Encrypt([]byte("p93_whsec_test"), "webhook-endpoint:"+webhookID.String())
	if _, err = db.Exec(context.Background(), `INSERT INTO webhook_endpoints(id,application_id,uri,secret_ciphertext) VALUES($1,$2,'https://events.example.test/platform93',$3)`, webhookID, applicationID, secret); err != nil {
		t.Fatal(err)
	}

	roleUpdate := requestWithRoute(t, "PATCH", "/", map[string]any{"name": "Updated", "permissions": []string{"users:read", "users:write"}}, map[string]string{"application_id": applicationID.String(), "role_id": roleID.String()}, kernel.Actor{Type: "control_user"})
	response := httptest.NewRecorder()
	server.updateRole(response, roleUpdate)
	if response.Code != 204 {
		t.Fatalf("role update failed: %d %s", response.Code, response.Body.String())
	}

	webhookTest := requestWithRoute(t, "POST", "/", map[string]any{}, map[string]string{"application_id": applicationID.String(), "webhook_id": webhookID.String()}, kernel.Actor{Type: "control_user", ID: kernel.NewID().String()})
	response = httptest.NewRecorder()
	server.testWebhook(response, webhookTest)
	if response.Code != 202 {
		t.Fatalf("webhook test failed: %d %s", response.Code, response.Body.String())
	}
	var eventCount, deliveryCount int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM domain_events WHERE application_id=$1 AND event_type='platform93.webhook.test'`, applicationID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM webhook_deliveries WHERE application_id=$1 AND webhook_endpoint_id=$2`, applicationID, webhookID).Scan(&deliveryCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 || deliveryCount != 1 {
		t.Fatalf("targeted webhook test created events=%d deliveries=%d", eventCount, deliveryCount)
	}

	workspaceDelete := requestWithRoute(t, "DELETE", "/", nil, map[string]string{"application_id": applicationID.String(), "workspace_id": workspaceID.String()}, kernel.Actor{Type: "control_user"})
	response = httptest.NewRecorder()
	server.deleteWorkspace(response, workspaceDelete)
	if response.Code != 204 {
		t.Fatalf("workspace retirement failed: %d %s", response.Code, response.Body.String())
	}
	var deleted bool
	if err = db.QueryRow(context.Background(), `SELECT deleted_at IS NOT NULL FROM workspaces WHERE id=$1`, workspaceID).Scan(&deleted); err != nil || !deleted {
		t.Fatalf("workspace was not soft deleted: deleted=%v error=%v", deleted, err)
	}
}
