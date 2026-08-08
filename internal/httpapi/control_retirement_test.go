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

func TestControlPlaneRetirementRevokesCredentialsAndRestoresBoundaries(t *testing.T) {
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
	operatorID, organizationID := kernel.NewID(), kernel.NewID()
	applicationID, userID, sessionID, keyID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	connectionID, publicID := kernel.NewID(), kernel.NewID().String()
	suffix := applicationID.String()
	providerSecret, _ := vault.Encrypt([]byte("synthetic-provider-secret"), "billing-provider:"+connectionID.String()+":secret")
	webhookSecret, _ := vault.Encrypt([]byte("synthetic-webhook-secret"), "billing-provider:"+connectionID.String()+":webhook")
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO operators(id,email,normalized_email,display_name) VALUES($1,$2,$2,'Lifecycle owner')`, []any{operatorID, "lifecycle-" + suffix + "@platform93.test"}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Retirement test',$2)`, []any{organizationID, "retirement-" + suffix}},
		{`INSERT INTO organization_memberships(organization_id,operator_id,role) VALUES($1,$2,'admin')`, []any{organizationID, operatorID}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Retirement test',$3)`, []any{applicationID, organizationID, "retirement-" + suffix}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{userID, applicationID, "user-" + suffix + "@platform93.test"}},
		{`INSERT INTO user_sessions(id,application_id,user_id,refresh_digest,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 day')`, []any{sessionID, applicationID, userID, []byte("session-" + suffix)}},
		{`INSERT INTO personal_api_keys(id,application_id,user_id,token_prefix,token_digest,expires_at) VALUES($1,$2,$3,'p93_pat_test',$4,now()+interval '1 day')`, []any{keyID, applicationID, userID, []byte("key-" + suffix)}},
		{`INSERT INTO provider_connections(id,application_id,provider,public_id,api_version,secret_ciphertext,webhook_secret_ciphertext) VALUES($1,$2,'stripe',$3,'2026-04-22.dahlia',$4,$5)`, []any{connectionID, applicationID, publicID, providerSecret, webhookSecret}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	organizationRequest := lifecycleRequest(t, http.MethodDelete, map[string]string{"organization_id": organizationID.String()}, operatorID.String(), 1)
	response := httptest.NewRecorder()
	server.retireOrganization(response, organizationRequest)
	if response.Code != http.StatusForbidden {
		t.Fatalf("organization retirement accepted admin: %d %s", response.Code, response.Body.String())
	}
	if _, err = db.Exec(context.Background(), `UPDATE organization_memberships SET role='owner' WHERE organization_id=$1 AND operator_id=$2`, organizationID, operatorID); err != nil {
		t.Fatal(err)
	}

	applicationRequest := lifecycleRequest(t, http.MethodDelete, map[string]string{"organization_id": organizationID.String(), "application_resource_id": applicationID.String()}, operatorID.String(), 1)
	response = httptest.NewRecorder()
	server.retireApplication(response, applicationRequest)
	if response.Code != http.StatusNoContent {
		t.Fatalf("application retirement failed: %d %s", response.Code, response.Body.String())
	}
	var applicationRetired, sessionRevoked, keyRevoked bool
	if err = db.QueryRow(context.Background(), `SELECT e.deleted_at IS NOT NULL,s.revoked_at IS NOT NULL,k.revoked_at IS NOT NULL
FROM applications e JOIN user_sessions s ON s.application_id=e.id JOIN personal_api_keys k ON k.application_id=e.id
WHERE e.id=$1 AND s.id=$2 AND k.id=$3`, applicationID, sessionID, keyID).Scan(&applicationRetired, &sessionRevoked, &keyRevoked); err != nil {
		t.Fatal(err)
	}
	if !applicationRetired || !sessionRevoked || !keyRevoked {
		t.Fatalf("retirement state application=%v session=%v key=%v", applicationRetired, sessionRevoked, keyRevoked)
	}

	webhookRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{"id": "evt_retired"}, map[string]string{"connection_public_id": publicID}, kernel.Actor{})
	response = httptest.NewRecorder()
	server.stripeWebhook(response, webhookRequest)
	if response.Code != http.StatusNotFound {
		t.Fatalf("retired application accepted provider webhook: %d %s", response.Code, response.Body.String())
	}

	restoreApplicationRequest := lifecycleRequest(t, http.MethodPost, map[string]string{"organization_id": organizationID.String(), "application_resource_id": applicationID.String()}, operatorID.String(), 2)
	response = httptest.NewRecorder()
	server.restoreApplication(response, restoreApplicationRequest)
	if response.Code != http.StatusNoContent {
		t.Fatalf("application restoration failed: %d %s", response.Code, response.Body.String())
	}
	if err = db.QueryRow(context.Background(), `SELECT e.deleted_at IS NULL,s.revoked_at IS NOT NULL,k.revoked_at IS NOT NULL
FROM applications e JOIN user_sessions s ON s.application_id=e.id JOIN personal_api_keys k ON k.application_id=e.id
WHERE e.id=$1 AND s.id=$2 AND k.id=$3`, applicationID, sessionID, keyID).Scan(&applicationRetired, &sessionRevoked, &keyRevoked); err != nil {
		t.Fatal(err)
	}
	if !applicationRetired || !sessionRevoked || !keyRevoked {
		t.Fatal("restoring an application restored previously revoked credentials")
	}

	// The application is active again before testing organization-wide retirement.
	organizationRequest = lifecycleRequest(t, http.MethodDelete, map[string]string{"organization_id": organizationID.String()}, operatorID.String(), 1)
	response = httptest.NewRecorder()
	server.retireOrganization(response, organizationRequest)
	if response.Code != http.StatusNoContent {
		t.Fatalf("organization retirement failed: %d %s", response.Code, response.Body.String())
	}
	organizationRestore := lifecycleRequest(t, http.MethodPost, map[string]string{"organization_id": organizationID.String()}, operatorID.String(), 2)
	response = httptest.NewRecorder()
	server.restoreOrganization(response, organizationRestore)
	if response.Code != http.StatusNoContent {
		t.Fatalf("organization restoration failed: %d %s", response.Code, response.Body.String())
	}
	var organizationActive, applicationStillRetired bool
	if err = db.QueryRow(context.Background(), `SELECT o.deleted_at IS NULL,e.deleted_at IS NOT NULL
FROM organizations o JOIN applications e ON e.organization_id=o.id
WHERE o.id=$1 AND e.id=$2`, organizationID, applicationID).Scan(&organizationActive, &applicationStillRetired); err != nil {
		t.Fatal(err)
	}
	if !organizationActive || !applicationStillRetired {
		t.Fatal("organization restoration implicitly restored descendants")
	}
}

func lifecycleRequest(t *testing.T, method string, params map[string]string, operatorID string, version int64) *http.Request {
	t.Helper()
	request := requestWithRoute(t, method, "/", nil, params, kernel.Actor{Type: "operator", ID: operatorID})
	request.Header.Set("If-Match", kernel.ETag(version))
	return request
}
