package httpapi

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestManagementClientBoundaryAndOrganizationLimits(t *testing.T) {
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
	if _, err = db.Exec(context.Background(), `INSERT INTO installations(management_api_enabled)
SELECT true WHERE NOT EXISTS(SELECT 1 FROM installations)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), "UPDATE installations SET management_api_enabled=true"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = server.app.EnsureSigningKey(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	clientID, clientSecret, clientDatabaseID := "provisioner-"+kernel.NewID().String(), "p93_mgmt_test_secret", kernel.NewID()
	if _, err = db.Exec(context.Background(), `INSERT INTO management_clients(id,client_id,name,secret_digest)
VALUES($1,$2,'Integration provisioner',$3)`, clientDatabaseID, clientID, vault.Digest(clientSecret)); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {managementOrganizationsScope}}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)
	response := httptest.NewRecorder()
	server.issueManagementToken(response, request, managementOAuthClient{ID: clientDatabaseID.String(), ClientID: clientID})
	if response.Code != http.StatusOK {
		t.Fatalf("management token issuance failed: %d %s", response.Code, response.Body.String())
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(response.Body.Bytes(), &tokenResponse) != nil || tokenResponse.AccessToken == "" {
		t.Fatal("management access token was not returned")
	}
	claims, err := identity.Verify(tokenResponse.AccessToken, func(kid string) (*rsa.PublicKey, error) {
		return server.app.ResolvePublicKey(context.Background(), kid)
	}, server.app.Issuer(), server.app.ControlAudience(), server.app.Now())
	if err != nil || claims.ActorType != "management_client" || claims.TokenKind != "management" || claims.SessionID != "" || claims.ClientID != clientID {
		t.Fatalf("unexpected management claims: %#v err=%v", claims, err)
	}

	called := false
	handler := server.requireManagementClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = actor(r).Type == "management_client"
		w.WriteHeader(http.StatusNoContent)
	}))
	request = httptest.NewRequest(http.MethodGet, "/v1/management/organizations", nil)
	request.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("management middleware rejected active client: %d", response.Code)
	}
	if _, err = db.Exec(context.Background(), "UPDATE installations SET management_api_enabled=false"); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/management/organizations", nil)
	request.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("disabled management API accepted an issued token: %d", response.Code)
	}

	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Governed org',$2)`, organizationID, "governed-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	var settings map[string]bool
	if err = db.QueryRow(context.Background(), `SELECT enabled_settings FROM organization_policies WHERE organization_id=$1`, organizationID).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	if !settings[settingWebhooks] || !settings[settingPublicRegistration] {
		t.Fatal("organization policy did not default to enabled capabilities")
	}
	if _, err = db.Exec(context.Background(), `UPDATE organization_policies SET max_applications=1,max_users=1 WHERE organization_id=$1`, organizationID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Governed app',$3)`, applicationID, organizationID, "governed-app-"+applicationID.String()); err != nil {
		t.Fatal(err)
	}
	tx, err = db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if limitErr := enforceApplicationLimit(context.Background(), tx, organizationID.String()); limitErr == nil {
		t.Fatal("application limit was not enforced")
	}
	_ = tx.Rollback(context.Background())
	if _, err = db.Exec(context.Background(), `INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, kernel.NewID(), applicationID, "governed-"+applicationID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	tx, err = db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if limitErr := enforceUserLimit(context.Background(), tx, applicationID.String()); limitErr == nil {
		t.Fatal("organization-wide user limit was not enforced")
	}
	_ = tx.Rollback(context.Background())
}
