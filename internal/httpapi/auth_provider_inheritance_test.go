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

func TestInstallationAuthProviderInheritanceCanBeChangedWithoutCredentials(t *testing.T) {
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
	controlUserID, organizationID, applicationID, providerID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := providerID.String()
	if _, err = db.Exec(context.Background(), `DELETE FROM auth_provider_configs WHERE application_id IS NULL AND organization_id IS NULL AND client_id IN ('platform93-inheritance-test-client','client')`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email) VALUES($1,$2,$2)`, controlUserID, "provider-owner-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,'owner')`, controlUserID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Provider inheritance',$2)`, organizationID, "provider-inheritance-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Provider inheritance app',$3)`, applicationID, organizationID, "provider-app-"+suffix); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := vault.Encrypt([]byte(`{"client_secret":"secret"}`), "auth-provider:"+providerID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO auth_provider_configs(id,provider,client_id,config_ciphertext,inheritable) VALUES($1,'google','platform93-inheritance-test-client',$2,true)`, providerID, ciphertext); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM auth_provider_configs WHERE id=$1`, providerID)
	}()

	update := func(inheritable any) *httptest.ResponseRecorder {
		request := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"inheritable": inheritable}, map[string]string{"provider": "google"}, kernel.Actor{Type: "control_user", ID: controlUserID.String()})
		response := httptest.NewRecorder()
		server.updateInstallationAuthProvider(response, request)
		return response
	}

	if response := update(false); response.Code != http.StatusNoContent {
		t.Fatalf("disable inheritance failed: %d %s", response.Code, response.Body.String())
	}
	if _, err = server.loadEffectiveAuthProvider(context.Background(), applicationID.String(), "google"); err == nil {
		t.Fatal("application resolved an installation provider after inheritance was disabled")
	}
	if response := update(true); response.Code != http.StatusNoContent {
		t.Fatalf("enable inheritance failed: %d %s", response.Code, response.Body.String())
	}
	if provider, loadErr := server.loadEffectiveAuthProvider(context.Background(), applicationID.String(), "google"); loadErr != nil || provider.Scope != "installation" {
		t.Fatalf("application did not resolve the re-enabled installation provider: %#v %v", provider, loadErr)
	}
	providers := server.loadEffectiveAuthProviders(context.Background(), applicationID.String())
	if provider, configured := providers["google"]; !configured || provider.Scope != "installation" {
		t.Fatalf("batched provider resolution did not include the inherited provider: %#v", providers)
	}
	if response := update(nil); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing inheritance value returned %d: %s", response.Code, response.Body.String())
	}
}
