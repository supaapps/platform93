package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestInstallationNotificationProviderIsScopeIsolated(t *testing.T) {
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
	controlUserID := kernel.NewID()
	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	installationProviderID, applicationProviderID := kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'SMTP scope test',$2)`, organizationID, "smtp-scope-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'SMTP scope test',$3)`, applicationID, organizationID, "smtp-scope-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email) VALUES($1,$2,$2)`, controlUserID, "smtp-control_user-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,'admin')`, controlUserID); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(storedSMTPConfig{Host: "smtp.example.test", Port: 587, TLSMode: "starttls"})
	installationCiphertext, _ := vault.Encrypt(config, "notification-provider:"+installationProviderID.String())
	applicationCiphertext, _ := vault.Encrypt(config, "notification-provider:"+applicationProviderID.String())
	if _, err = db.Exec(context.Background(), `INSERT INTO notification_providers(id,application_id,name,config_ciphertext,sender_email)
VALUES($1,NULL,'Installation SMTP',$2,'installation@example.test'),($3,$4,'Application SMTP',$5,'application@example.test')`,
		installationProviderID, installationCiphertext, applicationProviderID, applicationID, applicationCiphertext); err != nil {
		t.Fatal(err)
	}

	controlUser := kernel.Actor{Type: "control_user", ID: controlUserID.String()}
	wrongScope := requestWithRoute(t, "GET", "/", nil, map[string]string{"provider_id": applicationProviderID.String()}, controlUser)
	response := httptest.NewRecorder()
	server.getInstallationNotificationProvider(response, wrongScope)
	if response.Code != 404 {
		t.Fatalf("application provider escaped into installation scope: %d %s", response.Code, response.Body.String())
	}

	testRequest := requestWithRoute(t, "POST", "/", map[string]any{"recipient": "control_user@example.test"}, map[string]string{"provider_id": installationProviderID.String()}, controlUser)
	response = httptest.NewRecorder()
	server.testInstallationNotificationProvider(response, testRequest)
	if response.Code != 202 {
		t.Fatalf("installation SMTP test was not queued: %d %s", response.Code, response.Body.String())
	}
	var count int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM notifications WHERE notification_provider_id=$1 AND application_id IS NULL`, installationProviderID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected one installation-scoped test notification, got %d", count)
	}
}
