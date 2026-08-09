package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestProviderInheritanceUpdatesPreserveHealth(t *testing.T) {
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
	operatorID, smtpID, stripeID, storageID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := smtpID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO operators(id,email,normalized_email) VALUES($1,$2,$2)`, operatorID, "provider-health-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_operator_roles(operator_id,role) VALUES($1,'owner')`, operatorID); err != nil {
		t.Fatal(err)
	}
	smtpCiphertext, err := vault.Encrypt([]byte(`{"host":"smtp.example.test","port":587,"tls_mode":"starttls"}`), "notification-provider:"+smtpID.String())
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err = db.Exec(context.Background(), `INSERT INTO notification_providers(id,provider,name,config_ciphertext,sender_email,sender_name,verified_at,inheritable)
VALUES($1,'smtp','Installation SMTP',$2,'mail@example.test','Platform93',$3,true)`, smtpID, smtpCiphertext, verifiedAt); err != nil {
		t.Fatal(err)
	}
	stripeCiphertext, err := vault.Encrypt([]byte("sk_test_secret"), "billing-provider:"+stripeID.String()+":secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO provider_connections(id,provider,public_id,api_version,secret_ciphertext,status,inheritable)
VALUES($1,'stripe',$2,'2026-04-22.dahlia',$3,'error',true)`, stripeID, "p93_provider_health_"+suffix, stripeCiphertext); err != nil {
		t.Fatal(err)
	}
	storageCiphertext, err := vault.Encrypt([]byte(`{"access_key_id":"access","secret_access_key":"secret"}`), "storage-provider:"+storageID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO storage_providers
(id,name,endpoint,region,public_bucket,credentials_ciphertext,inheritable,allow_private_endpoint,status,verified_at)
VALUES($1,'Installation storage','http://127.0.0.1:9000','local','public',$2,true,true,'active',$3)`, storageID, storageCiphertext, verifiedAt); err != nil {
		t.Fatal(err)
	}

	smtpRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"inheritable": false}, map[string]string{"provider_id": smtpID.String()}, kernel.Actor{Type: "operator", ID: operatorID.String()})
	smtpResponse := httptest.NewRecorder()
	server.updateInstallationNotificationProvider(smtpResponse, smtpRequest)
	if smtpResponse.Code != http.StatusOK {
		t.Fatalf("SMTP inheritance update failed: %d %s", smtpResponse.Code, smtpResponse.Body.String())
	}
	var storedVerifiedAt *time.Time
	var smtpInheritable bool
	if err = db.QueryRow(context.Background(), `SELECT verified_at,inheritable FROM notification_providers WHERE id=$1`, smtpID).Scan(&storedVerifiedAt, &smtpInheritable); err != nil {
		t.Fatal(err)
	}
	if storedVerifiedAt == nil || !storedVerifiedAt.Equal(verifiedAt) || smtpInheritable {
		t.Fatalf("SMTP health changed with inheritance: verified=%v inheritable=%v", storedVerifiedAt, smtpInheritable)
	}

	stripeRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"inheritable": false}, map[string]string{"provider_id": stripeID.String()}, kernel.Actor{Type: "operator", ID: operatorID.String()})
	stripeResponse := httptest.NewRecorder()
	server.updateInstallationBillingProvider(stripeResponse, stripeRequest)
	if stripeResponse.Code != http.StatusNoContent {
		t.Fatalf("Stripe inheritance update failed: %d %s", stripeResponse.Code, stripeResponse.Body.String())
	}
	var stripeStatus string
	var stripeInheritable bool
	if err = db.QueryRow(context.Background(), `SELECT status,inheritable FROM provider_connections WHERE id=$1`, stripeID).Scan(&stripeStatus, &stripeInheritable); err != nil {
		t.Fatal(err)
	}
	if stripeStatus != "error" || stripeInheritable {
		t.Fatalf("Stripe health changed with inheritance: status=%s inheritable=%v", stripeStatus, stripeInheritable)
	}

	storageRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"inheritable": false}, map[string]string{"provider_id": storageID.String()}, kernel.Actor{Type: "operator", ID: operatorID.String()})
	storageResponse := httptest.NewRecorder()
	server.updateInstallationStorageProvider(storageResponse, storageRequest)
	if storageResponse.Code != http.StatusOK {
		t.Fatalf("storage inheritance update failed: %d %s", storageResponse.Code, storageResponse.Body.String())
	}
	var storageStatus string
	var storedStorageVerifiedAt *time.Time
	var storageInheritable bool
	if err = db.QueryRow(context.Background(), `SELECT status,verified_at,inheritable FROM storage_providers WHERE id=$1`, storageID).Scan(&storageStatus, &storedStorageVerifiedAt, &storageInheritable); err != nil {
		t.Fatal(err)
	}
	if storageStatus != "active" || storedStorageVerifiedAt == nil || !storedStorageVerifiedAt.Equal(verifiedAt) || storageInheritable {
		t.Fatalf("storage health changed with inheritance: status=%s verified=%v inheritable=%v", storageStatus, storedStorageVerifiedAt, storageInheritable)
	}
}
