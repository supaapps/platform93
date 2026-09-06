package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestExternalEmailEnrollmentResendCooldownIsAtomic(t *testing.T) {
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

	organizationID, applicationID, providerID, enrollmentID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	credential := "enrollment-credential-" + enrollmentID.String()
	credentialDigest := vault.Digest(credential)
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Enrollment cooldown',$2)`, organizationID, "enrollment-cooldown-"+enrollmentID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Enrollment cooldown',$3)`, applicationID, organizationID, "enrollment-cooldown-"+enrollmentID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO auth_provider_configs(id,application_id,provider,client_id,config_ciphertext) VALUES($1,$2,'microsoft',$3,'test')`, providerID, applicationID, "enrollment-cooldown-"+enrollmentID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO external_auth_email_enrollments
(id,application_id,auth_provider_config_id,provider,provider_subject,app_redirect_uri,credential_digest,code_challenge,expires_at)
VALUES($1,$2,$3,'microsoft',$4,'https://app.example/auth/callback',$5,$6,now()+interval '10 minutes')`, enrollmentID, applicationID, providerID, "subject-"+enrollmentID.String(), credentialDigest, strings.Repeat("a", 43)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM external_auth_email_enrollments WHERE id=$1`, enrollmentID)
		_, _ = db.Exec(context.Background(), `DELETE FROM auth_provider_configs WHERE id=$1`, providerID)
		_, _ = db.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, applicationID)
		_, _ = db.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	}()

	first, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(context.Background())
	if cooldown, reserveErr := reserveExternalEmailDelivery(context.Background(), first, "user@example.test", []byte("first-code"), []byte("first-link"), enrollmentID.String(), applicationID.String(), credentialDigest); reserveErr != nil || cooldown != nil {
		t.Fatalf("first reservation = %v, %v; want success", cooldown, reserveErr)
	}

	second, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback(context.Background())
	type reservationResult struct {
		cooldown *time.Time
		err      error
	}
	result := make(chan reservationResult, 1)
	go func() {
		cooldown, reserveErr := reserveExternalEmailDelivery(context.Background(), second, "user@example.test", []byte("second-code"), []byte("second-link"), enrollmentID.String(), applicationID.String(), credentialDigest)
		result <- reservationResult{cooldown: cooldown, err: reserveErr}
	}()

	select {
	case concurrent := <-result:
		t.Fatalf("concurrent reservation completed before the first transaction committed: %v, %v", concurrent.cooldown, concurrent.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err = first.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case concurrent := <-result:
		if concurrent.err != nil {
			t.Fatalf("concurrent reservation failed: %v", concurrent.err)
		}
		if concurrent.cooldown == nil || !concurrent.cooldown.After(time.Now()) {
			t.Fatalf("concurrent reservation cooldown = %v; want a future timestamp", concurrent.cooldown)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent reservation remained blocked after the first transaction committed")
	}
	if err = second.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err = db.Exec(context.Background(), `UPDATE external_auth_email_enrollments
	SET attempts=20,pkce_verified_at=now(),normalized_email='user@example.test',code_digest=$2
	WHERE id=$1`, enrollmentID, vault.Digest("VALID123")); err != nil {
		t.Fatal(err)
	}
	server := &Server{app: platform.New(db, vault, "https://platform93.test")}
	request := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"enrollment": enrollmentID.String() + ":" + credential,
		"code":       "WRONG123",
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	response := httptest.NewRecorder()
	server.verifyExternalEmailEnrollment(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid verification returned %d: %s", response.Code, response.Body.String())
	}
	var attempts int
	if err = db.QueryRow(context.Background(), `SELECT attempts FROM external_auth_email_enrollments WHERE id=$1`, enrollmentID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 20 {
		t.Fatalf("attempts = %d, want the database maximum 20", attempts)
	}
}
