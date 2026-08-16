package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestExternalAuthCallbackURIIsInstallationWide(t *testing.T) {
	server := &Server{app: &platform.App{PublicURL: "https://platform93.example"}}
	if got, want := server.externalAuthCallbackURI("google"), "https://platform93.example/v1/auth/providers/google/callback"; got != want {
		t.Fatalf("callback URI = %q, want %q", got, want)
	}
}

func TestExternalAuthCallbackResolvesApplicationFromState(t *testing.T) {
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
	server := &Server{app: platform.New(db, vault, "https://platform93.example")}
	organizationID, applicationID, challengeID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := challengeID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Callback organization',$2)`, organizationID, "callback-org-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Callback application',$3)`, applicationID, organizationID, "callback-app-"+suffix); err != nil {
		t.Fatal(err)
	}
	state := "p93_callback_state_" + suffix
	ciphertext, err := vault.Encrypt([]byte("verifier"), "external-auth:"+challengeID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO external_auth_challenges
(id,application_id,provider,flow,app_redirect_uri,state_digest,nonce_digest,verifier_ciphertext,expires_at)
VALUES($1,$2,'google','automatic','https://app.example/callback',$3,$4,$5,$6)`, challengeID, applicationID, vault.Digest(state), vault.Digest("nonce"), ciphertext, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM external_auth_challenges WHERE id=$1`, challengeID)
		_, _ = db.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, applicationID)
		_, _ = db.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	}()

	request := httptest.NewRequest(http.MethodGet, "/v1/auth/providers/google/callback?state="+state, nil)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, chi.NewRouteContext()))
	response := httptest.NewRecorder()
	resolvedApplicationID := ""
	server.routeExternalAuthCallback(response, request, "google", func(_ http.ResponseWriter, callbackRequest *http.Request) {
		resolvedApplicationID = chi.URLParam(callbackRequest, "application_id")
	})
	if response.Code != http.StatusOK {
		t.Fatalf("callback router returned %d: %s", response.Code, response.Body.String())
	}
	if resolvedApplicationID != applicationID.String() {
		t.Fatalf("resolved application = %q, want %q", resolvedApplicationID, applicationID)
	}
}
