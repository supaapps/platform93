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

func TestNormalizedWebOrigin(t *testing.T) {
	tests := map[string]string{
		"https://app.example/auth/callback": "https://app.example",
		"https://APP.example:443/callback":  "https://app.example",
		"http://localhost:3000/callback":    "http://localhost:3000",
	}
	for input, wanted := range tests {
		if actual, ok := normalizedWebOrigin(input); !ok || actual != wanted {
			t.Errorf("normalizedWebOrigin(%q) = %q, %v; want %q, true", input, actual, ok, wanted)
		}
	}
	for _, input := range []string{"null", "file:///tmp/callback", "javascript:alert(1)", "https://user@app.example/callback"} {
		if _, ok := normalizedWebOrigin(input); ok {
			t.Errorf("normalizedWebOrigin(%q) accepted an unsafe origin", input)
		}
	}
}

func TestApplicationCORSUsesRegisteredPublicClientOrigins(t *testing.T) {
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
	organizationID, applicationID, clientID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := clientID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'CORS organization',$2)`, organizationID, "cors-org-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'CORS application',$3)`, applicationID, organizationID, "cors-app-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO clients
(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes)
VALUES($1,$2,$3,'Browser','public',ARRAY['https://app.example/auth/callback'],ARRAY['authorization_code'],ARRAY['openid'])`, clientID, applicationID, "cors-client-"+suffix); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM clients WHERE id=$1`, clientID)
		_, _ = db.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, applicationID)
		_, _ = db.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	}()

	handler := server.cors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	request := httptest.NewRequest(http.MethodOptions, "/v1/applications/"+applicationID.String()+"/public-config", nil)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Access-Control-Request-Method", "GET")
	request.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("registered origin preflight failed: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/applications/"+applicationID.String()+"/auth/email/start", nil)
	request.Header.Set("Origin", "https://evil.example")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unregistered origin was not rejected: status=%d headers=%v", response.Code, response.Header())
	}

	request = httptest.NewRequest(http.MethodOptions, "/oidc/token", nil)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Access-Control-Request-Method", "POST")
	request.Header.Set("Access-Control-Request-Headers", "Content-Type")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("OIDC preflight failed: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}
