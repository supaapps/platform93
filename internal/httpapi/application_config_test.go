package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestApplicationConfigurationExposureAndEnforcement(t *testing.T) {
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
	userID, keyID, delegationID, sessionID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO operators(id,email,normalized_email,display_name) VALUES($1,$2,$2,'Configuration owner')`, []any{operatorID, "config-" + suffix + "@platform93.test"}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Configuration test',$2)`, []any{organizationID, "config-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug,internal_config) VALUES($1,$2,'Configuration test',$3,$4)`, []any{applicationID, organizationID, "config-" + suffix, `{"registration_mode":"public","password_enabled":true,"passwordless_enabled":true,"personal_api_keys_enabled":true,"delegation_enabled":true}`}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{userID, applicationID, "user-" + suffix + "@platform93.test"}},
		{`INSERT INTO personal_api_keys(id,application_id,user_id,token_prefix,token_digest,expires_at) VALUES($1,$2,$3,'p93_pat_test',$4,now()+interval '1 day')`, []any{keyID, applicationID, userID, []byte("key-" + suffix)}},
		{`INSERT INTO delegations(id,application_id,operator_id,user_id,reason,redirect_uri,permissions,exchange_digest,expires_at) VALUES($1,$2,$3,$4,'Support','https://app.example/callback',ARRAY['read'],$5,now()+interval '1 day')`, []any{delegationID, applicationID, operatorID, userID, []byte("delegation-" + suffix)}},
		{`INSERT INTO user_sessions(id,application_id,user_id,delegation_id,refresh_digest,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 day')`, []any{sessionID, applicationID, userID, delegationID, []byte("session-" + suffix)}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	publicRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{
		"brand_name": "Example", "support_url": "https://example.test/help",
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "operator", ID: operatorID.String()})
	publicRequest.Header.Set("If-Match", kernel.ETag(1))
	publicResponse := httptest.NewRecorder()
	server.updatePublicApplicationConfig(publicResponse, publicRequest)
	if publicResponse.Code != http.StatusNoContent {
		t.Fatalf("public configuration failed: %d %s", publicResponse.Code, publicResponse.Body.String())
	}

	internalRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{
		"registration_mode": "invite_only", "password_enabled": true, "passwordless_enabled": true,
		"personal_api_keys_enabled": false, "delegation_enabled": false,
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "operator", ID: operatorID.String()})
	internalRequest.Header.Set("If-Match", kernel.ETag(2))
	internalResponse := httptest.NewRecorder()
	server.updateInternalApplicationConfig(internalResponse, internalRequest)
	if internalResponse.Code != http.StatusNoContent {
		t.Fatalf("internal configuration failed: %d %s", internalResponse.Code, internalResponse.Body.String())
	}

	var keyRevoked, delegationRevoked, sessionRevoked bool
	if err = db.QueryRow(context.Background(), `SELECT k.revoked_at IS NOT NULL,d.revoked_at IS NOT NULL,s.revoked_at IS NOT NULL
FROM personal_api_keys k JOIN delegations d ON d.id=$2 JOIN user_sessions s ON s.id=$3 WHERE k.id=$1`, keyID, delegationID, sessionID).
		Scan(&keyRevoked, &delegationRevoked, &sessionRevoked); err != nil {
		t.Fatal(err)
	}
	if !keyRevoked || !delegationRevoked || !sessionRevoked {
		t.Fatalf("disabled credentials were not revoked: key=%v delegation=%v session=%v", keyRevoked, delegationRevoked, sessionRevoked)
	}

	runtimeRequest := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	runtimeResponse := httptest.NewRecorder()
	server.publicConfig(runtimeResponse, runtimeRequest)
	body := runtimeResponse.Body.String()
	if runtimeResponse.Code != http.StatusOK || !strings.Contains(body, `"brand_name":"Example"`) || !strings.Contains(body, `"registration_mode":"invite_only"`) {
		t.Fatalf("runtime configuration was incomplete: %d %s", runtimeResponse.Code, body)
	}
	for _, privateKey := range []string{"internal_config", "personal_api_keys_enabled", "delegation_enabled"} {
		if strings.Contains(body, privateKey) {
			t.Fatalf("runtime configuration leaked %s: %s", privateKey, body)
		}
	}

	signUpRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"email": "new-" + suffix + "@platform93.test", "intent": "sign_up", "delivery": "both",
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	signUpResponse := httptest.NewRecorder()
	server.emailStart(signUpResponse, signUpRequest)
	if signUpResponse.Code != http.StatusForbidden || !strings.Contains(signUpResponse.Body.String(), "registration_invite_only") {
		t.Fatalf("invite-only registration accepted public signup: %d %s", signUpResponse.Code, signUpResponse.Body.String())
	}
}
