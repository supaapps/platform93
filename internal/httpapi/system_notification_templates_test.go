package httpapi

import (
	"context"
	"encoding/json"
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

func TestSystemTemplateInheritanceAndApplicationFlowConfig(t *testing.T) {
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
	suffix := applicationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Template test',$2)`, organizationID, "template-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Template application',$3)`, applicationID, organizationID, "template-"+suffix); err != nil {
		t.Fatal(err)
	}
	localizedUserID := kernel.NewID()
	localizedEmail := "localized-" + suffix + "@example.test"
	if _, err = db.Exec(context.Background(), `INSERT INTO users(id,application_id,email,normalized_email,locale)
VALUES($1,$2,$3,$3,'de-CH')`, localizedUserID, applicationID, localizedEmail); err != nil {
		t.Fatal(err)
	}
	localizedKey := "localized." + strings.ReplaceAll(suffix, "-", "")
	if _, err = db.Exec(context.Background(), `INSERT INTO notification_templates
(id,application_id,key,locale,category,version,subject_template,text_template,variable_schema,status)
VALUES($1,NULL,$2,'en','transactional',1,'English','English {{message_locale}}','{}','published'),
($3,$4,$2,'de','transactional',1,'Deutsch','Deutsch {{message_locale}}','{}','published')`,
		kernel.NewID(), localizedKey, kernel.NewID(), applicationID); err != nil {
		t.Fatal(err)
	}
	applicationIDString := applicationID.String()
	_, resolvedLocale, localizedPayload, err := server.renderSystemNotification(context.Background(), &applicationIDString, localizedKey, localizedEmail, map[string]any{})
	if err != nil || resolvedLocale != "de" || !strings.Contains(string(localizedPayload), `Deutsch de`) || !strings.Contains(string(localizedPayload), `"fallback_used":true`) {
		t.Fatalf("regional locale did not fall back to the application language: locale=%q payload=%s err=%v", resolvedLocale, localizedPayload, err)
	}
	queueRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"template_key": localizedKey, "user_id": localizedUserID.String(),
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "operator"})
	queueResponse := httptest.NewRecorder()
	server.queueNotification(queueResponse, queueRequest)
	if queueResponse.Code != http.StatusAccepted || !strings.Contains(queueResponse.Body.String(), `"resolved_locale":"de"`) || !strings.Contains(queueResponse.Body.String(), `"fallback_used":true`) {
		t.Fatalf("localized notification was not queued with fallback metadata: %d %s", queueResponse.Code, queueResponse.Body.String())
	}
	var storedLocale string
	if err = db.QueryRow(context.Background(), `SELECT locale FROM notifications WHERE application_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 1`, applicationID, localizedUserID).Scan(&storedLocale); err != nil || storedLocale != "de" {
		t.Fatalf("notification stored the wrong resolved locale: %q %v", storedLocale, err)
	}

	listRequest := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "operator"})
	listResponse := httptest.NewRecorder()
	server.listNotificationTemplates(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), `"key":"platform93.application_sign_in"`) || !strings.Contains(listResponse.Body.String(), `"inherited":true`) {
		t.Fatalf("application defaults were not inherited: %d %s", listResponse.Code, listResponse.Body.String())
	}

	var installationTemplateID string
	if err = db.QueryRow(context.Background(), `SELECT id FROM notification_templates
WHERE application_id IS NULL AND key=$1 AND status='published'`, applicationSignInTemplate).Scan(&installationTemplateID); err != nil {
		t.Fatal(err)
	}
	updateRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{
		"subject_template": "Custom sign in to {{application_name}}",
	}, map[string]string{"application_id": applicationID.String(), "template_id": installationTemplateID}, kernel.Actor{Type: "operator"})
	updateResponse := httptest.NewRecorder()
	server.updateNotificationTemplate(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusCreated {
		t.Fatalf("inherited template override failed: %d %s", updateResponse.Code, updateResponse.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(updateResponse.Body.Bytes(), &created) != nil || created.ID == "" {
		t.Fatal("template override response did not contain an id")
	}
	publishRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{}, map[string]string{"application_id": applicationID.String(), "template_id": created.ID}, kernel.Actor{Type: "operator"})
	publishResponse := httptest.NewRecorder()
	server.publishNotificationTemplate(publishResponse, publishRequest)
	if publishResponse.Code != http.StatusNoContent {
		t.Fatalf("application template publish failed: %d %s", publishResponse.Code, publishResponse.Body.String())
	}
	_, _, rendered, err := server.renderSystemNotification(context.Background(), &applicationIDString, applicationSignInTemplate, "user@example.test", map[string]any{
		"code": "AB12CD34", "magic_link": "https://app.example/auth/callback", "expires_minutes": 10, "intent": "sign_in",
	})
	if err != nil || !strings.Contains(string(rendered), "Custom sign in to Template application") {
		t.Fatalf("published application override was not effective: %s %v", rendered, err)
	}

	clientID := kernel.NewID()
	if _, err = db.Exec(context.Background(), `INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes)
VALUES($1,$2,'web','Web','public',ARRAY['https://app.example/auth/callback'],ARRAY['authorization_code','refresh_token'],ARRAY['openid','profile','email'])`, clientID, applicationID); err != nil {
		t.Fatal(err)
	}
	configRequest := requestWithRoute(t, http.MethodPatch, "/", map[string]any{"flows": map[string]any{
		"oauth_client_id": "web", "sign_in_redirect_uri": "https://app.example/auth/callback", "invitation_redirect_uri": "https://app.example/invitations/accept",
	}}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "operator"})
	configResponse := httptest.NewRecorder()
	server.updateAuthConfig(configResponse, configRequest)
	if configResponse.Code != http.StatusNoContent {
		t.Fatalf("application flow config failed: %d %s", configResponse.Code, configResponse.Body.String())
	}
	publicRequest := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	publicResponse := httptest.NewRecorder()
	server.publicConfig(publicResponse, publicRequest)
	if publicResponse.Code != http.StatusOK || !strings.Contains(publicResponse.Body.String(), `"oauth_client_id":"web"`) || !strings.Contains(publicResponse.Body.String(), `"invitation_redirect_uri":"https://app.example/invitations/accept"`) {
		t.Fatalf("public config omitted application flows: %d %s", publicResponse.Code, publicResponse.Body.String())
	}
}
