package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestPasswordlessSignupLocale(t *testing.T) {
	dsn := os.Getenv("PLATFORM93_DATABASE_URL")
	if dsn == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(dsn); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := database.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app := platform.New(db, vault, "https://platform.example.test")
	server := &Server{app: app}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = app.EnsureSigningKey(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	org, application := kernel.NewID().String(), kernel.NewID().String()
	if _, err = db.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Locale tests',$2)`, org, org); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO applications(id,organization_id,name,slug,internal_config)
VALUES($1,$2,'Locale tests',$3,'{"registration_mode":"public","password_enabled":true,"passwordless_enabled":true,"personal_api_keys_enabled":false,"delegation_enabled":false,"user_invitations_enabled":false,"custom_token_claim_keys":[]}')`, application, org, application); err != nil {
		t.Fatal(err)
	}
	otherApplication := kernel.NewID().String()
	if _, err = db.Exec(ctx, `INSERT INTO applications(id,organization_id,name,slug,internal_config)
SELECT $1,organization_id,'Other locale tests',$2,internal_config FROM applications WHERE id=$3`, otherApplication, otherApplication, application); err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"en", "de"} {
		if _, err = db.Exec(ctx, `INSERT INTO notification_templates
(id,application_id,key,locale,category,version,subject_template,text_template,variable_schema,status)
VALUES($1,$2,$3,$4,'security',1,$4,'{{code}}|{{magic_link}}',
'{"properties":{"code":{"type":"string"},"magic_link":{"type":"string"},"expires_minutes":{"type":"integer"},"intent":{"type":"string"}}}','published')`, kernel.NewID(), application, applicationSignInTemplate, locale); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(ctx, `INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris)
VALUES($1,$2,$3,'Browser','public',ARRAY['https://app.example.test/callback'])`, kernel.NewID(), application, "locale-"+application); err != nil {
		t.Fatal(err)
	}
	start := func(t *testing.T, email, intent, locale, delivery, expectedLocale string) (string, map[string]any) {
		t.Helper()
		w := httptest.NewRecorder()
		request := requestWithRoute(t, http.MethodPost, "/", map[string]any{"email": email, "intent": intent, "locale": locale, "delivery": delivery, "redirect_uri": "https://app.example.test/callback"}, map[string]string{"application_id": application}, kernel.Actor{})
		// Locale tests use unique recipients; shared-IP rate limits have separate coverage.
		request.RemoteAddr = ""
		server.emailStart(w, request)
		if w.Code != http.StatusAccepted {
			t.Fatalf("start: %d %s", w.Code, w.Body.String())
		}
		var response struct {
			ChallengeID string `json:"challenge_id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		var encrypted, selected string
		if err := db.QueryRow(ctx, `SELECT payload_ciphertext,locale FROM notifications WHERE id=$1`, response.ChallengeID).Scan(&encrypted, &selected); err != nil {
			t.Fatal(err)
		}
		if selected != expectedLocale {
			t.Fatalf("delivery locale %q, want %q", selected, expectedLocale)
		}
		payload, err := vault.Decrypt(encrypted, "notification:"+response.ChallengeID)
		if err != nil {
			t.Fatal(err)
		}
		var rendered struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(payload, &rendered); err != nil {
			t.Fatal(err)
		}
		parts := strings.SplitN(rendered.Text, "|", 2)
		credentials := map[string]any{"challenge_id": response.ChallengeID}
		if delivery == "link" {
			link, err := url.Parse(parts[1])
			if err != nil {
				t.Fatal(err)
			}
			credentials["link_token"] = link.Query().Get("link_token")
		} else {
			credentials["code"] = parts[0]
		}
		return response.ChallengeID, credentials
	}
	verify := func(t *testing.T, credentials map[string]any, appID string, status int) {
		t.Helper()
		w := httptest.NewRecorder()
		request := requestWithRoute(t, http.MethodPost, "/", credentials, map[string]string{"application_id": appID}, kernel.Actor{})
		request.RemoteAddr = ""
		server.emailVerify(w, request)
		if w.Code != status {
			t.Fatalf("verify: %d %s, want %d", w.Code, w.Body.String(), status)
		}
	}
	for _, delivery := range []string{"code", "link", "both"} {
		t.Run(delivery, func(t *testing.T) {
			email := delivery + "-" + application + "@example.test"
			challenge, credentials := start(t, email, "automatic", "de_ch", delivery, "de")
			var locale string
			if err := db.QueryRow(ctx, `SELECT locale FROM login_challenges WHERE id=$1`, challenge).Scan(&locale); err != nil || locale != "de-CH" {
				t.Fatalf("challenge locale: %q %v", locale, err)
			}
			verify(t, credentials, otherApplication, http.StatusUnauthorized)
			verify(t, credentials, application, http.StatusOK)
			if err := db.QueryRow(ctx, `SELECT locale FROM users WHERE application_id=$1 AND normalized_email=$2`, application, email).Scan(&locale); err != nil || locale != "de-CH" {
				t.Fatalf("user locale: %q %v", locale, err)
			}
			verify(t, credentials, application, http.StatusUnauthorized)
			_, login := start(t, email, "sign_in", "en", "code", "de")
			verify(t, login, application, http.StatusOK)
			if err := db.QueryRow(ctx, `SELECT locale FROM users WHERE application_id=$1 AND normalized_email=$2`, application, email).Scan(&locale); err != nil || locale != "de-CH" {
				t.Fatalf("login overwrote locale: %q %v", locale, err)
			}
		})
	}
	_, credentials := start(t, "default-"+application+"@example.test", "sign_up", "", "code", "en")
	verify(t, credentials, application, http.StatusOK)
	var locale string
	if err := db.QueryRow(ctx, `SELECT locale FROM users WHERE application_id=$1 AND normalized_email=$2`, application, "default-"+application+"@example.test").Scan(&locale); err != nil || locale != "" {
		t.Fatalf("default locale: %q %v", locale, err)
	}
	_, login := start(t, "default-"+application+"@example.test", "sign_in", "de-CH", "code", "de")
	verify(t, login, application, http.StatusOK)
	if err := db.QueryRow(ctx, `SELECT locale FROM users WHERE application_id=$1 AND normalized_email=$2`, application, "default-"+application+"@example.test").Scan(&locale); err != nil || locale != "" {
		t.Fatalf("login changed an unset preference: %q %v", locale, err)
	}
	_, fallback := start(t, "fallback-"+application+"@example.test", "sign_up", "fr-CA", "code", "en")
	verify(t, fallback, application, http.StatusOK)
	if err := db.QueryRow(ctx, `SELECT locale FROM users WHERE application_id=$1 AND normalized_email=$2`, application, "fallback-"+application+"@example.test").Scan(&locale); err != nil || locale != "fr-CA" {
		t.Fatalf("fallback lost requested locale: %q %v", locale, err)
	}
	challenge, expired := start(t, "expired-"+application+"@example.test", "sign_up", "de-CH", "code", "de")
	if _, err := db.Exec(ctx, `UPDATE login_challenges SET expires_at=now()-interval '1 minute' WHERE id=$1`, challenge); err != nil {
		t.Fatal(err)
	}
	verify(t, expired, application, http.StatusUnauthorized)
	for _, invalid := range []string{"not a locale", strings.Repeat("a", 36), "und"} {
		w := httptest.NewRecorder()
		server.emailStart(w, requestWithRoute(t, http.MethodPost, "/", map[string]any{"email": "invalid@example.test", "intent": "sign_up", "delivery": "code", "locale": invalid}, map[string]string{"application_id": application}, kernel.Actor{}))
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "invalid_user_locale") {
			t.Fatalf("invalid locale accepted: %d %s", w.Code, w.Body.String())
		}
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM login_challenges WHERE application_id=$1 AND normalized_email='invalid@example.test'`, application).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid locale persisted: %d %v", count, err)
	}
}
