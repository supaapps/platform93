package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
	"github.com/supaapps/platform93/migrations"
	"golang.org/x/net/html"
)

func TestPasswordlessEmailDeliveryPostgres(t *testing.T) {
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
	vault, _ := secure.NewVault(make([]byte, 32))
	app := platform.New(db, vault, "https://platform.example.test")
	s := &Server{app: app}
	tx, _ := db.Begin(ctx)
	if err := app.EnsureSigningKey(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	org, application := kernel.NewID().String(), kernel.NewID().String()
	if _, err := db.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1::uuid,'Delivery test',$1::text)`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO applications(id,organization_id,name,slug,internal_config)
VALUES($1::uuid,$2,'Delivery test',$1::text,'{"registration_mode":"public","password_enabled":true,"passwordless_enabled":true,"personal_api_keys_enabled":false,"delegation_enabled":false,"user_invitations_enabled":false,"custom_token_claim_keys":[]}')`, application, org); err != nil {
		t.Fatal(err)
	}
	const redirect = "https://app.example.test/callback?source=email"
	client := "email-" + application
	if _, err := db.Exec(ctx, `INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants)
VALUES($1,$2,$3,'Browser','public',ARRAY[$4],ARRAY['authorization_code','refresh_token'])`, kernel.NewID(), application, client, redirect); err != nil {
		t.Fatal(err)
	}
	start := func(t *testing.T, body map[string]any, status int) string {
		t.Helper()
		body["email"] = kernel.NewID().String() + "@example.test"
		body["intent"] = "automatic"
		w := httptest.NewRecorder()
		r := requestWithRoute(t, http.MethodPost, "/", body, map[string]string{"application_id": application}, kernel.Actor{})
		r.RemoteAddr = ""
		s.emailStart(w, r)
		if w.Code != status {
			t.Fatalf("start: %d %s; want %d", w.Code, w.Body.String(), status)
		}
		if status != http.StatusAccepted {
			var count int
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM login_challenges WHERE application_id=$1 AND normalized_email=$2)+(SELECT count(*) FROM notifications WHERE application_id=$1 AND recipient=$2)`, application, body["email"]).Scan(&count); err != nil || count != 0 {
				t.Fatalf("rejected request persisted mail/challenge: %d %v", count, err)
			}
			return ""
		}
		var response struct {
			ChallengeID string `json:"challenge_id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.ChallengeID
	}
	for _, delivery := range []string{"code", "link", "both"} {
		t.Run(delivery, func(t *testing.T) {
			input := map[string]any{"delivery": delivery}
			if delivery != "code" {
				input["redirect_uri"] = redirect
			}
			id := start(t, input, http.StatusAccepted)
			var cipher string
			var codeDigest, linkDigest []byte
			if err := db.QueryRow(ctx, `SELECT n.payload_ciphertext,c.code_digest,c.link_digest FROM notifications n JOIN login_challenges c ON c.id=n.id WHERE n.id=$1`, id).Scan(&cipher, &codeDigest, &linkDigest); err != nil {
				t.Fatal(err)
			}
			plain, err := vault.Decrypt(cipher, "notification:"+id)
			if err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Text string `json:"text"`
				HTML string `json:"html"`
			}
			if err := json.Unmarshal(plain, &payload); err != nil {
				t.Fatal(err)
			}
			code := regexp.MustCompile(`Code: ([A-Z0-9]{8})`).FindStringSubmatch(payload.Text)
			hasCode := delivery != "link"
			if (len(code) == 2) != hasCode || (len(codeDigest) > 0) != hasCode || strings.Contains(payload.HTML, "SIGN-IN CODE") != hasCode {
				t.Fatalf("code presentation/digest mismatch for %s", delivery)
			}
			var links []string
			doc, err := html.Parse(strings.NewReader(payload.HTML))
			if err != nil {
				t.Fatal(err)
			}
			var walk func(*html.Node)
			walk = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "a" {
					for _, a := range n.Attr {
						if a.Key == "href" {
							links = append(links, a.Val)
						}
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c)
				}
			}
			walk(doc)
			hasLink := delivery != "code"
			if (len(links) == 1) != hasLink || (len(linkDigest) > 0) != hasLink || strings.Contains(payload.Text, "Magic link:") != hasLink || strings.Contains(payload.HTML, "{{") {
				t.Fatalf("link presentation/digest mismatch for %s: %s", delivery, payload.HTML)
			}
			credentials := map[string]any{"challenge_id": id}
			if hasLink {
				link, err := url.Parse(links[0])
				if err != nil || link.Query().Get("source") != "email" || link.Query().Get("challenge_id") != id || link.Query().Get("link_token") == "" {
					t.Fatalf("invalid magic link: %q %v", links[0], err)
				}
				credentials["link_token"] = link.Query().Get("link_token")
			} else {
				credentials["code"] = code[1]
			}
			verify := func(values map[string]any, status int) {
				w := httptest.NewRecorder()
				r := requestWithRoute(t, http.MethodPost, "/", values, map[string]string{"application_id": application}, kernel.Actor{})
				r.RemoteAddr = ""
				s.emailVerify(w, r)
				if w.Code != status {
					t.Fatalf("verify %s: %d %s", delivery, w.Code, w.Body.String())
				}
			}
			if delivery == "link" {
				verify(map[string]any{"challenge_id": id, "code": "AB12CD34"}, http.StatusUnauthorized)
			}
			if delivery == "code" {
				verify(map[string]any{"challenge_id": id, "link_token": "not-issued"}, http.StatusUnauthorized)
			}
			verify(credentials, http.StatusOK)
			if delivery == "both" {
				verify(map[string]any{"challenge_id": id, "code": code[1]}, http.StatusUnauthorized)
			} else {
				verify(credentials, http.StatusUnauthorized)
			}
		})
	}
	for _, delivery := range []string{"link", "both", ""} {
		start(t, map[string]any{"delivery": delivery}, http.StatusUnprocessableEntity)
	}
	start(t, map[string]any{"delivery": "both", "redirect_uri": "https://other.example/callback"}, http.StatusUnprocessableEntity)
	if _, err := db.Exec(ctx, `UPDATE applications SET auth_config=jsonb_build_object('flows',jsonb_build_object('oauth_client_id',$2::text,'sign_in_redirect_uri',$3::text)) WHERE id=$1`, application, client, redirect); err != nil {
		t.Fatal(err)
	}
	start(t, map[string]any{"delivery": "both"}, http.StatusAccepted)
	start(t, map[string]any{}, http.StatusAccepted)
	if _, err := db.Exec(ctx, `UPDATE clients SET disabled_at=now() WHERE application_id=$1`, application); err != nil {
		t.Fatal(err)
	}
	start(t, map[string]any{"delivery": "code"}, http.StatusAccepted)
	start(t, map[string]any{"delivery": "link"}, http.StatusUnprocessableEntity)
	for _, key := range []string{controlUserSignInTemplate, verifyEmailTemplate, changeEmailTemplate, passwordResetTemplate} {
		for _, delivery := range []string{"code", "link", "both"} {
			variables := map[string]any{"code": "AB12CD34", "magic_link": redirect, "expires_minutes": 10}
			if delivery == "code" {
				variables["magic_link"] = ""
			}
			if delivery == "link" {
				variables["code"] = ""
			}
			_, _, payload, err := s.renderSystemNotification(ctx, &application, key, "user@example.test", variables)
			if err != nil || strings.Contains(string(payload), `href=\"\"`) || strings.Contains(string(payload), "{{#if") {
				t.Fatalf("shared template %s/%s: %s %v", key, delivery, payload, err)
			}
		}
	}
}

func TestAuthEmailDeliveryMigrationPostgres(t *testing.T) {
	f := newOAuthSecurityFixture(t)
	ctx := context.Background()
	raw, err := migrations.FS.ReadFile("00010_auth_email_delivery.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(raw), "-- +goose Down")
	up, down := strings.TrimPrefix(parts[0], "-- +goose Up"), parts[1]
	if _, err := f.app.DB.Exec(ctx, down); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE notification_templates SET subject_template='Customized Platform login' WHERE application_id IS NULL AND key=$1 AND status='published'`, controlUserSignInTemplate)
	var sourceID string
	if err := f.app.DB.QueryRow(ctx, `SELECT id FROM notification_templates WHERE application_id IS NULL AND key=$1 AND status='published'`, applicationSignInTemplate).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO notification_templates(id,application_id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status)
SELECT $1,$2,key,locale,category,1,'Customized application login',text_template,html_template,variable_schema,'published' FROM notification_templates WHERE id=$3`, kernel.NewID(), f.application, sourceID)
	for round := 0; round < 2; round++ {
		if _, err := f.app.DB.Exec(ctx, up); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := f.app.DB.QueryRow(ctx, `SELECT count(*) FROM notification_templates WHERE application_id IS NULL AND status='published' AND variable_schema ? 'x-platform93-delivery-source-id'`).Scan(&count); err != nil || count != 4 {
			t.Fatalf("up: expected four unchanged defaults upgraded, got %d %v", count, err)
		}
		if err := f.app.DB.QueryRow(ctx, `SELECT count(*) FROM notification_templates WHERE status='published' AND subject_template IN ('Customized Platform login','Customized application login')`).Scan(&count); err != nil || count != 2 {
			t.Fatalf("customizations were changed: %d %v", count, err)
		}
		if _, err := f.app.DB.Exec(ctx, down); err != nil {
			t.Fatal(err)
		}
		var status string
		if err := f.app.DB.QueryRow(ctx, `SELECT status FROM notification_templates WHERE id=$1`, sourceID).Scan(&status); err != nil || status != "published" {
			t.Fatalf("down did not restore original: %s %v", status, err)
		}
	}
	if _, err := f.app.DB.Exec(ctx, up); err != nil {
		t.Fatal(err)
	}
	customID := kernel.NewID().String()
	f.exec(`WITH old AS (UPDATE notification_templates SET status='archived' WHERE application_id IS NULL AND key=$1 AND status='published' RETURNING *)
INSERT INTO notification_templates(id,application_id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,system_managed)
SELECT $2,NULL,key,locale,category,version+1,'Later customization',text_template,html_template,variable_schema,'published',true FROM old`, applicationSignInTemplate, customID)
	if _, err := f.app.DB.Exec(ctx, down); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := f.app.DB.QueryRow(ctx, `SELECT status FROM notification_templates WHERE id=$1`, customID).Scan(&status); err != nil || status != "published" {
		t.Fatalf("down changed later customization with copied schema: %s %v", status, err)
	}
}
