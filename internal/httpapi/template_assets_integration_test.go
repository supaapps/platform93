package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/supaapps/platform93/internal/kernel"
)

func TestTemplateAssetValidationPostgres(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	provider, other := kernel.NewID().String(), kernel.NewID().String()
	f.exec(`INSERT INTO storage_providers(id,name,endpoint,region,public_bucket,private_bucket,credentials_ciphertext) VALUES($1,'Fixture','https://storage.example.test','test','public','private','fixture')`, provider)
	f.exec(`INSERT INTO applications(id,organization_id,name,slug) SELECT $1,organization_id,'Other',$1::uuid::text FROM applications WHERE id=$2`, other, f.application)
	base := f.controlJSON("POST", "/notification-templates", map[string]any{"key": "asset_base", "category": "transactional", "subject_template": "Hello", "text_template": "Hello"})
	if base.Code != 201 {
		t.Fatalf("%d %s", base.Code, base.Body.String())
	}
	var template map[string]any
	if err := json.Unmarshal(base.Body.Bytes(), &template); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, visibility, status, mime, scope string
		want                                  int
	}{
		{"missing", "public", "ready", "image/png", "missing", 422},
		{"private", "private", "ready", "image/png", "application", 422},
		{"pending", "public", "pending", "image/png", "application", 422},
		{"non_image", "public", "ready", "text/plain", "application", 422},
		{"foreign", "public", "ready", "image/png", "foreign", 422},
		{"application", "public", "ready", "image/png", "application", 201},
		{"installation", "public", "ready", "image/png", "installation", 201},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := kernel.NewID().String()
			if test.scope != "missing" {
				var app any = f.application
				owner := "application"
				if test.scope == "foreign" {
					app = other
				}
				if test.scope == "installation" {
					app = nil
					owner = "installation"
				}
				f.exec(`INSERT INTO storage_objects(id,application_id,storage_provider_id,owner_type,visibility,bucket_role,bucket_name,object_key,filename,content_type,size_bytes,status,upload_expires_at) VALUES($1,$2,$3,$4,$5,$5,$5,$1::uuid::text,'fixture.png',$6,100,$7,now()+interval '10 minutes')`, id, app, provider, owner, test.visibility, test.mime, test.status)
			}
			html := fmt.Sprintf(`<img src="https://assets.example.test/fixture.png" data-p93-object-id="%s">`, id)
			for _, method := range []string{"POST", "PATCH"} {
				path := "/notification-templates"
				body := map[string]any{"html_template": html}
				if method == "POST" {
					body["key"] = "asset_" + test.name
					body["category"] = "transactional"
					body["subject_template"] = "Hello"
					body["text_template"] = "Hello"
				} else {
					path += "/" + template["id"].(string)
				}
				var before int
				if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM notification_templates WHERE application_id=$1`, f.application).Scan(&before); err != nil {
					t.Fatal(err)
				}
				w := f.controlJSON(method, path, body)
				if w.Code != test.want {
					t.Fatalf("%s: %d %s", method, w.Code, w.Body.String())
				}
				if test.want == 422 {
					if !strings.Contains(w.Body.String(), "invalid_notification_template_assets") {
						t.Fatal(w.Body.String())
					}
					var after int
					if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM notification_templates WHERE application_id=$1`, f.application).Scan(&after); err != nil {
						t.Fatal(err)
					}
					if after != before {
						t.Fatal("invalid asset left a template version")
					}
				} else {
					var result map[string]any
					if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					var refs int
					if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM notification_template_assets WHERE notification_template_id=$1 AND storage_object_id=$2`, result["id"], id).Scan(&refs); err != nil {
						t.Fatal(err)
					}
					if refs != 1 {
						t.Fatal("valid asset reference missing")
					}
				}
			}
		})
	}
	f.exec(`CREATE FUNCTION reject_asset_reference() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-storage-diagnostic'; END $$`)
	f.exec(`CREATE TRIGGER reject_asset_reference BEFORE INSERT ON notification_template_assets FOR EACH ROW EXECUTE FUNCTION reject_asset_reference()`)
	var valid string
	if err := f.app.DB.QueryRow(context.Background(), `SELECT id FROM storage_objects WHERE application_id=$1 AND status='ready' AND visibility='public' AND content_type='image/png'`, f.application).Scan(&valid); err != nil {
		t.Fatal(err)
	}
	w := f.controlJSON("POST", "/notification-templates", map[string]any{"key": "asset_storage_failure", "category": "transactional", "subject_template": "Hello", "text_template": "Hello", "html_template": fmt.Sprintf(`<img src="https://assets.example.test/fixture.png" data-p93-object-id="%s">`, valid)})
	if w.Code != 500 || strings.Contains(w.Body.String(), "private-storage-diagnostic") {
		t.Fatalf("unexpected asset error: %d %s", w.Code, w.Body.String())
	}
}
