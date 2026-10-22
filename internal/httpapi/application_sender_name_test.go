package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/supaapps/platform93/internal/kernel"
)

func TestApplicationSenderNameConfigurationPostgres(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	base := "/v1/control/applications/" + f.application
	var version int64 = 1
	patch := func(body map[string]any, etag int64) *httptest.ResponseRecorder {
		t.Helper()
		encoded, _ := json.Marshal(body)
		r := httptest.NewRequest("PATCH", base+"/internal-config", strings.NewReader(string(encoded)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", f.app.PublicURL)
		r.Header.Set("If-Match", kernel.ETag(etag))
		r.AddCookie(&http.Cookie{Name: "p93_control_access", Value: f.controlToken})
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, r)
		return w
	}
	for _, name := range []string{"  Example Support  ", strings.Repeat("é", 200), "", "   "} {
		w := patch(map[string]any{"email_sender_name": name}, version)
		if w.Code != http.StatusNoContent {
			t.Fatalf("sender update: %d %s", w.Code, w.Body.String())
		}
		version++
		if w.Header().Get("ETag") != kernel.ETag(version) {
			t.Fatal("missing updated version")
		}
		config, err := loadApplicationInternalConfig(t.Context(), f.app.DB, f.application)
		if err != nil || config.EmailSenderName != strings.TrimSpace(name) || !config.PasswordEnabled || config.RegistrationMode != "public" {
			t.Fatalf("update lost configuration: %+v %v", config, err)
		}
	}
	for _, invalid := range []any{nil, false, 7, map[string]any{"name": "Example"}, strings.Repeat("a", 201), "Name\r\nBcc: injected@example.test", "\nName", "Name\x00", "Name\u0085"} {
		w := patch(map[string]any{"email_sender_name": invalid}, version)
		if w.Code != 422 || !strings.Contains(w.Body.String(), "invalid_email_sender_name") {
			t.Fatalf("invalid sender accepted: %d %s", w.Code, w.Body.String())
		}
	}
	w := patch(map[string]any{"email_sender_name": "App Only"}, version)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	version++
	w = patch(map[string]any{"password_enabled": false}, version)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	version++
	config, err := loadApplicationInternalConfig(t.Context(), f.app.DB, f.application)
	if err != nil || config.EmailSenderName != "App Only" || config.PasswordEnabled {
		t.Fatalf("unrelated policy edit reset sender: %+v %v", config, err)
	}
	if w = patch(map[string]any{"email_sender_name": "Stale"}, version-1); w.Code != 412 {
		t.Fatalf("stale version accepted: %d %s", w.Code, w.Body.String())
	}
	w = f.controlJSON("GET", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"email_sender_name":"App Only"`) {
		t.Fatal("control read lost saved name", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("GET", "/v1/applications/"+f.application+"/public-config", nil)
	w = httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "email_sender_name") || strings.Contains(w.Body.String(), "App Only") {
		t.Fatal("sender config leaked publicly", w.Code, w.Body.String())
	}
	w = f.optionalJSON("PATCH", base+"/internal-config", map[string]any{"email_sender_name": "User cannot edit"}, false)
	if w.Code != 401 && w.Code != 403 {
		t.Fatal("application user changed control configuration", w.Code, w.Body.String())
	}
	foreignOrg, foreignApp := kernel.NewID(), kernel.NewID()
	f.exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Other organization',$2)`, foreignOrg, foreignOrg.String())
	f.exec(`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Other application',$3)`, foreignApp, foreignOrg, foreignApp.String())
	w = f.optionalJSON("PATCH", "/v1/control/applications/"+foreignApp.String()+"/internal-config", map[string]any{"email_sender_name": "Foreign"}, true)
	if w.Code != 403 && w.Code != 404 {
		t.Fatal("foreign configuration was accessible", w.Code, w.Body.String())
	}
	var auditCount int
	if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_records WHERE application_id=$1 AND action='http.patch' AND changes->>'path'=$2`, f.application, base+"/internal-config").Scan(&auditCount); err != nil || auditCount != 6 {
		t.Fatalf("configuration changes were not audited: count=%d err=%v", auditCount, err)
	}
}
