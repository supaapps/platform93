package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestReferenceLabelsAndAggregatedUsage(t *testing.T) {
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
	server := &Server{app: platform.New(db, vault, "https://platform93.test")}
	org, app, other, user, foreign, workspace, control := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Label tests',$1::uuid::text)`, []any{org}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Labels',$1::uuid::text),($3,$2,'Other',$3::uuid::text)`, []any{app, org, other}},
		{`INSERT INTO users(id,application_id,email,normalized_email,first_name,last_name) VALUES($1,$2,$1::uuid::text||'@example.test',$1::uuid::text||'@example.test','Local','User'),($3,$4,$3::uuid::text||'@example.test',$3::uuid::text||'@example.test','Foreign','User')`, []any{user, app, foreign, other}},
		{`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,$1::uuid::text,'Local workspace')`, []any{workspace, app, user}},
		{`INSERT INTO control_users(id,email,normalized_email,display_name) VALUES($1,$1::uuid::text||'@example.test',$1::uuid::text||'@example.test','Label administrator')`, []any{control}},
		{`INSERT INTO organization_memberships(organization_id,control_user_id,role) VALUES($1,$2,'auditor')`, []any{org, control}},
	} {
		if _, err := db.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		db.Exec(ctx, `DELETE FROM organization_memberships WHERE control_user_id=$1`, control)
		db.Exec(ctx, `DELETE FROM control_users WHERE id=$1`, control)
		db.Exec(ctx, `DELETE FROM workspaces WHERE application_id IN ($1,$2)`, app, other)
		db.Exec(ctx, `DELETE FROM users WHERE application_id IN ($1,$2)`, app, other)
		db.Exec(ctx, `DELETE FROM applications WHERE organization_id=$1`, org)
		db.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org)
	}()
	actor := kernel.Actor{Type: "control_user", ID: control}
	query := url.Values{"references": {"users:" + user, "users:" + foreign, "workspaces:" + workspace, "users:" + user}}
	r := requestWithRoute(t, "GET", "/?"+query.Encode(), nil, map[string]string{"application_id": app}, actor)
	w := httptest.NewRecorder()
	server.listReferenceLabels(w, r)
	var labels struct {
		Items []referenceLabel `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &labels) != nil || len(labels.Items) != 2 {
		t.Fatalf("labels: %d %s", w.Code, w.Body.String())
	}
	for _, label := range labels.Items {
		if label.ID == foreign || label.Label == "Foreign User" {
			t.Fatal("cross-application label leaked")
		}
	}
	w = httptest.NewRecorder()
	server.listOrganizations(w, requestWithRoute(t, "GET", "/", nil, nil, actor))
	var organizations struct {
		Items []struct {
			ID    string                              `json:"id"`
			Usage struct{ Applications, Users int64 } `json:"usage"`
		} `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &organizations) != nil || len(organizations.Items) != 1 || organizations.Items[0].Usage.Applications != 2 || organizations.Items[0].Usage.Users != 2 {
		t.Fatalf("organization counts: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	server.listApplications(w, requestWithRoute(t, "GET", "/", nil, map[string]string{"organization_id": org}, actor))
	var applications struct {
		Items []struct {
			ID    string                            `json:"id"`
			Usage struct{ Users, Workspaces int64 } `json:"usage"`
		} `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &applications) != nil {
		t.Fatalf("application counts: %d %s", w.Code, w.Body.String())
	}
	found := false
	for _, item := range applications.Items {
		if item.ID == app {
			found = true
			if item.Usage.Users != 1 || item.Usage.Workspaces != 1 {
				t.Fatalf("application usage: %#v", item)
			}
		}
	}
	if !found {
		t.Fatal("application usage response omitted the authorized application")
	}
	for _, value := range []string{"secrets:anything", "users:"} {
		w = httptest.NewRecorder()
		server.listReferenceLabels(w, requestWithRoute(t, "GET", "/?references="+url.QueryEscape(value), nil, map[string]string{"application_id": app}, actor))
		if w.Code != 422 {
			t.Fatalf("invalid reference accepted: %d", w.Code)
		}
	}
}
