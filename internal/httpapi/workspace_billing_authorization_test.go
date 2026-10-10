package httpapi

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
)

func TestWorkspaceBillingUsesExplicitCheckoutSubject(t *testing.T) {
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{app: platform.New(db, nil, "https://platform93.test")}
	org, app, otherApp := kernel.NewID(), kernel.NewID(), kernel.NewID()
	owner, member, outsider, workspace := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	fixtures := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Billing authorization test',$2)`, []any{org, org.String()}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Billing test',$3),($4,$2,'Other application',$5)`, []any{app, org, app.String(), otherApp, otherApp.String()}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'owner@example.test','owner@example.test'),($3,$2,'member@example.test','member@example.test'),($4,$2,'outsider@example.test','outsider@example.test')`, []any{owner, app, member, outsider}},
		{`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'billing-test','Billing workspace')`, []any{workspace, app, owner}},
		{`INSERT INTO workspace_memberships(application_id,workspace_id,user_id) VALUES($1,$2,$3)`, []any{app, workspace, member}},
	}
	for _, fixture := range fixtures {
		if _, err := db.Exec(ctx, fixture.query, fixture.args...); err != nil {
			t.Fatal(err)
		}
	}
	permission := "/applications/" + app.String() + "/workspaces/" + workspace.String() + "/billing/manage"
	for _, tc := range []struct {
		name, application, routeWorkspace string
		actor                             kernel.Actor
		allowed                           bool
	}{
		{"owner with body subject only", app.String(), "", kernel.Actor{Type: "user", ID: owner.String()}, true},
		{"owner with unrelated route parameter", app.String(), kernel.NewID().String(), kernel.Actor{Type: "user", ID: owner.String()}, true},
		{"owner in wrong application", otherApp.String(), "", kernel.Actor{Type: "user", ID: owner.String()}, false},
		{"member without billing permission", app.String(), "", kernel.Actor{Type: "user", ID: member.String()}, false},
		{"member with billing permission", app.String(), "", kernel.Actor{Type: "user", ID: member.String(), Permissions: []string{permission}}, true},
		{"outsider even with permission", app.String(), "", kernel.Actor{Type: "user", ID: outsider.String(), Permissions: []string{permission}}, false},
		{"control user", app.String(), "", kernel.Actor{Type: "control_user", ID: outsider.String()}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := requestWithRoute(t, http.MethodPost, "/", nil, map[string]string{"application_id": tc.application, "workspace_id": tc.routeWorkspace}, tc.actor)
			if got := s.canManageWorkspaceBillingFor(r, workspace.String()); got != tc.allowed {
				t.Fatalf("billing authorization = %v, want %v", got, tc.allowed)
			}
		})
	}
	if _, err := db.Exec(ctx, `UPDATE workspaces SET deleted_at=now() WHERE id=$1`, workspace); err != nil {
		t.Fatal(err)
	}
	r := requestWithRoute(t, http.MethodPost, "/", nil, map[string]string{"application_id": app.String()}, kernel.Actor{Type: "user", ID: owner.String()})
	if s.canManageWorkspaceBillingFor(r, workspace.String()) {
		t.Fatal("archived workspace owner retained billing access")
	}
}
