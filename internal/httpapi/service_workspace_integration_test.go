package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
)

func TestServiceWorkspaceReadPreservesAuthorizationBoundaries(t *testing.T) {
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
	owner, member, outsider, workspace, client := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	fixtures := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Service workspace test',$2)`, []any{org, org.String()}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Service test',$3),($4,$2,'Other application',$5)`, []any{app, org, app.String(), otherApp, otherApp.String()}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'owner@example.test','owner@example.test'),($3,$2,'member@example.test','member@example.test'),($4,$2,'outsider@example.test','outsider@example.test')`, []any{owner, app, member, outsider}},
		{`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'service-test','Service workspace')`, []any{workspace, app, owner}},
		{`INSERT INTO workspace_memberships(application_id,workspace_id,user_id) VALUES($1,$2,$3)`, []any{app, workspace, member}},
	}
	for _, fixture := range fixtures {
		if _, err := db.Exec(ctx, fixture.query, fixture.args...); err != nil {
			t.Fatal(err)
		}
	}
	permission := "/applications/" + app.String() + "/workspaces/read"
	for _, tc := range []struct {
		name        string
		application string
		actor       kernel.Actor
		service     bool
		status      int
	}{
		{"machine without membership", app.String(), kernel.Actor{Type: "client", ID: client.String(), Permissions: []string{permission}}, true, http.StatusOK},
		{"machine missing permission", app.String(), kernel.Actor{Type: "client", ID: client.String()}, true, http.StatusForbidden},
		{"machine wrong application permission", otherApp.String(), kernel.Actor{Type: "client", ID: client.String(), Permissions: []string{permission}}, true, http.StatusForbidden},
		{"foreign workspace hidden", otherApp.String(), kernel.Actor{Type: "client", ID: client.String(), Permissions: []string{"/applications/" + otherApp.String() + "/workspaces/read"}}, true, http.StatusNotFound},
		{"user rejected by service", app.String(), kernel.Actor{Type: "user", ID: owner.String(), Permissions: []string{permission}}, true, http.StatusForbidden},
		{"owner normal read", app.String(), kernel.Actor{Type: "user", ID: owner.String()}, false, http.StatusOK},
		{"member normal read", app.String(), kernel.Actor{Type: "user", ID: member.String()}, false, http.StatusOK},
		{"nonmember normal read", app.String(), kernel.Actor{Type: "user", ID: outsider.String(), Permissions: []string{permission}}, false, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": tc.application, "workspace_id": workspace.String()}, tc.actor)
			response := httptest.NewRecorder()
			if tc.service {
				s.serviceGetWorkspace(response, request)
			} else {
				s.getWorkspace(response, request)
			}
			if response.Code != tc.status {
				t.Fatalf("got %d, want %d: %s", response.Code, tc.status, response.Body.String())
			}
			if tc.status == http.StatusOK {
				var result struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.ID != workspace.String() || response.Header().Get("ETag") == "" {
					t.Fatalf("invalid workspace response: %s", response.Body.String())
				}
			}
		})
	}
}
