package httpapi

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestWorkspaceMemberRoleReplacementIsAtomic(t *testing.T) {
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
	userID, ownerID, workspaceID, firstRoleID, secondRoleID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Workspace test',$2)`, []any{organizationID, "workspace-management-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Workspace test',$3)`, []any{applicationID, organizationID, "workspace-management-" + suffix}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{userID, applicationID, "workspace-" + suffix + "@example.test"}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{ownerID, applicationID, "owner-" + suffix + "@example.test"}},
		{`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,$4,'Workspace')`, []any{workspaceID, applicationID, ownerID, "workspace-" + suffix}},
		{`INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,$3,'One','workspace',ARRAY['one'])`, []any{firstRoleID, applicationID, "one-" + suffix}},
		{`INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,$3,'Two','workspace',ARRAY['two'])`, []any{secondRoleID, applicationID, "two-" + suffix}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	params := map[string]string{"application_id": applicationID.String(), "workspace_id": workspaceID.String(), "user_id": userID.String()}
	replace := requestWithRoute(t, "PUT", "/", map[string]any{"role_keys": []string{"one-" + suffix, "two-" + suffix}}, params, kernel.Actor{Type: "operator"})
	response := httptest.NewRecorder()
	server.replaceWorkspaceMemberRoles(response, replace)
	if response.Code != 200 {
		t.Fatalf("initial role replacement failed: %d %s", response.Code, response.Body.String())
	}

	replace = requestWithRoute(t, "PUT", "/", map[string]any{"role_keys": []string{"two-" + suffix}}, params, kernel.Actor{Type: "operator"})
	response = httptest.NewRecorder()
	server.replaceWorkspaceMemberRoles(response, replace)
	if response.Code != 200 {
		t.Fatalf("second role replacement failed: %d %s", response.Code, response.Body.String())
	}
	var count int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM role_assignments WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3`, applicationID, workspaceID, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	var roleID string
	if err = db.QueryRow(context.Background(), `SELECT role_id::text FROM role_assignments WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3`, applicationID, workspaceID, userID).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if count != 1 || roleID != secondRoleID.String() {
		t.Fatalf("role replacement left stale assignments: count=%d role=%s", count, roleID)
	}
}
