package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestOperatorMiddlewareEnforcesOrganizationBoundaryAndWriteRole(t *testing.T) {
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
	operatorID, sessionID := kernel.NewID(), kernel.NewID()
	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO operators(id,email,normalized_email,display_name) VALUES($1,$2,$2,'Boundary operator')`, operatorID, "boundary-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO operator_sessions(id,operator_id,refresh_digest,kind,expires_at) VALUES($1,$2,$3,'operator',$4)`, sessionID, operatorID, vault.Digest("refresh-"+suffix), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = server.app.EnsureSigningKey(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	token, err := server.issueOperatorAccess(context.Background(), operatorID.String(), sessionID.String(), "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Boundary org',$2)`, organizationID, "boundary-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Boundary app',$3)`, applicationID, organizationID, "boundary-"+suffix); err != nil {
		t.Fatal(err)
	}

	called := false
	handler := server.requireOperator(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	request := requestWithRoute(t, "GET", "/v1/applications/"+suffix+"/users", nil, map[string]string{"application_id": suffix}, kernel.Actor{})
	request.AddCookie(&http.Cookie{Name: "p93_operator_access", Value: token})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || called {
		t.Fatalf("operator crossed organization boundary: status=%d called=%v", response.Code, called)
	}

	if _, err = db.Exec(context.Background(), `INSERT INTO organization_memberships(organization_id,operator_id,role) VALUES($1,$2,'auditor')`, organizationID, operatorID); err != nil {
		t.Fatal(err)
	}
	request = requestWithRoute(t, "POST", "/v1/applications/"+suffix+"/users", map[string]any{}, map[string]string{"application_id": suffix}, kernel.Actor{})
	request.AddCookie(&http.Cookie{Name: "p93_operator_access", Value: token})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("read-only operator gained write access: status=%d called=%v", response.Code, called)
	}

	if _, err = db.Exec(context.Background(), `UPDATE organization_memberships SET role='admin' WHERE organization_id=$1 AND operator_id=$2`, organizationID, operatorID); err != nil {
		t.Fatal(err)
	}
	called = false
	request = requestWithRoute(t, "POST", "/v1/control/applications/"+suffix+"/users", map[string]any{}, map[string]string{"application_id": suffix}, kernel.Actor{})
	request.Header.Set("Origin", "https://platform93.test")
	request.AddCookie(&http.Cookie{Name: "p93_operator_access", Value: token})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("authorized operator write failed: status=%d called=%v", response.Code, called)
	}
	var method, path string
	if err = db.QueryRow(context.Background(), `SELECT changes->>'method',changes->>'path' FROM audit_records
WHERE actor_id=$1 AND application_id=$2 AND action='http.post' ORDER BY created_at DESC LIMIT 1`, operatorID, applicationID).Scan(&method, &path); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/v1/control/applications/"+suffix+"/users" {
		t.Fatalf("unexpected audit changes: method=%q path=%q", method, path)
	}
}
