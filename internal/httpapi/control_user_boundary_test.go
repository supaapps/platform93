package httpapi

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestControlUserMiddlewareEnforcesOrganizationBoundaryAndWriteRole(t *testing.T) {
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
	controlUserID, sessionID := kernel.NewID(), kernel.NewID()
	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email,display_name) VALUES($1,$2,$2,'Boundary control_user')`, controlUserID, "boundary-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_user_sessions(id,control_user_id,refresh_digest,kind,expires_at) VALUES($1,$2,$3,'control',$4)`, sessionID, controlUserID, vault.Digest("refresh-"+suffix), time.Now().Add(time.Hour)); err != nil {
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
	token, err := server.issueControlUserAccess(context.Background(), controlUserID.String(), sessionID.String(), "control")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := identity.Verify(token, func(kid string) (*rsa.PublicKey, error) {
		return server.app.ResolvePublicKey(context.Background(), kid)
	}, server.app.Issuer(), server.app.ControlAudience(), server.app.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.ActorType != "control_user" || claims.TokenKind != "control" || len(claims.Audience) != 1 || claims.Audience[0] != server.app.ControlAudience() {
		t.Fatalf("unexpected Platform user claims: actor_type=%q token_kind=%q audience=%v", claims.ActorType, claims.TokenKind, claims.Audience)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Boundary org',$2)`, organizationID, "boundary-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Boundary app',$3)`, applicationID, organizationID, "boundary-"+suffix); err != nil {
		t.Fatal(err)
	}

	applicationCalled := false
	applicationHandler := server.requireUser(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		applicationCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	applicationRequest := requestWithRoute(t, http.MethodGet, "/v1/applications/"+suffix+"/me", nil, map[string]string{"application_id": suffix}, kernel.Actor{})
	applicationRequest.Header.Set("Authorization", "Bearer "+token)
	applicationResponse := httptest.NewRecorder()
	applicationHandler.ServeHTTP(applicationResponse, applicationRequest)
	if applicationResponse.Code != http.StatusUnauthorized || applicationCalled {
		t.Fatalf("Platform user token authenticated an application endpoint: status=%d called=%v", applicationResponse.Code, applicationCalled)
	}

	kid, privateKey, err := server.app.ActiveSigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := server.app.Now()
	applicationToken, err := identity.Sign(privateKey, kid, identity.Claims{
		Issuer: server.app.Issuer(), Subject: kernel.NewID().String(), Audience: []string{server.app.ApplicationAudience(applicationID)},
		ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(), NotBefore: now.Add(-time.Second).Unix(),
		JWTID: kernel.NewID().String(), SessionID: kernel.NewID().String(), ApplicationID: applicationID.String(), TokenKind: "access", ActorType: "user",
		Roles: identity.RoleClaims{Application: []string{}, Workspaces: map[string][]string{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	controlCalled := false
	controlHandler := server.requireControlUser(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		controlCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	controlRequest := requestWithRoute(t, http.MethodGet, "/v1/control/organizations", nil, nil, kernel.Actor{})
	controlRequest.Header.Set("Authorization", "Bearer "+applicationToken)
	controlResponse := httptest.NewRecorder()
	controlHandler.ServeHTTP(controlResponse, controlRequest)
	if controlResponse.Code != http.StatusUnauthorized || controlCalled {
		t.Fatalf("application user token authenticated a control endpoint: status=%d called=%v", controlResponse.Code, controlCalled)
	}

	called := false
	handler := server.requireControlUser(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	request := requestWithRoute(t, "GET", "/v1/applications/"+suffix+"/users", nil, map[string]string{"application_id": suffix}, kernel.Actor{})
	request.AddCookie(&http.Cookie{Name: "p93_control_access", Value: token})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || called {
		t.Fatalf("control_user crossed organization boundary: status=%d called=%v", response.Code, called)
	}

	if _, err = db.Exec(context.Background(), `INSERT INTO organization_memberships(organization_id,control_user_id,role) VALUES($1,$2,'auditor')`, organizationID, controlUserID); err != nil {
		t.Fatal(err)
	}
	request = requestWithRoute(t, "POST", "/v1/applications/"+suffix+"/users", map[string]any{}, map[string]string{"application_id": suffix}, kernel.Actor{})
	request.AddCookie(&http.Cookie{Name: "p93_control_access", Value: token})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("read-only control_user gained write access: status=%d called=%v", response.Code, called)
	}

	if _, err = db.Exec(context.Background(), `UPDATE organization_memberships SET role='admin' WHERE organization_id=$1 AND control_user_id=$2`, organizationID, controlUserID); err != nil {
		t.Fatal(err)
	}
	called = false
	request = requestWithRoute(t, "POST", "/v1/control/applications/"+suffix+"/users", map[string]any{}, map[string]string{"application_id": suffix}, kernel.Actor{})
	request.AddCookie(&http.Cookie{Name: "p93_control_access", Value: token})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("cookie-authenticated write without an Origin was accepted: status=%d called=%v", response.Code, called)
	}

	request = requestWithRoute(t, "POST", "/v1/control/applications/"+suffix+"/users", map[string]any{}, map[string]string{"application_id": suffix}, kernel.Actor{})
	request.Header.Set("Origin", "https://platform93.test")
	request.AddCookie(&http.Cookie{Name: "p93_control_access", Value: token})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("authorized control_user write failed: status=%d called=%v", response.Code, called)
	}
	var method, path string
	if err = db.QueryRow(context.Background(), `SELECT changes->>'method',changes->>'path' FROM audit_records
WHERE actor_id=$1 AND application_id=$2 AND action='http.post' ORDER BY created_at DESC LIMIT 1`, controlUserID, applicationID).Scan(&method, &path); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/v1/control/applications/"+suffix+"/users" {
		t.Fatalf("unexpected audit changes: method=%q path=%q", method, path)
	}
}
