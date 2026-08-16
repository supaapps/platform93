package httpapi

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestControlUserAccountPasswordLifecycle(t *testing.T) {
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
	app := platform.New(db, vault, "https://platform93.test")
	server := &Server{app: app}
	controlUserID, sessionID := kernel.NewID(), kernel.NewID()
	email := "control_user-" + controlUserID.String() + "@example.test"
	refresh := "p93_control_refresh_" + controlUserID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO installations(id,setup_completed_at)
SELECT $1,now() WHERE NOT EXISTS(SELECT 1 FROM installations)`, kernel.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email,display_name) VALUES($1,$2,$2,'Test ControlUser')`, controlUserID, email); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,'owner')`, controlUserID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_user_sessions(id,control_user_id,refresh_digest,kind,expires_at) VALUES($1,$2,$3,'control',$4)`, sessionID, controlUserID, vault.Digest(refresh), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = app.EnsureSigningKey(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	current := kernel.Actor{Type: "control_user", ID: controlUserID.String(), SessionID: sessionID.String()}

	accountRequest := requestWithRoute(t, http.MethodGet, "/", nil, nil, current)
	accountResponse := httptest.NewRecorder()
	server.getControlUserAccount(accountResponse, accountRequest)
	if accountResponse.Code != http.StatusOK || !strings.Contains(accountResponse.Body.String(), `"password":false`) || !strings.Contains(accountResponse.Body.String(), email) {
		t.Fatalf("unexpected control_user account response: %d %s", accountResponse.Code, accountResponse.Body.String())
	}

	addRequest := requestWithRoute(t, http.MethodPut, "/", map[string]any{"new_password": "correct horse battery staple"}, nil, current)
	addResponse := httptest.NewRecorder()
	server.changeControlUserPassword(addResponse, addRequest)
	if addResponse.Code != http.StatusNoContent {
		t.Fatalf("first control_user password was not added: %d %s", addResponse.Code, addResponse.Body.String())
	}
	var passwordHash string
	if err = db.QueryRow(context.Background(), `SELECT password_hash FROM control_users WHERE id=$1`, controlUserID).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if !identity.VerifyPassword(passwordHash, "correct horse battery staple") {
		t.Fatal("control_user password was not stored as a valid Argon2id hash")
	}

	loginRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{"email": email, "password": "correct horse battery staple"}, nil, kernel.Actor{})
	loginResponse := httptest.NewRecorder()
	server.controlUserPasswordLogin(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK || !strings.Contains(loginResponse.Header().Get("Set-Cookie"), "p93_control_access=") {
		t.Fatalf("control_user password login failed: %d %s", loginResponse.Code, loginResponse.Body.String())
	}

	wrongRequest := requestWithRoute(t, http.MethodPut, "/", map[string]any{"current_password": "incorrect password value", "new_password": "another correct horse battery"}, nil, current)
	wrongResponse := httptest.NewRecorder()
	server.changeControlUserPassword(wrongResponse, wrongRequest)
	if wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("incorrect current password was accepted: %d %s", wrongResponse.Code, wrongResponse.Body.String())
	}

	changeRequest := requestWithRoute(t, http.MethodPut, "/", map[string]any{"current_password": "correct horse battery staple", "new_password": "another correct horse battery"}, nil, current)
	changeResponse := httptest.NewRecorder()
	server.changeControlUserPassword(changeResponse, changeRequest)
	if changeResponse.Code != http.StatusNoContent {
		t.Fatalf("control_user password change failed: %d %s", changeResponse.Code, changeResponse.Body.String())
	}
	var activeSessions int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM control_user_sessions WHERE control_user_id=$1 AND revoked_at IS NULL`, controlUserID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if activeSessions != 1 {
		t.Fatalf("expected only the current session after password change, got %d", activeSessions)
	}
}

func TestControlUserEmailVerificationIssuesAMRFromUncommittedSession(t *testing.T) {
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
	app := platform.New(db, vault, "https://platform93.test")
	server := &Server{app: app}
	controlUserID, challengeID := kernel.NewID(), kernel.NewID()
	email := "email-amr-" + controlUserID.String() + "@example.test"
	code := "A1B2C3D4"
	if _, err = db.Exec(context.Background(), `INSERT INTO installations(id,setup_completed_at)
SELECT $1,now() WHERE NOT EXISTS(SELECT 1 FROM installations)`, kernel.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `UPDATE installations SET control_email_code_enabled=true`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email,display_name) VALUES($1,$2,$2,'Email AMR')`, controlUserID, email); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,'auditor')`, controlUserID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_user_login_challenges(id,normalized_email,code_digest,expires_at)
VALUES($1,$2,$3,now()+interval '10 minutes')`, challengeID, email, vault.Digest(code)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = app.EnsureSigningKey(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	request := requestWithRoute(t, http.MethodPost, "/v1/control/auth/email/verify", map[string]any{
		"challenge_id": challengeID.String(), "code": code,
	}, nil, kernel.Actor{})
	response := httptest.NewRecorder()
	server.controlUserEmailVerify(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("email verification failed: %d %s", response.Code, response.Body.String())
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(response.Body.Bytes(), &payload) != nil || payload.AccessToken == "" {
		t.Fatal("email verification did not return an access token")
	}
	claims, err := identity.Verify(payload.AccessToken, func(kid string) (*rsa.PublicKey, error) {
		return app.ResolvePublicKey(context.Background(), kid)
	}, app.Issuer(), app.ControlAudience(), app.Now())
	if err != nil || len(claims.AMR) != 1 || claims.AMR[0] != "email_code" {
		t.Fatalf("unexpected email verification claims: %#v err=%v", claims, err)
	}
}

func TestControlAuthPolicyPreventsInstallationOwnerLockout(t *testing.T) {
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
	controlUserID := kernel.NewID()
	email := "lockout-owner-" + controlUserID.String() + "@example.test"
	if _, err = db.Exec(context.Background(), `INSERT INTO installations(id,setup_completed_at)
SELECT $1,now() WHERE NOT EXISTS(SELECT 1 FROM installations)`, kernel.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email) VALUES($1,$2,$2)`, controlUserID, email); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,'owner')`, controlUserID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM installation_control_user_roles WHERE control_user_id=$1`, controlUserID)
		_, _ = db.Exec(context.Background(), `DELETE FROM control_users WHERE id=$1`, controlUserID)
	}()

	request := requestWithRoute(t, http.MethodPatch, "/v1/control/installation/auth-policy", map[string]any{
		"email_code_enabled": false, "magic_link_enabled": false, "password_enabled": false,
	}, nil, kernel.Actor{Type: "control_user", ID: controlUserID.String()})
	response := httptest.NewRecorder()
	server.updateControlAuthPolicy(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "control_auth_owner_lockout") {
		t.Fatalf("owner lockout was not rejected: %d %s", response.Code, response.Body.String())
	}
}
