package httpapi

import (
	"context"
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

func TestOperatorAccountPasswordLifecycle(t *testing.T) {
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
	operatorID, sessionID := kernel.NewID(), kernel.NewID()
	email := "operator-" + operatorID.String() + "@example.test"
	refresh := "p93_ops_refresh_" + operatorID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO operators(id,email,normalized_email,display_name) VALUES($1,$2,$2,'Test Operator')`, operatorID, email); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO installation_operator_roles(operator_id,role) VALUES($1,'owner')`, operatorID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO operator_sessions(id,operator_id,refresh_digest,kind,expires_at) VALUES($1,$2,$3,'operator',$4)`, sessionID, operatorID, vault.Digest(refresh), time.Now().Add(time.Hour)); err != nil {
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
	current := kernel.Actor{Type: "operator", ID: operatorID.String(), SessionID: sessionID.String()}

	accountRequest := requestWithRoute(t, http.MethodGet, "/", nil, nil, current)
	accountResponse := httptest.NewRecorder()
	server.getOperatorAccount(accountResponse, accountRequest)
	if accountResponse.Code != http.StatusOK || !strings.Contains(accountResponse.Body.String(), `"password":false`) || !strings.Contains(accountResponse.Body.String(), email) {
		t.Fatalf("unexpected operator account response: %d %s", accountResponse.Code, accountResponse.Body.String())
	}

	addRequest := requestWithRoute(t, http.MethodPut, "/", map[string]any{"new_password": "correct horse battery staple"}, nil, current)
	addResponse := httptest.NewRecorder()
	server.changeOperatorPassword(addResponse, addRequest)
	if addResponse.Code != http.StatusNoContent {
		t.Fatalf("first operator password was not added: %d %s", addResponse.Code, addResponse.Body.String())
	}
	var passwordHash string
	if err = db.QueryRow(context.Background(), `SELECT password_hash FROM operators WHERE id=$1`, operatorID).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if !identity.VerifyPassword(passwordHash, "correct horse battery staple") {
		t.Fatal("operator password was not stored as a valid Argon2id hash")
	}

	loginRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{"email": email, "password": "correct horse battery staple"}, nil, kernel.Actor{})
	loginResponse := httptest.NewRecorder()
	server.operatorPasswordLogin(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK || !strings.Contains(loginResponse.Header().Get("Set-Cookie"), "p93_operator_access=") {
		t.Fatalf("operator password login failed: %d %s", loginResponse.Code, loginResponse.Body.String())
	}

	wrongRequest := requestWithRoute(t, http.MethodPut, "/", map[string]any{"current_password": "incorrect password value", "new_password": "another correct horse battery"}, nil, current)
	wrongResponse := httptest.NewRecorder()
	server.changeOperatorPassword(wrongResponse, wrongRequest)
	if wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("incorrect current password was accepted: %d %s", wrongResponse.Code, wrongResponse.Body.String())
	}

	changeRequest := requestWithRoute(t, http.MethodPut, "/", map[string]any{"current_password": "correct horse battery staple", "new_password": "another correct horse battery"}, nil, current)
	changeResponse := httptest.NewRecorder()
	server.changeOperatorPassword(changeResponse, changeRequest)
	if changeResponse.Code != http.StatusNoContent {
		t.Fatalf("operator password change failed: %d %s", changeResponse.Code, changeResponse.Body.String())
	}
	var activeSessions int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM operator_sessions WHERE operator_id=$1 AND revoked_at IS NULL`, operatorID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if activeSessions != 1 {
		t.Fatalf("expected only the current session after password change, got %d", activeSessions)
	}
}
