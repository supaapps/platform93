package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestApplicationInvitationRotationAcceptanceAndPKCEReplay(t *testing.T) {
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
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app := platform.New(db, vault, "https://platform93.test")
	server := &Server{app: app}
	organizationID, applicationID, controlUserID, roleID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email,display_name)
VALUES($1,$2,$2,'Invitation administrator')`, controlUserID, "inviter-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Invitation lifecycle',$2)`, organizationID, "invite-lifecycle-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug,auth_config)
VALUES($1,$2,'Invitation application',$3,$4)`, applicationID, organizationID, "invite-app-"+suffix,
		`{"flows":{"oauth_client_id":"web","sign_in_redirect_uri":"https://app.example/auth/callback","invitation_redirect_uri":"https://app.example/invitations/accept"}}`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO roles(id,application_id,key,name,scope,permissions)
VALUES($1,$2,'reader','Reader','application',ARRAY['records:read'])`, roleID, applicationID); err != nil {
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
	current := kernel.Actor{Type: "control_user", ID: controlUserID.String()}
	email := "rotated-" + suffix + "@example.test"
	createRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"email": email, "application_role_keys": []string{"reader"},
	}, map[string]string{"application_id": applicationID.String()}, current)
	createResponse := httptest.NewRecorder()
	server.createControlInvitation(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("invitation creation failed: %d %s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(createResponse.Body.Bytes(), &created) != nil || created.ID == "" {
		t.Fatal("invitation creation did not return an id")
	}
	var oldLinkDigest, oldCodeDigest []byte
	if err = db.QueryRow(context.Background(), `SELECT link_credential_digest,code_credential_digest
FROM application_invitations WHERE id=$1`, created.ID).Scan(&oldLinkDigest, &oldCodeDigest); err != nil {
		t.Fatal(err)
	}
	cooldownRequest := requestWithRoute(t, http.MethodPost, "/", nil, map[string]string{
		"application_id": applicationID.String(), "invitation_id": created.ID,
	}, current)
	cooldownResponse := httptest.NewRecorder()
	server.resendInvitation(cooldownResponse, cooldownRequest)
	if cooldownResponse.Code != http.StatusTooManyRequests || cooldownResponse.Header().Get("Retry-After") == "" {
		t.Fatalf("resend cooldown was not enforced: %d %s", cooldownResponse.Code, cooldownResponse.Body.String())
	}
	if _, err = db.Exec(context.Background(), `UPDATE application_invitations SET resend_available_at=now()-interval '1 second' WHERE id=$1`, created.ID); err != nil {
		t.Fatal(err)
	}
	resendResponse := httptest.NewRecorder()
	server.resendInvitation(resendResponse, cooldownRequest)
	if resendResponse.Code != http.StatusAccepted {
		t.Fatalf("eligible invitation resend failed: %d %s", resendResponse.Code, resendResponse.Body.String())
	}
	var newLinkDigest, newCodeDigest []byte
	if err = db.QueryRow(context.Background(), `SELECT link_credential_digest,code_credential_digest
FROM application_invitations WHERE id=$1`, created.ID).Scan(&newLinkDigest, &newCodeDigest); err != nil {
		t.Fatal(err)
	}
	if equalBytes(oldLinkDigest, newLinkDigest) || equalBytes(oldCodeDigest, newCodeDigest) {
		t.Fatal("resend did not rotate both invitation credentials")
	}

	code, linkToken := "ABCD2345", "p93_invite_known_"+suffix
	acceptanceID := kernel.NewID()
	acceptedEmail := "accepted-" + suffix + "@example.test"
	if _, err = db.Exec(context.Background(), `INSERT INTO application_invitations
(id,application_id,normalized_email,link_credential_digest,code_credential_digest,application_roles,workspace_roles,expires_at,inviter_type,inviter_id,last_sent_at,resend_available_at)
VALUES($1,$2,$3,$4,$5,ARRAY['reader'],'{}',now()+interval '1 hour','control_user',$6,now(),now()+interval '1 minute')`,
		acceptanceID, applicationID, acceptedEmail, vault.Digest(linkToken), vault.Digest(code), controlUserID); err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	responses := make([]*httptest.ResponseRecorder, 2)
	var wait sync.WaitGroup
	for index := range responses {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := requestWithRoute(t, http.MethodPost, "/", map[string]any{
				"invitation_id": acceptanceID.String(), "link_token": linkToken, "code_challenge": challenge,
			}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
			responses[index] = httptest.NewRecorder()
			server.exchangeInvitation(responses[index], request)
		}(index)
	}
	wait.Wait()
	successes := 0
	var authorizationCode string
	for _, response := range responses {
		if response.Code == http.StatusOK {
			successes++
			var payload struct {
				AuthorizationCode string `json:"authorization_code"`
			}
			if json.Unmarshal(response.Body.Bytes(), &payload) == nil {
				authorizationCode = payload.AuthorizationCode
			}
		} else if response.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected concurrent acceptance result: %d %s", response.Code, response.Body.String())
		}
	}
	if successes != 1 || authorizationCode == "" {
		t.Fatalf("expected exactly one successful invitation acceptance, got %d", successes)
	}
	var userID string
	if err = db.QueryRow(context.Background(), `SELECT id FROM users WHERE application_id=$1 AND normalized_email=$2`, applicationID, acceptedEmail).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	var assignmentCount int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM role_assignments
WHERE application_id=$1 AND user_id=$2 AND role_id=$3`, applicationID, userID, roleID).Scan(&assignmentCount); err != nil || assignmentCount != 1 {
		t.Fatalf("invitation role assignment count=%d err=%v", assignmentCount, err)
	}
	redeemRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"authorization_code": authorizationCode, "code_verifier": verifier,
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	redeemResponse := httptest.NewRecorder()
	server.redeemInvitationAuthorizationCode(redeemResponse, redeemRequest)
	if redeemResponse.Code != http.StatusOK {
		t.Fatalf("PKCE redemption failed: %d %s", redeemResponse.Code, redeemResponse.Body.String())
	}
	replayResponse := httptest.NewRecorder()
	replayRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"authorization_code": authorizationCode, "code_verifier": verifier,
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	server.redeemInvitationAuthorizationCode(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("invitation authorization code replay was accepted: %d %s", replayResponse.Code, replayResponse.Body.String())
	}

	if _, err = db.Exec(context.Background(), `UPDATE application_invitations SET expires_at=now()-interval '1 second' WHERE id=$1`, created.ID); err != nil {
		t.Fatal(err)
	}
	expiredRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"email": email, "code": "ABCDEFGH", "code_challenge": challenge,
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	expiredResponse := httptest.NewRecorder()
	server.exchangeInvitation(expiredResponse, expiredRequest)
	if expiredResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expired invitation was accepted: %d %s", expiredResponse.Code, expiredResponse.Body.String())
	}

	revokeRequest := requestWithRoute(t, http.MethodDelete, "/", nil, map[string]string{
		"application_id": applicationID.String(), "invitation_id": created.ID,
	}, current)
	revokeResponse := httptest.NewRecorder()
	server.revokeInvitation(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("invitation revocation failed: %d %s", revokeResponse.Code, revokeResponse.Body.String())
	}
}
