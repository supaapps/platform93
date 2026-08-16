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

func TestAcceptOrganizationInvitationIncludesNewMembershipInAccessToken(t *testing.T) {
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

	inviterID, organizationID, invitationID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := invitationID.String()
	credential := "p93_org_invite_" + suffix
	if _, err = db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email) VALUES($1,$2,$2)`, inviterID, "inviter-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Invitation test',$2)`, organizationID, "invitation-"+suffix); err != nil {
		t.Fatal(err)
	}
	notificationTx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	queueRequest := requestWithRoute(t, http.MethodPost, "/", nil, nil, kernel.Actor{Type: "control_user", ID: inviterID.String()})
	if err = server.queueOrganizationInvitation(queueRequest, notificationTx, organizationID.String(), invitationID.String(), "invitee-"+suffix+"@example.test", "admin", "email", credential, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = notificationTx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	var queuedOrganizationID string
	if err = db.QueryRow(context.Background(), `SELECT organization_id FROM notifications WHERE payload_ciphertext IS NOT NULL AND recipient=$1 ORDER BY created_at DESC LIMIT 1`, "invitee-"+suffix+"@example.test").Scan(&queuedOrganizationID); err != nil || queuedOrganizationID != organizationID.String() {
		t.Fatalf("organization invitation notification lost its provider scope: organization=%q err=%v", queuedOrganizationID, err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO control_user_invitations(id,organization_id,normalized_email,role,credential_digest,invited_by,expires_at)
VALUES($1,$2,$3,'admin',$4,$5,$6)`, invitationID, organizationID, "invitee-"+suffix+"@example.test", vault.Digest(credential), inviterID, time.Now().Add(time.Hour)); err != nil {
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

	request := requestWithRoute(t, http.MethodPost, "/v1/control/organization-invitations/accept", map[string]any{
		"invitation_token": credential,
		"display_name":     "Invited control_user",
	}, nil, kernel.Actor{})
	response := httptest.NewRecorder()
	server.acceptOrganizationInvitation(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("invitation acceptance failed: %d %s", response.Code, response.Body.String())
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	claims, err := identity.Verify(payload.AccessToken, func(kid string) (*rsa.PublicKey, error) {
		return server.app.ResolvePublicKey(context.Background(), kid)
	}, server.app.Issuer(), server.app.ControlAudience(), server.app.Now())
	if err != nil {
		t.Fatal(err)
	}
	wantedScope := "/control/organizations/" + organizationID.String() + "/*"
	if !strings.Contains(" "+claims.Scope+" ", " "+wantedScope+" ") {
		t.Fatalf("new membership missing from access token scope: %q", claims.Scope)
	}
}
