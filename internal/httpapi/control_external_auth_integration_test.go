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
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestControlExternalInvitationAndLoginLifecycle(t *testing.T) {
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
	if _, err = db.Exec(context.Background(), `INSERT INTO installations(id,setup_completed_at)
SELECT $1,now() WHERE NOT EXISTS(SELECT 1 FROM installations)`, kernel.NewID()); err != nil {
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

	for _, provider := range []string{"google", "apple"} {
		t.Run(provider, func(t *testing.T) {
			inviterID, providerID, invitationID, challengeID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
			var acceptedControlUserID string
			providerCreated := false
			challengeIDs := []string{challengeID.String()}
			suffix := challengeID.String()
			email := provider + "-invite-" + suffix + "@example.test"
			if _, insertErr := db.Exec(context.Background(), `INSERT INTO control_users(id,email,normalized_email,display_name)
VALUES($1,$2,$2,'External auth inviter')`, inviterID, "inviter-"+suffix+"@example.test"); insertErr != nil {
				t.Fatal(insertErr)
			}
			var existingProviderID string
			providerErr := db.QueryRow(context.Background(), `SELECT id FROM auth_provider_configs
WHERE provider=$1 AND application_id IS NULL AND organization_id IS NULL`, provider).Scan(&existingProviderID)
			if providerErr == nil {
				if parseErr := providerID.Scan(existingProviderID); parseErr != nil {
					t.Fatal(parseErr)
				}
			} else {
				ciphertext, encryptErr := vault.Encrypt([]byte(`{}`), "auth-provider:"+providerID.String())
				if encryptErr != nil {
					t.Fatal(encryptErr)
				}
				if _, insertErr := db.Exec(context.Background(), `INSERT INTO auth_provider_configs
(id,provider,client_id,config_ciphertext,control_login_enabled) VALUES($1,$2,$3,$4,true)`,
					providerID, provider, provider+"-client-"+suffix, ciphertext); insertErr != nil {
					t.Fatal(insertErr)
				}
				providerCreated = true
			}
			t.Cleanup(func() {
				_, _ = db.Exec(context.Background(), `DELETE FROM control_user_external_auth_challenges WHERE id=ANY($1::uuid[])`, challengeIDs)
				if acceptedControlUserID != "" {
					_, _ = db.Exec(context.Background(), `DELETE FROM control_user_sessions WHERE control_user_id=$1`, acceptedControlUserID)
					_, _ = db.Exec(context.Background(), `DELETE FROM installation_control_user_roles WHERE control_user_id=$1`, acceptedControlUserID)
					_, _ = db.Exec(context.Background(), `DELETE FROM control_user_identities WHERE control_user_id=$1`, acceptedControlUserID)
				}
				_, _ = db.Exec(context.Background(), `DELETE FROM control_user_invitations WHERE id=$1`, invitationID)
				if acceptedControlUserID != "" {
					_, _ = db.Exec(context.Background(), `DELETE FROM control_users WHERE id=$1`, acceptedControlUserID)
				}
				_, _ = db.Exec(context.Background(), `DELETE FROM control_users WHERE id=$1`, inviterID)
				if providerCreated {
					_, _ = db.Exec(context.Background(), `DELETE FROM auth_provider_configs WHERE id=$1`, providerID)
				}
			})
			if _, insertErr := db.Exec(context.Background(), `INSERT INTO control_user_invitations
(id,normalized_email,role,onboarding_method,credential_digest,invited_by,expires_at)
VALUES($1,$2,'auditor',$3,$4,$5,now()+interval '1 hour')`, invitationID, email, provider, vault.Digest("invite-"+suffix), inviterID); insertErr != nil {
				t.Fatal(insertErr)
			}
			insertControlExternalChallenge(t, server, challengeID, providerID, provider, "invitation", invitationID.String(), "")

			request := requestWithRoute(t, http.MethodGet, "/v1/auth/providers/"+provider+"/callback", nil, nil, kernel.Actor{})
			response := httptest.NewRecorder()
			config := externalAuthProviderConfig{ID: providerID.String(), Provider: provider}
			external := controlExternalIdentity{Subject: "subject-" + suffix, Email: email, FirstName: "External", LastName: "User"}
			if err = server.completeControlExternalSignIn(response, request, challengeID.String(), "invitation", invitationID.String(), config, external); err != nil {
				t.Fatalf("%s invitation acceptance failed: %v", provider, err)
			}
			if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Set-Cookie"), "p93_control_access=") {
				t.Fatalf("%s invitation did not establish a control session: %d %s", provider, response.Code, response.Header().Get("Set-Cookie"))
			}

			var controlUserID, role, method string
			var acceptedAt, consumedAt *time.Time
			if err = db.QueryRow(context.Background(), `SELECT accepted_by,role,onboarding_method,accepted_at
FROM control_user_invitations WHERE id=$1`, invitationID).Scan(&controlUserID, &role, &method, &acceptedAt); err != nil {
				t.Fatal(err)
			}
			if role != "auditor" || method != provider || acceptedAt == nil {
				t.Fatalf("unexpected accepted invitation state: role=%q method=%q accepted=%v", role, method, acceptedAt)
			}
			acceptedControlUserID = controlUserID
			if err = db.QueryRow(context.Background(), `SELECT consumed_at FROM control_user_external_auth_challenges WHERE id=$1`, challengeID).Scan(&consumedAt); err != nil || consumedAt == nil {
				t.Fatalf("external challenge was not consumed: %v", err)
			}
			var identityCount, sessionCount int
			if err = db.QueryRow(context.Background(), `SELECT count(*) FROM control_user_identities
WHERE control_user_id=$1 AND auth_provider_config_id=$2 AND provider_subject=$3`, controlUserID, providerID, external.Subject).Scan(&identityCount); err != nil || identityCount != 1 {
				t.Fatalf("external identity count=%d err=%v", identityCount, err)
			}
			if err = db.QueryRow(context.Background(), `SELECT count(*) FROM control_user_sessions
WHERE control_user_id=$1 AND $2=ANY(amr) AND revoked_at IS NULL`, controlUserID, provider).Scan(&sessionCount); err != nil || sessionCount != 1 {
				t.Fatalf("provider session count=%d err=%v", sessionCount, err)
			}

			replayID := kernel.NewID()
			challengeIDs = append(challengeIDs, replayID.String())
			insertControlExternalChallenge(t, server, replayID, providerID, provider, "invitation", invitationID.String(), "")
			if replayErr := server.completeControlExternalSignIn(httptest.NewRecorder(), request, replayID.String(), "invitation", invitationID.String(), config, external); replayErr == nil {
				t.Fatal("accepted external invitation was replayed")
			}

			loginID := kernel.NewID()
			challengeIDs = append(challengeIDs, loginID.String())
			insertControlExternalChallenge(t, server, loginID, providerID, provider, "login", "", "")
			loginResponse := httptest.NewRecorder()
			if loginErr := server.completeControlExternalSignIn(loginResponse, request, loginID.String(), "login", "", config, external); loginErr != nil {
				t.Fatalf("linked %s login failed: %v", provider, loginErr)
			}
			if err = db.QueryRow(context.Background(), `SELECT count(*) FROM control_user_sessions
WHERE control_user_id=$1 AND $2=ANY(amr) AND revoked_at IS NULL`, controlUserID, provider).Scan(&sessionCount); err != nil || sessionCount != 2 {
				t.Fatalf("linked provider login session count=%d err=%v", sessionCount, err)
			}
		})
	}
}

func insertControlExternalChallenge(t *testing.T, server *Server, challengeID, providerID interface{ String() string }, provider, flow, invitationID, controlUserID string) {
	t.Helper()
	verifier, err := server.app.Vault.Encrypt([]byte("test-verifier"), "control-external-auth:"+challengeID.String())
	if err != nil {
		t.Fatal(err)
	}
	var invitation, requestedBy any
	if invitationID != "" {
		invitation = invitationID
	}
	if controlUserID != "" {
		requestedBy = controlUserID
	}
	if _, err = server.app.DB.Exec(context.Background(), `INSERT INTO control_user_external_auth_challenges
(id,auth_provider_config_id,provider,flow,requested_by_control_user_id,invitation_id,state_digest,nonce_digest,verifier_ciphertext,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '10 minutes')`, challengeID.String(), providerID.String(), provider, flow,
		requestedBy, invitation, server.app.Vault.Digest("state-"+challengeID.String()), server.app.Vault.Digest("nonce"), verifier); err != nil {
		t.Fatal(err)
	}
}
