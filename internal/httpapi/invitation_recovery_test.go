package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/kernel"
)

func TestApplicationInvitationCredentialRecoveryPostgres(t *testing.T) {
	for _, rejectAudit := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery", true: "rollback"}[rejectAudit], func(t *testing.T) {
			f := newApplicationAdministrationFixture(t, []string{"invitations:manage"})
			db := f.server.app.DB
			for _, query := range []string{
				`UPDATE users SET password_hash='old-test-hash',email_verified_at=NULL,first_name='Recipient' WHERE application_id=$1 AND id=$2`,
				`INSERT INTO user_identities(application_id,user_id,provider,provider_subject) VALUES($1,$2,'google',$2::uuid::text)`,
				`INSERT INTO user_authentication_methods(application_id,user_id,method_type,status,secret_ciphertext) VALUES($1,$2,'totp','active','old-test-secret')`,
				`INSERT INTO personal_api_keys(application_id,user_id,token_prefix,token_digest,expires_at) VALUES($1,$2,'test',convert_to($2::uuid::text,'UTF8'),now()+interval '1 day')`,
				`INSERT INTO user_recovery_codes(application_id,user_id,code_digest) VALUES($1,$2,convert_to($2::uuid::text,'UTF8'))`,
				`INSERT INTO mfa_login_challenges(application_id,user_id,primary_amr,expires_at) VALUES($1,$2,ARRAY['pwd'],now()+interval '5 minutes')`,
				`INSERT INTO webauthn_ceremonies(application_id,user_id,intent,origin,session_ciphertext,expires_at) VALUES($1,$2,'register','https://app.example.test','old-test-ceremony',now()+interval '5 minutes')`,
				`INSERT INTO login_challenges(application_id,requested_by_user_id,normalized_email,intent,expires_at) VALUES($1,$2,'other@example.test','change_email',now()+interval '5 minutes')`,
				`INSERT INTO external_auth_challenges(application_id,requested_by_user_id,provider,flow,app_redirect_uri,state_digest,nonce_digest,verifier_ciphertext,expires_at) VALUES($1,$2,'google','link','https://app.example.test/auth',convert_to($2::uuid::text,'UTF8'),convert_to($2::uuid::text,'UTF8'),'old-test-verifier',now()+interval '5 minutes')`,
				`INSERT INTO external_auth_exchanges(application_id,user_id,credential_digest,expires_at) VALUES($1,$2,convert_to($2::uuid::text,'UTF8'),now()+interval '5 minutes')`,
				`INSERT INTO invitation_authorization_codes(application_id,user_id,code_digest,code_challenge,expires_at) VALUES($1,$2,convert_to($2::uuid::text,'UTF8'),repeat('a',43),now()+interval '5 minutes')`,
				`INSERT INTO oauth_sessions(application_id,signature_digest,kind,request_id,request_payload,expires_at) VALUES($1,convert_to($2::text,'UTF8'),'refresh',$2::text,jsonb_build_object('session',jsonb_build_object('subject',$2::text)),now()+interval '1 day')`,
			} {
				if _, err := db.Exec(t.Context(), query, f.app, f.target); err != nil {
					t.Fatalf("seed %s: %v", query, err)
				}
			}
			var pendingLink string
			if err := db.QueryRow(t.Context(), `SELECT id FROM external_auth_challenges WHERE application_id=$1 AND requested_by_user_id=$2 AND flow='link'`, f.app, f.target).Scan(&pendingLink); err != nil {
				t.Fatal(err)
			}
			oldSession := httptest.NewRecorder()
			f.server.issueSession(oldSession, requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": f.app}, kernel.Actor{}), f.target, []string{"pwd"})
			var old struct {
				Access string `json:"access_token"`
			}
			if err := json.Unmarshal(oldSession.Body.Bytes(), &old); err != nil || old.Access == "" {
				t.Fatal("old session missing", err)
			}
			created := f.request(t, "POST", "/invitations", map[string]any{"email": f.target + "@example.test", "send_email": false, "reason": "Onboard recipient"}, f.access, "recover-invitation", "")
			expectAdministrationStatus(t, created, 201)
			var invitation struct {
				ID  string `json:"id"`
				URL string `json:"invitation_url"`
			}
			if err := json.Unmarshal(created.Body.Bytes(), &invitation); err != nil {
				t.Fatal(err)
			}
			uri, _ := url.Parse(invitation.URL)
			verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"
			sum := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(sum[:])
			proof := kernel.NewID().String()
			if _, err := db.Exec(t.Context(), `INSERT INTO invitation_email_challenges(id,application_id,invitation_id,invitation_version,code_challenge,code_digest,link_digest,expires_at) VALUES($1,$2,$3,1,$4,$5,$6,now()+interval '5 minutes')`, proof, f.app, invitation.ID, challenge, f.server.app.Vault.Digest("ABCD2345"), f.server.app.Vault.Digest("independent-mailbox-link")); err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"invitation_id": invitation.ID, "link_token": uri.Query().Get("link_token"), "code_challenge": challenge}
			// Even a later verified bearer cannot authorize credential recovery.
			if _, err := db.Exec(t.Context(), `UPDATE users SET email_verified_at=now() WHERE id=$1`, f.target); err != nil {
				t.Fatal(err)
			}
			expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", input, old.Access, "", ""), 401)
			input["authentication_challenge_id"] = proof
			input["authentication_link_token"] = "independent-mailbox-link"
			if rejectAudit {
				name := "reject_recovery_" + strings.ReplaceAll(f.target, "-", "")
				if _, err := db.Exec(t.Context(), `CREATE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.application_id='`+f.app+`' AND NEW.action='user.credentials_recovered' THEN RAISE EXCEPTION 'test recovery audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER `+name+` BEFORE INSERT ON audit_records FOR EACH ROW EXECUTE FUNCTION `+name+`()`); err != nil {
					t.Fatal(err)
				}
				defer db.Exec(context.Background(), `DROP TRIGGER `+name+` ON audit_records; DROP FUNCTION `+name+`()`) // Test-local fixture only.
				expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", input, "", "", ""), 503)
				var intact bool
				if err := db.QueryRow(t.Context(), `SELECT u.password_hash='old-test-hash' AND i.accepted_at IS NULL AND c.consumed_at IS NULL AND EXISTS(SELECT 1 FROM user_identities WHERE user_id=u.id) AND EXISTS(SELECT 1 FROM user_sessions WHERE user_id=u.id AND revoked_at IS NULL) FROM users u JOIN application_invitations i ON i.id=$2 JOIN invitation_email_challenges c ON c.id=$3 WHERE u.id=$1`, f.target, invitation.ID, proof).Scan(&intact); err != nil || !intact {
					t.Fatal("recovery failure partially committed", err)
				}
				return
			}
			accepted := f.request(t, "POST", "/auth/invitations/exchange", input, "", "", "")
			expectAdministrationStatus(t, accepted, 200)
			expectAdministrationStatus(t, f.request(t, "GET", "/me", nil, old.Access, "", ""), 401)
			providerRequest := requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": f.app}, kernel.Actor{})
			if _, err := f.server.completeExternalIdentity(providerRequest, "google", pendingLink, "link", &f.target, "new-test-subject", f.target+"@example.test", "", ""); err == nil {
				t.Fatal("pending provider link resurrected credentials after recovery")
			}
			if _, err := f.server.completeExternalIdentity(providerRequest, "google", "", "automatic", nil, f.target, f.target+"@example.test", "", ""); err == nil || err.Error() != "account_link_required" {
				t.Fatal("unbound provider sign-in reclaimed recovered account by email", err)
			}
			callback := httptest.NewRecorder()
			f.server.completeExternalAuthCallback(callback, providerRequest, pendingLink, "https://app.example.test/auth", f.target)
			location, _ := url.Parse(callback.Header().Get("Location"))
			if location.Query().Get("external_auth_error") != "exchange_creation_failed" {
				t.Fatal("pending callback issued a new exchange after recovery", callback.Header().Get("Location"))
			}
			var remaining int
			if err := db.QueryRow(t.Context(), `SELECT
 (SELECT count(*) FROM user_sessions WHERE user_id=$1 AND revoked_at IS NULL)+
 (SELECT count(*) FROM oauth_sessions WHERE application_id=$2 AND request_payload->'session'->>'subject'=$1::text AND active)+
 (SELECT count(*) FROM user_identities WHERE user_id=$1)+
 (SELECT count(*) FROM personal_api_keys WHERE user_id=$1 AND revoked_at IS NULL)+
 (SELECT count(*) FROM user_authentication_methods WHERE user_id=$1 AND (status<>'disabled' OR secret_ciphertext IS NOT NULL))+
 (SELECT count(*) FROM user_recovery_codes WHERE user_id=$1)+
 (SELECT count(*) FROM mfa_login_challenges WHERE user_id=$1 AND consumed_at IS NULL)+
 (SELECT count(*) FROM webauthn_ceremonies WHERE user_id=$1 AND consumed_at IS NULL)+
 (SELECT count(*) FROM login_challenges WHERE requested_by_user_id=$1 AND consumed_at IS NULL)+
 (SELECT count(*) FROM external_auth_challenges WHERE requested_by_user_id=$1 AND consumed_at IS NULL)+
 (SELECT count(*) FROM external_auth_exchanges WHERE user_id=$1 AND consumed_at IS NULL)+
 (SELECT count(*) FROM invitation_authorization_codes WHERE user_id=$1 AND used_at IS NULL AND expires_at>now())`, f.target, f.app).Scan(&remaining); err != nil || remaining != 1 {
				t.Fatal("old credentials survived (only the new invitation code should remain)", remaining, err)
			}
			var code struct {
				Code string `json:"authorization_code"`
			}
			if err := json.Unmarshal(accepted.Body.Bytes(), &code); err != nil {
				t.Fatal(err)
			}
			redeemed := f.request(t, "POST", "/auth/invitations/token", map[string]any{"authorization_code": code.Code, "code_verifier": verifier}, "", "", "")
			expectAdministrationStatus(t, redeemed, 200)
			var tokens struct {
				Access string `json:"access_token"`
			}
			if err := json.Unmarshal(redeemed.Body.Bytes(), &tokens); err != nil || tokens.Access == "" {
				t.Fatal("new recipient session missing", err)
			}
			expectAdministrationStatus(t, f.request(t, "GET", "/me", nil, tokens.Access, "", ""), 200)
			expectAdministrationStatus(t, f.request(t, "GET", "/me", nil, f.access, "", ""), 200)
			var preserved bool
			if err := db.QueryRow(t.Context(), `SELECT first_name='Recipient' AND password_hash IS NULL AND email_verified_at IS NOT NULL FROM users WHERE id=$1`, f.target).Scan(&preserved); err != nil || !preserved {
				t.Fatal("recovery changed identity/profile", err)
			}
		})
	}
}

func TestApplicationInvitationRecoveryLoginRacePostgres(t *testing.T) {
	for _, flow := range []string{"session", "mfa", "credential"} {
		t.Run(flow, func(t *testing.T) {
			f := newApplicationAdministrationFixture(t, []string{"invitations:manage"})
			current := kernel.Actor{}
			if flow == "credential" {
				issued := httptest.NewRecorder()
				f.server.issueSession(issued, requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": f.app}, kernel.Actor{}), f.target, []string{"pwd"})
				expectAdministrationStatus(t, issued, 200)
				current = kernel.Actor{Type: "user", ID: f.target, ApplicationID: f.app}
				if err := f.server.app.DB.QueryRow(t.Context(), `SELECT id FROM user_sessions WHERE application_id=$1 AND user_id=$2 AND revoked_at IS NULL`, f.app, f.target).Scan(&current.SessionID); err != nil {
					t.Fatal(err)
				}
			}
			if flow == "mfa" {
				if _, err := f.server.app.DB.Exec(t.Context(), `INSERT INTO user_authentication_methods(application_id,user_id,method_type,status) VALUES($1,$2,'totp','active')`, f.app, f.target); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := f.server.app.DB.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			var pid int
			if err = tx.QueryRow(t.Context(), `SELECT pg_backend_pid() FROM users WHERE application_id=$1 AND id=$2 FOR UPDATE`, f.app, f.target).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			r := withAuthenticationEpoch(requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": f.app}, current), 0)
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if flow == "credential" {
					err := f.server.storeExternalAuthChallenge(r, f.target, `INSERT INTO external_auth_challenges(application_id,requested_by_user_id,provider,flow,app_redirect_uri,state_digest,nonce_digest,verifier_ciphertext,expires_at) VALUES($1,$2,'google','link','https://app.example.test',convert_to($2::uuid::text,'UTF8'),convert_to($2::uuid::text,'UTF8'),'test',now()+interval '5 minutes')`, f.app, f.target)
					if !credentialSessionProblem(response, r, err) {
						response.WriteHeader(500)
					}
				} else if flow == "session" {
					f.server.issueSession(response, r, f.target, []string{"pwd"})
				} else {
					f.server.completePrimaryAuthentication(response, r, f.target, []string{"pwd"})
				}
			}()
			deadline := time.Now().Add(10 * time.Second)
			blocked := false
			for time.Now().Before(deadline) {
				if err = f.server.app.DB.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case <-done:
					t.Fatalf("authentication did not serialize with recovery: %d %s", response.Code, response.Body)
				default:
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("authentication did not reach recovery lock")
			}
			if err = f.server.recoverInvitationCredentials(r, tx, f.target, kernel.NewID().String()); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("authentication failed to finish after recovery")
			}
			expectAdministrationStatus(t, response, 401)
			var count int
			if err = f.server.app.DB.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM user_sessions WHERE application_id=$1 AND user_id=$2 AND revoked_at IS NULL)+(SELECT count(*) FROM mfa_login_challenges WHERE application_id=$1 AND user_id=$2 AND consumed_at IS NULL)+(SELECT count(*) FROM external_auth_challenges WHERE application_id=$1 AND requested_by_user_id=$2 AND consumed_at IS NULL)`, f.app, f.target).Scan(&count); err != nil || count != 0 {
				t.Fatal("stale authentication survived recovery", count, err)
			}
			fresh := httptest.NewRecorder()
			f.server.issueSession(fresh, withAuthenticationEpoch(r, 1), f.target, []string{"email"})
			expectAdministrationStatus(t, fresh, 200)
		})
	}
}

func TestCredentialMutationRequiresDirectSession(t *testing.T) {
	for _, current := range []kernel.Actor{{Type: "user_api_key", ID: "subject", SessionID: "key"}, {Type: "user", ID: "subject", SessionID: "session", DelegatedBy: "control"}, {Type: "client", ID: "subject"}} {
		r := requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": "app"}, current)
		w := httptest.NewRecorder()
		s := &Server{}
		if !credentialSessionProblem(w, r, s.lockCredentialMutation(r, nil, "subject")) {
			t.Fatal("non-session credential accepted")
		}
		expectAdministrationStatus(t, w, 403)
		if !strings.Contains(w.Body.String(), "direct_authentication_required") {
			t.Fatal(w.Body.String())
		}
	}
}
