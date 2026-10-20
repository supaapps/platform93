package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/supaapps/platform93/internal/generated"
	"github.com/supaapps/platform93/internal/identity"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/kernel"
)

type applicationAdministrationFixture struct {
	googleProvisionFixture
	user, target, role, access string
}

func configureInvitationSMTP(t *testing.T, s *Server, app string) {
	t.Helper()
	id := kernel.NewID().String()
	cipher, err := s.app.Vault.Encrypt([]byte(`{"host":"smtp.example.test","port":587,"tls_mode":"starttls"}`), "notification-provider:"+id)
	if err == nil {
		_, err = s.app.DB.Exec(t.Context(), `INSERT INTO notification_providers(id,application_id,name,config_ciphertext,sender_email) VALUES($1,$2,'Test SMTP',$3,'noreply@example.test')`, id, app, cipher)
	}
	if err != nil {
		t.Fatal(err)
	}
}
func invitationAuthenticationCode(t *testing.T, s *Server, app, email string) string {
	t.Helper()
	var id, cipher string
	if err := s.app.DB.QueryRow(t.Context(), `SELECT id,payload_ciphertext FROM notifications WHERE application_id=$1 AND recipient=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, app, email).Scan(&id, &cipher); err != nil {
		t.Fatal(err)
	}
	payload, err := s.app.Vault.Decrypt(cipher, "notification:"+id)
	if err != nil {
		t.Fatal(err)
	}
	var message struct {
		Text string `json:"text"`
	}
	if err = json.Unmarshal(payload, &message); err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`\b[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}\b`).FindString(message.Text)
	if code == "" {
		t.Fatal("Authentication notification has no code")
	}
	return code
}

func newApplicationAdministrationFixture(t *testing.T, permissions []string) applicationAdministrationFixture {
	t.Helper()
	f := applicationAdministrationFixture{googleProvisionFixture: newGoogleProvisionFixture(t), user: kernel.NewID().String(), target: kernel.NewID().String(), role: kernel.NewID().String()}
	db := f.server.app.DB
	for _, id := range []string{f.user, f.target} {
		if _, e := db.Exec(t.Context(), `INSERT INTO users(id,application_id,email,normalized_email,email_verified_at) VALUES($1,$2,$3,$3,now())`, id, f.app, id+"@example.test"); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := db.Exec(t.Context(), `INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,'administrator','Administrator','application',$3)`, f.role, f.app, permissions); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(t.Context(), `INSERT INTO role_assignments(id,application_id,user_id,role_id) VALUES($1,$2,$3,$4)`, kernel.NewID(), f.app, f.user, f.role); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(t.Context(), `UPDATE applications SET internal_config=internal_config||'{"user_invitations_enabled":true}'::jsonb,auth_config='{"flows":{"sign_in_redirect_uri":"https://app.example.test/auth","invitation_redirect_uri":"https://app.example.test/invitations"}}' WHERE id=$1`, f.app); e != nil {
		t.Fatal(e)
	}
	response := httptest.NewRecorder()
	f.server.issueSession(response, requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": f.app}, kernel.Actor{}), f.user, []string{"pwd"})
	var tokens struct {
		Access string `json:"access_token"`
	}
	if e := json.Unmarshal(response.Body.Bytes(), &tokens); e != nil || tokens.Access == "" {
		t.Fatalf("session: %d %s", response.Code, response.Body)
	}
	f.access = tokens.Access
	return f
}
func (f applicationAdministrationFixture) request(t *testing.T, method, path string, body any, token, key, etag string) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "/v1/applications/"+f.app+path, strings.NewReader(string(encoded)))
	r.RemoteAddr = invitationFixtureAddress(f.app)
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	if etag != "" {
		r.Header.Set("If-Match", etag)
	}
	w := httptest.NewRecorder()
	New(f.server.app, "").ServeHTTP(w, r)
	return w
}

func invitationFixtureAddress(app string) string {
	return "[fd00::" + app[24:28] + ":" + app[28:32] + ":" + app[32:36] + "]:10000"
}
func expectAdministrationStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("expected %d, got %d: %s", status, w.Code, w.Body)
	}
}

func TestApplicationAdministrationPermissionsPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"users:read", "users:update", "users:create"})
	expectAdministrationStatus(t, f.request(t, "GET", "/users", nil, f.access, "", ""), 200)
	expectAdministrationStatus(t, f.request(t, "PATCH", "/users/"+f.target, map[string]any{"first_name": "Updated", "reason": "Correct profile"}, f.access, "", `"v1"`), 204)
	expectAdministrationStatus(t, f.request(t, "PATCH", "/users/"+f.target, map[string]any{"is_org_verified": true, "reason": "No privilege"}, f.access, "", `"v2"`), 400)
	expectAdministrationStatus(t, f.request(t, "POST", "/users/"+f.target+"/suspend", map[string]any{"reason": "Missing scope"}, f.access, "suspend-forbidden", `"v2"`), 403)
	expectAdministrationStatus(t, f.request(t, "PATCH", "/users/"+f.target, map[string]any{"first_name": "Stale", "reason": "Conflict"}, f.access, "", `"v1"`), 412)
	expectAdministrationStatus(t, f.request(t, "PATCH", "/users/"+f.target, map[string]any{"first_name": "Missing version", "reason": "Conflict"}, f.access, "", ""), 428)
	create := map[string]any{"email": "silent-" + f.target + "@example.test", "reason": "Create account"}
	first := f.request(t, "POST", "/users", create, f.access, "create-account-key", "")
	expectAdministrationStatus(t, first, 201)
	retry := f.request(t, "POST", "/users", create, f.access, "create-account-key", "")
	expectAdministrationStatus(t, retry, 201)
	if first.Body.String() != retry.Body.String() {
		t.Fatal("creation retry changed identity")
	}
	expectAdministrationStatus(t, f.request(t, "POST", "/users", map[string]any{"email": "sensitive@example.test", "email_verified": true, "reason": "Missing scope"}, f.access, "create-sensitive-key", ""), 403)
	var active bool
	var passwords, sessions, notifications int
	if e := f.server.app.DB.QueryRow(t.Context(), `SELECT (SELECT email_verified_at IS NOT NULL FROM users WHERE application_id=$1 AND normalized_email=$2),(SELECT count(*) FROM users WHERE application_id=$1 AND password_hash IS NOT NULL),(SELECT count(*) FROM user_sessions WHERE application_id=$1 AND user_id<>$3),(SELECT count(*) FROM notifications WHERE application_id=$1)`, f.app, create["email"], f.user).Scan(&active, &passwords, &sessions, &notifications); e != nil || active || passwords+sessions+notifications != 0 {
		t.Fatalf("silent creation side effects: %v %d %d %d %v", active, passwords, sessions, notifications, e)
	}
	if _, e := f.server.app.DB.Exec(t.Context(), `UPDATE roles SET permissions=ARRAY['users:create'] WHERE id=$1`, f.role); e != nil {
		t.Fatal(e)
	}
	expectAdministrationStatus(t, f.request(t, "GET", "/users", nil, f.access, "", ""), 403)
	expectAdministrationStatus(t, f.request(t, "GET", "/users", nil, f.token, "", ""), 401)
	other := newApplicationAdministrationFixture(t, []string{"users:read"})
	expectAdministrationStatus(t, f.request(t, "GET", "/users/"+other.target, nil, f.access, "", ""), 403)
	request := httptest.NewRequest("GET", "/v1/control/applications/"+f.app+"/users", nil)
	request.Header.Set("Authorization", "Bearer "+f.access)
	response := httptest.NewRecorder()
	New(f.server.app, "").ServeHTTP(response, request)
	if response.Code < 400 {
		t.Fatal("application admin reached control plane")
	}
}

func TestApplicationAdministrationRolesAndSensitiveActionsPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"users:*", "roles:read", "roles:assign", "records:read"})
	for i, action := range []string{"verify-email", "verify-organization", "suspend", "restore", "sessions/revoke"} {
		expectAdministrationStatus(t, f.request(t, "POST", "/users/"+f.target+"/"+action, map[string]any{"reason": "Administrative action"}, f.access, "action-key-"+action, kernel.ETag(int64(i+1))), 204)
	}
	low, high := kernel.NewID().String(), kernel.NewID().String()
	for id, p := range map[string]string{low: "records:read", high: "billing:write"} {
		if _, e := f.server.app.DB.Exec(t.Context(), `INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,$3,$3,'application',ARRAY[$4::text])`, id, f.app, "role-"+id, p); e != nil {
			t.Fatal(e)
		}
	}
	denied := f.request(t, "POST", "/role-assignments", map[string]any{"user_id": f.target, "role_id": high, "reason": "Escalation attempt"}, f.access, "high-role-key", `"v6"`)
	expectAdministrationStatus(t, denied, 403)
	allowed := f.request(t, "POST", "/role-assignments", map[string]any{"user_id": f.target, "role_id": low, "reason": "Assign reader"}, f.access, "low-role-key", `"v6"`)
	expectAdministrationStatus(t, allowed, 201)
	var assignment struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(allowed.Body.Bytes(), &assignment)
	expectAdministrationStatus(t, f.request(t, "DELETE", "/role-assignments/"+assignment.ID, map[string]any{"reason": "Remove reader"}, f.access, "", `"v7"`), 204)
	if _, e := f.server.app.DB.Exec(t.Context(), `UPDATE user_sessions SET authenticated_at=now()-interval '11 minutes' WHERE user_id=$1`, f.user); e != nil {
		t.Fatal(e)
	}
	expectAdministrationStatus(t, f.request(t, "PATCH", "/users/"+f.target+"/attributes", map[string]any{"custom_attributes": map[string]any{"tier": "test"}, "reason": "Update attributes"}, f.access, "", `"v8"`), 403)
}

func TestApplicationInvitationsIndependentAuthenticationPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"invitations:manage", "records:read"})
	create := map[string]any{"email": "invited-" + f.target + "@example.test", "send_email": false, "reason": "Onboard colleague"}
	first := f.request(t, "POST", "/invitations", create, f.access, "copy-invitation-key", "")
	expectAdministrationStatus(t, first, 201)
	var result struct {
		ID  string `json:"id"`
		URL string `json:"invitation_url"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &result)
	u, e := url.Parse(result.URL)
	if e != nil || u.Host != "app.example.test" {
		t.Fatalf("invitation destination: %s", result.URL)
	}
	if first.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential caching not disabled")
	}
	replay := f.request(t, "POST", "/invitations", create, f.access, "copy-invitation-key", "")
	expectAdministrationStatus(t, replay, 201)
	if replay.Body.String() != first.Body.String() {
		t.Fatal("idempotent response lost credential")
	}
	var count int
	var raw []byte
	if e = f.server.app.DB.QueryRow(t.Context(), `SELECT count(*) FROM notifications WHERE application_id=$1`, f.app).Scan(&count); e != nil || count != 0 {
		t.Fatal("copy-only invitation queued email", e)
	}
	if e = f.server.app.DB.QueryRow(t.Context(), `SELECT response_body FROM idempotency_records WHERE application_id=$1 AND idempotency_key='copy-invitation-key'`, f.app).Scan(&raw); e != nil || strings.Contains(string(raw), u.Query().Get("link_token")) {
		t.Fatal("credential cached unencrypted", e)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	input := map[string]any{"invitation_id": result.ID, "link_token": u.Query().Get("link_token"), "code_challenge": challenge}
	expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", input, "", "", ""), 401)
	expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", input, f.access, "", ""), 401)
	proof := kernel.NewID().String()
	if _, e = f.server.app.DB.Exec(t.Context(), `INSERT INTO invitation_email_challenges(id,application_id,invitation_id,invitation_version,code_challenge,code_digest,link_digest,expires_at) VALUES($1,$2,$3,1,$4,$5,$6,now()+interval '5 minutes')`, proof, f.app, result.ID, challenge, f.server.app.Vault.Digest("ABCD2345"), f.server.app.Vault.Digest("independent-link")); e != nil {
		t.Fatal(e)
	}
	input["authentication_challenge_id"] = proof
	input["authentication_code"] = "WRONG123"
	expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", input, "", "", ""), 401)
	input["authentication_code"] = "ABCD2345"
	expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", input, "", "", ""), 200)
	expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", input, "", "", ""), 401)
	listing := f.request(t, "GET", "/invitations", nil, f.access, "", "")
	expectAdministrationStatus(t, listing, 200)
	if strings.Contains(listing.Body.String(), u.Query().Get("link_token")) || strings.Contains(listing.Body.String(), "invitation_url") {
		t.Fatal("listing leaked invitation credential")
	}
}

func TestApplicationInvitationRotationAndRevocationPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"invitations:manage", "records:read"})
	config, err := pgxpool.ParseConfig(os.Getenv("PLATFORM93_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	single, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer single.Close()
	f.server.app.DB = single
	create := map[string]any{"email": "rotate-" + f.target + "@example.test", "send_email": false, "reason": "Onboard colleague"}
	first := f.request(t, "POST", "/invitations", create, f.access, "rotation-invite-key", "")
	expectAdministrationStatus(t, first, 201)
	var result struct {
		ID  string `json:"id"`
		URL string `json:"invitation_url"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &result)
	expectAdministrationStatus(t, f.request(t, "GET", "/invitations/"+result.ID, nil, f.access, "", ""), 200)
	expectAdministrationStatus(t, f.request(t, "POST", "/invitations/"+result.ID+"/rotate", map[string]any{"send_email": false, "reason": "Send manually"}, f.access, "rotation-too-soon", `"v1"`), 429)
	if _, err = single.Exec(t.Context(), `UPDATE application_invitations SET resend_available_at=now()-interval '1 second' WHERE id=$1`, result.ID); err != nil {
		t.Fatal(err)
	}
	configureInvitationSMTP(t, f.server, f.app)
	u, _ := url.Parse(result.URL)
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	credential := map[string]any{"invitation_id": result.ID, "link_token": u.Query().Get("link_token"), "code_challenge": challenge}
	proof := f.request(t, "POST", "/auth/invitations/email/start", credential, "", "", "")
	expectAdministrationStatus(t, proof, 202)
	var authentication struct {
		ID string `json:"challenge_id"`
	}
	_ = json.Unmarshal(proof.Body.Bytes(), &authentication)
	rotated := f.request(t, "POST", "/invitations/"+result.ID+"/rotate", map[string]any{"send_email": true, "reason": "Resend invitation"}, f.access, "rotation-send-key", `"v1"`)
	expectAdministrationStatus(t, rotated, 202)
	expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", credential, "", "", ""), 401)
	var remaining int
	if err = single.QueryRow(t.Context(), `SELECT count(*) FROM invitation_email_challenges WHERE id=$1`, authentication.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("old authentication challenge survived", err)
	}
	if _, err = single.Exec(t.Context(), `UPDATE applications SET internal_config=internal_config||'{"user_invitations_enabled":false}'::jsonb WHERE id=$1`, f.app); err != nil {
		t.Fatal(err)
	}
	expectAdministrationStatus(t, f.request(t, "POST", "/invitations", create, f.access, "disabled-invitation-key", ""), 403)
	expectAdministrationStatus(t, f.request(t, "GET", "/invitations/"+result.ID, nil, f.access, "", ""), 200)
	expectAdministrationStatus(t, f.request(t, "DELETE", "/invitations/"+result.ID, map[string]any{"reason": "Withdraw invitation"}, f.access, "", `"v2"`), 204)
}

func TestApplicationAdministrationIsolationAndAtomicityPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"users:*", "roles:*", "invitations:manage"})
	foreign := newApplicationAdministrationFixture(t, []string{"users:read"})
	expectAdministrationStatus(t, f.request(t, "GET", "/users/"+foreign.target, nil, f.access, "", ""), 404)
	expectAdministrationStatus(t, f.request(t, "PATCH", "/users/"+foreign.target, map[string]any{"first_name": "Foreign", "reason": "Forbidden"}, f.access, "", `"v1"`), 404)
	client := kernel.NewID().String()
	externalID := "machine-" + client
	if _, err := f.server.app.DB.Exec(t.Context(), `INSERT INTO clients(id,application_id,client_id,name,client_type) VALUES($1,$2,$3,'Administration test','machine');`, client, f.app, externalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.server.app.DB.Exec(t.Context(), `INSERT INTO role_assignments(id,application_id,client_id,role_id) VALUES($1,$2,$3,$4)`, kernel.NewID(), f.app, client, f.role); err != nil {
		t.Fatal(err)
	}
	kid, key, err := f.server.app.ActiveSigningKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := f.server.app.Now()
	machine, err := identity.Sign(key, kid, identity.Claims{Issuer: f.server.app.Issuer(), Subject: externalID, ClientID: externalID, ApplicationID: f.app, Audience: []string{"platform93:application:" + f.app}, ActorType: "client", TokenKind: "machine", Scope: "/applications/" + f.app + "/users/create", Roles: emptyRoleClaims(), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), JWTID: kernel.NewID().String()})
	if err != nil {
		t.Fatal(err)
	}
	expectAdministrationStatus(t, f.request(t, "POST", "/users", map[string]any{"email": "machine-created-" + f.target + "@example.test", "reason": "Machine onboarding"}, machine, "machine-create-key", ""), 201)
	expectAdministrationStatus(t, f.request(t, "POST", "/users/"+f.target+"/suspend", map[string]any{"reason": "Token ceiling"}, machine, "machine-suspend-key", `"v1"`), 403)
	name := "reject_admin_" + strings.ReplaceAll(f.target, "-", "")
	if _, err = f.server.app.DB.Exec(t.Context(), `CREATE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.application_id='`+f.app+`' THEN RAISE EXCEPTION 'test audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER `+name+` BEFORE INSERT ON audit_records FOR EACH ROW EXECUTE FUNCTION `+name+`()`); err != nil {
		t.Fatal(err)
	}
	defer f.server.app.DB.Exec(context.Background(), `DROP TRIGGER `+name+` ON audit_records; DROP FUNCTION `+name+`()`)
	expectAdministrationStatus(t, f.request(t, "PATCH", "/users/"+f.target, map[string]any{"first_name": "Must roll back", "reason": "Atomicity regression"}, f.access, "", `"v1"`), 409)
	var firstName string
	var version int64
	if err = f.server.app.DB.QueryRow(t.Context(), `SELECT first_name,version FROM users WHERE application_id=$1 AND id=$2`, f.app, f.target).Scan(&firstName, &version); err != nil || firstName != "" || version != 1 {
		t.Fatal("audit failure partially committed user", firstName, version, err)
	}
}

func TestApplicationInvitationGoogleIdentityBoundaryPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"invitations:manage"})
	provider := externalAuthProviderConfig{Provider: "google"}
	create := func(email string) string {
		t.Helper()
		id := kernel.NewID().String()
		if _, err := f.server.app.DB.Exec(t.Context(), `INSERT INTO application_invitations(id,application_id,normalized_email,link_credential_digest,onboarding_method,inviter_type,inviter_id,expires_at) VALUES($1,$2,$3,$4,'google','user',$5,now()+interval '1 day')`, id, f.app, email, f.server.app.Vault.Digest(id), f.user); err != nil {
			t.Fatal(err)
		}
		return id
	}
	request := requestWithRoute(t, "GET", "/", nil, map[string]string{"application_id": f.app}, kernel.Actor{})
	email := "google-invited-" + f.target + "@example.test"
	id := create(email)
	if _, err := f.server.completeApplicationInvitationExternalIdentity(request, id, provider, externalProviderIdentity{Subject: "google-sub-" + id, Email: "wrong@example.test", TrustedEmail: true}); err == nil {
		t.Fatal("wrong Google email accepted")
	}
	if _, err := f.server.completeApplicationInvitationExternalIdentity(request, id, provider, externalProviderIdentity{Subject: "google-sub-" + id, Email: email, TrustedEmail: false}); err == nil {
		t.Fatal("unverified Google email accepted")
	}
	user, err := f.server.completeApplicationInvitationExternalIdentity(request, id, provider, externalProviderIdentity{Subject: "google-sub-" + id, Email: email, TrustedEmail: true})
	if err != nil {
		t.Fatal(err)
	}
	if again, e := f.server.completeExternalIdentity(request, "google", "", "automatic", nil, "google-sub-"+id, email, "", ""); e != nil || again != user {
		t.Fatal("repeat Google login changed UUID", e)
	}
	existing := create(f.target + "@example.test")
	if _, err = f.server.completeApplicationInvitationExternalIdentity(request, existing, provider, externalProviderIdentity{Subject: "unlinked-google-" + existing, Email: f.target + "@example.test", TrustedEmail: true}); err == nil || err.Error() != "identity_link_required" {
		t.Fatal("matching email silently claimed existing account", err)
	}
	var events, notifications int
	if err = f.server.app.DB.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM domain_events WHERE application_id=$1 AND event_type='user.created'),(SELECT count(*) FROM notifications WHERE application_id=$1)`, f.app).Scan(&events, &notifications); err != nil || events != 1 || notifications != 0 {
		t.Fatal("Google invitation lifecycle side effects", events, notifications, err)
	}
	unsafe := create("untrusted-" + f.target + "@example.test")
	if _, err = f.server.app.DB.Exec(t.Context(), `UPDATE application_invitations SET onboarding_method='facebook' WHERE id=$1`, unsafe); err != nil {
		t.Fatal(err)
	}
	if _, err = f.server.completeApplicationInvitationExternalIdentity(request, unsafe, externalAuthProviderConfig{Provider: "facebook"}, externalProviderIdentity{Subject: "attacker-owned-subject", Email: "attacker@example.test", TrustedEmail: false}); err == nil {
		t.Fatal("untrusted provider email claimed the invited account")
	}
}

func validateAdministrationResponse(t *testing.T, w *httptest.ResponseRecorder, path, method, status string) {
	t.Helper()
	spec, err := generated.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	response := spec.Paths.Value(path).GetOperation(method).Responses.Value(status)
	var value any
	if err = json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if err = response.Value.Content["application/json"].Schema.Value.VisitJSON(value); err != nil {
		t.Fatal("response violates public contract", err)
	}
}

func TestApplicationAdministrationResponseContractsPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"users:read", "users:sessions:read", "roles:read", "invitations:manage"})
	for _, item := range []struct{ url, path string }{{"/users", "/v1/applications/{application_id}/users"}, {"/users/" + f.user, "/v1/applications/{application_id}/users/{user_id}"}, {"/users/" + f.user + "/sessions", "/v1/applications/{application_id}/users/{user_id}/sessions"}, {"/roles", "/v1/applications/{application_id}/roles"}, {"/role-assignments?user_id=" + f.user, "/v1/applications/{application_id}/role-assignments"}} {
		response := f.request(t, "GET", item.url, nil, f.access, "", "")
		expectAdministrationStatus(t, response, 200)
		validateAdministrationResponse(t, response, item.path, "GET", "200")
	}
}

func TestApplicationInvitationWorkspaceOwnerPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"records:read"})
	workspace := kernel.NewID().String()
	role := kernel.NewID().String()
	if _, err := f.server.app.DB.Exec(t.Context(), `INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'new-workspace','New workspace')`, workspace, f.app, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.server.app.DB.Exec(t.Context(), `INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,'reader','Reader','workspace',ARRAY['records:read'])`, role, f.app); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"email": "member-" + workspace + "@example.test", "workspace_role_keys": []string{"reader"}, "send_email": false, "reason": "Invite a workspace member"}
	expectAdministrationStatus(t, f.request(t, "POST", "/workspaces/"+workspace+"/invitations", body, f.access, "stale-owner-invitation-key", ""), 403)
	response := httptest.NewRecorder()
	f.server.issueSession(response, requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": f.app}, kernel.Actor{}), f.user, []string{"pwd"})
	var refreshed struct {
		Access string `json:"access_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &refreshed); err != nil || refreshed.Access == "" {
		t.Fatalf("refresh owner scopes: %d %s", response.Code, response.Body)
	}
	f.access = refreshed.Access
	expectAdministrationStatus(t, f.request(t, "POST", "/workspaces/"+workspace+"/invitations", body, f.access, "owner-invitation-key", ""), 201)
	expectAdministrationStatus(t, f.request(t, "GET", "/workspaces/"+workspace+"/invitations", nil, f.access, "", ""), 200)
	expectAdministrationStatus(t, f.request(t, "GET", "/users", nil, f.access, "", ""), 403)
	body["workspace_id"] = kernel.NewID().String()
	expectAdministrationStatus(t, f.request(t, "POST", "/workspaces/"+workspace+"/invitations", body, f.access, "foreign-workspace-key", ""), 422)
}

func TestApplicationAdministrationIdempotencyEncryptionPostgres(t *testing.T) {
	f := newApplicationAdministrationFixture(t, []string{"users:read"})
	for _, cacheControl := range []string{"", "private, no-store"} {
		t.Run(cacheControl, func(t *testing.T) {
			key := "encryption-key-" + kernel.NewID().String()
			handler := f.server.idempotent(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", cacheControl)
				kernel.WriteJSON(w, 201, map[string]any{"value": "private-result"})
			}))
			invoke := func() *httptest.ResponseRecorder {
				r := requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": f.app}, kernel.Actor{Type: "user", ID: f.user})
				r.Header.Set("Idempotency-Key", key)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			first, replay := invoke(), invoke()
			expectAdministrationStatus(t, first, 201)
			expectAdministrationStatus(t, replay, 201)
			if first.Body.String() != replay.Body.String() || replay.Header().Get("Idempotent-Replayed") != "true" {
				t.Fatal("encrypted receipt did not replay")
			}
			var stored []byte
			if err := f.server.app.DB.QueryRow(t.Context(), `SELECT response_body FROM idempotency_records WHERE application_id=$1 AND idempotency_key=$2`, f.app, key).Scan(&stored); err != nil || !strings.HasPrefix(string(stored), "p93_encrypted:") || strings.Contains(string(stored), "private-result") {
				t.Fatalf("response was not encrypted: %v", err)
			}
		})
	}
}

func TestApplicationInvitationPreRegisteredAccountPostgres(t *testing.T) {
	for _, credential := range []string{"password", "identity", "mfa", "personal_key", "none", "verified"} {
		t.Run(credential, func(t *testing.T) {
			f := newApplicationAdministrationFixture(t, []string{"invitations:manage"})
			db := f.server.app.DB
			if credential != "verified" {
				if _, err := db.Exec(t.Context(), `UPDATE users SET email_verified_at=NULL WHERE id=$1`, f.target); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			switch credential {
			case "password", "verified":
				_, err = db.Exec(t.Context(), `UPDATE users SET password_hash='preexisting-test-hash' WHERE id=$1`, f.target)
			case "identity":
				_, err = db.Exec(t.Context(), `INSERT INTO user_identities(application_id,user_id,provider,provider_subject) VALUES($1,$2,'google',$3)`, f.app, f.target, kernel.NewID().String())
			case "mfa":
				_, err = db.Exec(t.Context(), `INSERT INTO user_authentication_methods(application_id,user_id,method_type) VALUES($1,$2,'totp')`, f.app, f.target)
			case "personal_key":
				_, err = db.Exec(t.Context(), `INSERT INTO personal_api_keys(application_id,user_id,token_prefix,token_digest,expires_at) VALUES($1,$2,'test',$3,now()+interval '1 day')`, f.app, f.target, f.server.app.Vault.Digest(f.target))
			}
			if err != nil {
				t.Fatal(err)
			}
			created := f.request(t, "POST", "/invitations", map[string]any{"email": f.target + "@example.test", "send_email": false, "reason": "Onboard recipient"}, f.access, "pre-registered-invitation", "")
			expectAdministrationStatus(t, created, 201)
			var invitation struct {
				ID  string `json:"id"`
				URL string `json:"invitation_url"`
			}
			if err = json.Unmarshal(created.Body.Bytes(), &invitation); err != nil {
				t.Fatal(err)
			}
			uri, _ := url.Parse(invitation.URL)
			sum := sha256.Sum256([]byte("abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"))
			challenge := base64.RawURLEncoding.EncodeToString(sum[:])
			proof := kernel.NewID().String()
			if _, err = db.Exec(t.Context(), `INSERT INTO invitation_email_challenges(id,application_id,invitation_id,invitation_version,code_challenge,code_digest,link_digest,expires_at) VALUES($1,$2,$3,1,$4,$5,$6,now()+interval '5 minutes')`, proof, f.app, invitation.ID, challenge, f.server.app.Vault.Digest("ABCD2345"), f.server.app.Vault.Digest("independent-proof")); err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"invitation_id": invitation.ID, "link_token": uri.Query().Get("link_token"), "code_challenge": challenge, "authentication_challenge_id": proof, "authentication_code": "ABCD2345"}
			if credential == "none" || credential == "verified" {
				expectAdministrationStatus(t, f.request(t, "POST", "/auth/invitations/exchange", input, "", "", ""), 200)
				return
			}
			for attempt := 0; attempt < 2; attempt++ {
				response := f.request(t, "POST", "/auth/invitations/exchange", input, "", "", "")
				expectAdministrationStatus(t, response, 409)
				if !strings.Contains(response.Body.String(), "invited_account_review_required") {
					t.Fatal(response.Body.String())
				}
				var untouched bool
				if err = db.QueryRow(t.Context(), `SELECT i.accepted_at IS NULL AND c.consumed_at IS NULL FROM application_invitations i JOIN invitation_email_challenges c ON c.invitation_id=i.id WHERE i.id=$1`, invitation.ID).Scan(&untouched); err != nil || !untouched {
					t.Fatal("failed acceptance consumed credentials", err)
				}
				if _, err = db.Exec(t.Context(), `UPDATE users SET email_verified_at=now() WHERE id=$1`, f.target); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
