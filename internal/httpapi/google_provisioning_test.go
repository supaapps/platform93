package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

type googleProvisionFixture struct {
	server                   *Server
	app, org, control, token string
}

func newGoogleProvisionFixture(t *testing.T) googleProvisionFixture {
	t.Helper()
	dsn := os.Getenv("PLATFORM93_DATABASE_URL")
	if dsn == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(dsn); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	vault, _ := secure.NewVault(make([]byte, 32))
	s := &Server{app: platform.New(db, vault, "https://platform93.test")}
	f := googleProvisionFixture{server: s, app: kernel.NewID().String(), org: kernel.NewID().String(), control: kernel.NewID().String()}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Provisioning',$2)`, []any{f.org, "provision-" + f.org}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Provisioning',$3)`, []any{f.app, f.org, "provision-" + f.app}},
		{`UPDATE applications SET internal_config=internal_config || '{"registration_mode":"invite_only"}'::jsonb WHERE id=$1`, []any{f.app}},
		{`INSERT INTO control_users(id,email,normalized_email) VALUES($1,$2,$2)`, []any{f.control, f.control + "@example.test"}},
		{`INSERT INTO organization_memberships(organization_id,control_user_id,role) VALUES($1,$2,'admin')`, []any{f.org, f.control}},
	} {
		if _, err := db.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	session := kernel.NewID().String()
	if _, err := db.Exec(t.Context(), `INSERT INTO control_user_sessions(id,control_user_id,refresh_digest,kind,expires_at) VALUES($1,$2,$3,'control',$4)`, session, f.control, vault.Digest(session), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.app.EnsureSigningKey(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.token, err = s.issueControlUserAccess(t.Context(), f.control, session, "control")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f googleProvisionFixture) provision(t *testing.T, body any, key string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/control/applications/"+f.app+"/users/provision-google", strings.NewReader(string(encoded)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.token)
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	New(f.server.app, "").ServeHTTP(w, r)
	return w
}

func newProvisionBody(sub, email string) map[string]any {
	return map[string]any{"google_sub": sub, "reason": "Administrative import", "user": map[string]any{"email": email}}
}

func requireProvisionStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body.String())
	}
}

func TestGoogleProvisioningSilentCreationAndLogin(t *testing.T) {
	f := newGoogleProvisionFixture(t)
	body := newProvisionBody("opaque-google-sub", "Person@Example.test")
	key := kernel.NewID().String()
	w := f.provision(t, body, key)
	requireProvisionStatus(t, w, 201)
	var result provisionGoogleResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.CreatedUser || result.Provider != "google" || result.User.EmailVerified || result.User.IsOrgVerified || result.User.Status != "active" || result.User.Email != "person@example.test" || result.User.Attributes == nil {
		t.Fatalf("unexpected result: %+v", result)
	}
	replay := f.provision(t, body, key)
	requireProvisionStatus(t, replay, 201)
	if replay.Body.String() != w.Body.String() || replay.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("retry did not replay the original result")
	}
	changed := newProvisionBody("different", "different@example.test")
	requireProvisionStatus(t, f.provision(t, changed, key), 409)
	for _, flow := range []string{"automatic", "sign_in"} {
		r := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": f.app}, kernel.Actor{})
		id, err := f.server.completeGoogleIdentity(r, "", flow, nil, "opaque-google-sub", "changed@example.test", "Different", "Name")
		if err != nil || id != result.User.ID {
			t.Fatalf("%s login resolved %s: %v", flow, id, err)
		}
		_, err = f.server.completeGoogleIdentity(r, "", flow, nil, "unrelated-sub", "person@example.test", "", "")
		if err == nil || err.Error() != "account_link_required" {
			t.Fatalf("email unexpectedly claimed: %v", err)
		}
	}
	for _, check := range []struct {
		query string
		want  int
	}{
		{`SELECT count(*) FROM users WHERE application_id=$1`, 1},
		{`SELECT count(*) FROM user_identities WHERE application_id=$1`, 1},
		{`SELECT count(*) FROM notifications WHERE application_id=$1`, 0},
		{`SELECT count(*) FROM application_invitations WHERE application_id=$1`, 0},
		{`SELECT count(*) FROM user_sessions WHERE application_id=$1`, 0},
		{`SELECT count(*) FROM workspaces WHERE application_id=$1`, 0},
		{`SELECT count(*) FROM role_assignments WHERE application_id=$1`, 0},
		{`SELECT count(*) FROM users WHERE application_id=$1 AND password_hash IS NOT NULL`, 0},
		{`SELECT count(*) FROM domain_events WHERE application_id=$1 AND event_type IN ('user.created','user.identity.provisioned')`, 2},
		{`SELECT count(*) FROM audit_records WHERE application_id=$1 AND action='user.identity.provisioned'`, 1},
		{`SELECT count(*) FROM outbox WHERE event_id IN (SELECT id FROM domain_events WHERE application_id=$1)`, 2},
	} {
		var count int
		if err := f.server.app.DB.QueryRow(t.Context(), check.query, f.app).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != check.want {
			t.Fatalf("%s: got %d want %d", check.query, count, check.want)
		}
	}
	var data string
	if err := f.server.app.DB.QueryRow(t.Context(), `SELECT data::text FROM domain_events WHERE application_id=$1 AND event_type='user.identity.provisioned'`, f.app).Scan(&data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(data, "opaque-google-sub") || strings.Contains(data, "@") {
		t.Fatal("event exposed identity data")
	}
}

func TestGoogleProvisioningExistingUsersAndCollisions(t *testing.T) {
	f := newGoogleProvisionFixture(t)
	create := func(email, status string) string {
		t.Helper()
		id := kernel.NewID().String()
		if _, err := f.server.app.DB.Exec(t.Context(), `INSERT INTO users(id,application_id,email,normalized_email,status) VALUES($1,$2,$3,$3,$4)`, id, f.app, email, status); err != nil {
			t.Fatal(err)
		}
		return id
	}
	user := create("existing@example.test", "active")
	body := map[string]any{"google_sub": "existing-sub", "reason": "Link imported identity", "user_id": user}
	for i := 0; i < 2; i++ {
		requireProvisionStatus(t, f.provision(t, body, kernel.NewID().String()), 200)
	}
	if _, err := f.server.app.DB.Exec(t.Context(), `UPDATE users SET first_name='Retained' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	other := create("other@example.test", "active")
	suspended := create("suspended@example.test", "suspended")
	cases := []map[string]any{
		newProvisionBody("new-sub", "existing@example.test"),
		newProvisionBody("existing-sub", "new@example.test"),
		{"google_sub": "existing-sub", "reason": "test", "user_id": other},
		{"google_sub": "different-sub", "reason": "test", "user_id": user},
		{"google_sub": "suspended", "reason": "test", "user_id": suspended},
		{"google_sub": "absent", "reason": "test", "user_id": kernel.NewID().String()},
	}
	for _, body := range cases {
		requireProvisionStatus(t, f.provision(t, body, kernel.NewID().String()), 409)
	}
	foreign := newGoogleProvisionFixture(t)
	foreignUser := kernel.NewID().String()
	if _, err := f.server.app.DB.Exec(t.Context(), `INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'foreign@example.test','foreign@example.test')`, foreignUser, foreign.app); err != nil {
		t.Fatal(err)
	}
	requireProvisionStatus(t, f.provision(t, map[string]any{"google_sub": "foreign", "reason": "test", "user_id": foreignUser}, kernel.NewID().String()), 409)
	requireProvisionStatus(t, foreign.provision(t, newProvisionBody("existing-sub", "existing@example.test"), kernel.NewID().String()), 201)
	var count int
	if err := f.server.app.DB.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE application_id=$1`, f.app).Scan(&count); err != nil || count != 3 {
		t.Fatalf("conflict leaked user: %d %v", count, err)
	}
	var name string
	if err := f.server.app.DB.QueryRow(t.Context(), `SELECT first_name FROM users WHERE id=$1`, user).Scan(&name); err != nil || name != "Retained" {
		t.Fatalf("existing profile changed: %q %v", name, err)
	}
}

func TestGoogleProvisioningValidationAndAuthorization(t *testing.T) {
	f := newGoogleProvisionFixture(t)
	requireProvisionStatus(t, f.provision(t, newProvisionBody("sub", "user@example.test"), ""), 400)
	for _, body := range []any{
		map[string]any{"google_sub": "sub", "reason": "test"},
		map[string]any{"google_sub": "sub", "reason": "test", "user_id": kernel.NewID().String(), "user": map[string]any{"email": "u@example.test"}},
		map[string]any{"google_sub": "sub", "reason": "test", "user_id": "invalid"},
		newProvisionBody("a b", "u@example.test"), newProvisionBody("a\tb", "u@example.test"), newProvisionBody(strings.Repeat("x", 256), "u@example.test"), newProvisionBody("", "u@example.test"),
		newProvisionBody("sub", "invalid"), map[string]any{"google_sub": "sub", "reason": " ", "user": map[string]any{"email": "u@example.test"}},
	} {
		requireProvisionStatus(t, f.provision(t, body, kernel.NewID().String()), 422)
	}
	for _, role := range []string{"auditor", "member"} {
		if _, err := f.server.app.DB.Exec(t.Context(), `UPDATE organization_memberships SET role=$1 WHERE organization_id=$2 AND control_user_id=$3`, role, f.org, f.control); err != nil {
			t.Fatal(err)
		}
		requireProvisionStatus(t, f.provision(t, newProvisionBody("sub", "u@example.test"), kernel.NewID().String()), 403)
	}
	if _, err := f.server.app.DB.Exec(t.Context(), `DELETE FROM organization_memberships WHERE organization_id=$1 AND control_user_id=$2`, f.org, f.control); err != nil {
		t.Fatal(err)
	}
	requireProvisionStatus(t, f.provision(t, newProvisionBody("sub", "u@example.test"), kernel.NewID().String()), 404)
	kid, key, err := f.server.app.ActiveSigningKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"user", "client", "user_api_key"} {
		token, err := identity.Sign(key, kid, identity.Claims{Issuer: f.server.app.Issuer(), Subject: kernel.NewID().String(), Audience: []string{"platform93:application:" + f.app}, ExpiresAt: time.Now().Add(time.Minute).Unix(), ActorType: kind, TokenKind: "access", ApplicationID: f.app, Roles: identity.RoleClaims{Application: []string{}, Workspaces: map[string][]string{}}})
		if err != nil {
			t.Fatal(err)
		}
		copy := f
		copy.token = token
		requireProvisionStatus(t, copy.provision(t, newProvisionBody("sub", "u@example.test"), kernel.NewID().String()), 401)
	}
}

func TestGoogleProvisioningConcurrentAndAtomic(t *testing.T) {
	f := newGoogleProvisionFixture(t)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- f.provision(t, newProvisionBody("concurrent", "u@example.test"), kernel.NewID().String()).Code
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[201] != 1 || counts[409] != 1 {
		t.Fatalf("unexpected concurrent results: %v", counts)
	}
	// Force an event-contract failure after both inserts to prove full rollback.
	if _, err := f.server.app.DB.Exec(t.Context(), `CREATE FUNCTION fail_provision_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.application_id='`+f.app+`'::uuid AND NEW.event_type='user.identity.provisioned' THEN RAISE EXCEPTION 'fixture failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_provision_event BEFORE INSERT ON domain_events FOR EACH ROW EXECUTE FUNCTION fail_provision_event()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.server.app.DB.Exec(context.Background(), `DROP TRIGGER IF EXISTS fail_provision_event ON domain_events; DROP FUNCTION IF EXISTS fail_provision_event()`)
	})
	requireProvisionStatus(t, f.provision(t, newProvisionBody("rollback", "rollback@example.test"), kernel.NewID().String()), 500)
	var count int
	if err := f.server.app.DB.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE application_id=$1`, f.app).Scan(&count); err != nil || count != 1 {
		t.Fatalf("partial user persisted: %d %v", count, err)
	}
	if _, err := f.server.app.DB.Exec(t.Context(), `UPDATE organization_policies SET max_users=1 WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	requireProvisionStatus(t, f.provision(t, newProvisionBody("limited", "limited@example.test"), kernel.NewID().String()), 409)
}
