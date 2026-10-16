package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/oauthserver"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

type oauthSecurityFixture struct {
	t                                               *testing.T
	app                                             *platform.App
	router                                          http.Handler
	application, user, session, client, controlUser string
}

func newOAuthSecurityFixture(t *testing.T) *oauthSecurityFixture {
	t.Helper()
	dsn := os.Getenv("PLATFORM93_DATABASE_URL")
	if dsn == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "p93_oauth_" + strings.ReplaceAll(kernel.NewID().String(), "-", "")
	if _, err = admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, `DROP DATABASE `+name+` WITH (FORCE)`); admin.Close() })
	config, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Path = "/" + name
	if err = database.Migrate(config.String()); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(ctx, config.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app := platform.New(db, vault, "https://platform93.test")
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = app.EnsureSigningKey(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f := &oauthSecurityFixture{t: t, app: app, application: kernel.NewID().String(), user: kernel.NewID().String(), session: kernel.NewID().String(), client: kernel.NewID().String(), controlUser: kernel.NewID().String()}
	org, role := kernel.NewID().String(), kernel.NewID().String()
	f.exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'OAuth tests',$1::uuid::text)`, org)
	f.exec(`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'OAuth tests',$1::uuid::text)`, f.application, org)
	f.exec(`INSERT INTO users(id,application_id,email,normalized_email,email_verified_at) VALUES($1,$2,'user@example.test','user@example.test',now())`, f.user, f.application)
	f.exec(`INSERT INTO control_users(id,email,normalized_email) VALUES($1,'control@example.test','control@example.test')`, f.controlUser)
	f.exec(`INSERT INTO user_sessions(id,application_id,user_id,refresh_digest,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 day')`, f.session, f.application, f.user, vault.Digest("test-session"))
	f.exec(`INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,'billing','Billing','application',ARRAY['billing:read','billing:write'])`, role, f.application)
	f.exec(`INSERT INTO role_assignments(id,application_id,role_id,user_id) VALUES($1,$2,$3,$4)`, kernel.NewID(), f.application, role, f.user)
	f.exec(`INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes,secret_digest,pkce_required)
VALUES($1,$2,$1::uuid::text,'OAuth test','confidential',ARRAY['https://client.example.test/callback'],ARRAY['authorization_code','refresh_token'],
ARRAY['openid','email','profile','offline_access',$4,$5,$6],$3,false)`, f.client, f.application, vault.Digest("fixture-secret"), f.scope("billing/read"), f.scope("billing/write"), f.scope("roles/billing"))
	f.router = New(app, "")
	return f
}

func (f *oauthSecurityFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.app.DB.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *oauthSecurityFixture) scope(permission string) string {
	return "/applications/" + f.application + "/" + permission
}

func (f *oauthSecurityFixture) call(method, target string, form url.Values, bearer, ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	r.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func (f *oauthSecurityFixture) accessToken(delegated bool) string {
	f.t.Helper()
	kid, key, err := f.app.ActiveSigningKey(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	now := time.Now()
	claims := identity.Claims{Issuer: f.app.Issuer(), Subject: f.user, Audience: []string{"platform93:application:" + f.application}, ApplicationID: f.application, SessionID: f.session, ActorType: "user", TokenKind: "access", Scope: f.scope("billing/read"), Roles: emptyRoleClaims(), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), JWTID: kernel.NewID().String()}
	if delegated {
		delegation := kernel.NewID().String()
		f.exec(`INSERT INTO delegations(id,application_id,control_user_id,user_id,reason,redirect_uri,permissions,exchange_digest,expires_at,exchanged_at) VALUES($1,$2,$3,$4,'Test','https://client.example.test/callback',ARRAY[$5],$6,now()+interval '5 minutes',now())`, delegation, f.application, f.controlUser, f.user, f.scope("billing/read"), f.app.Vault.Digest("fixture-delegation"))
		f.exec(`UPDATE user_sessions SET delegation_id=$1 WHERE id=$2`, delegation, f.session)
		claims.Actor = &identity.Actor{Subject: f.controlUser, Type: "control_user"}
	}
	token, err := identity.Sign(key, kid, claims)
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

func (f *oauthSecurityFixture) authorize(bearer string) *httptest.ResponseRecorder {
	return f.call("POST", "/oidc/authorize", url.Values{"client_id": {f.client}, "response_type": {"code"}, "redirect_uri": {"https://client.example.test/callback"}, "scope": {"openid email profile offline_access"}, "state": {"fixture-state-with-enough-entropy"}, "decision": {"approve"}}, bearer, "192.0.2.1")
}

func (f *oauthSecurityFixture) tokenBody(code string) url.Values {
	return url.Values{"client_id": {f.client}, "client_secret": {"fixture-secret"}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example.test/callback"}}
}

func (f *oauthSecurityFixture) code() string {
	f.t.Helper()
	w := f.authorize(f.accessToken(false))
	if w.Code != 200 {
		f.t.Fatalf("authorize status %d: %s", w.Code, w.Body.String())
	}
	v := decodeTestResponse(f.t, w)
	u, err := url.Parse(v["redirect_to"].(string))
	if err != nil || u.Query().Get("code") == "" {
		f.t.Fatal("missing authorization code")
	}
	return u.Query().Get("code")
}

func (f *oauthSecurityFixture) tokens() map[string]any {
	f.t.Helper()
	w := f.call("POST", "/oidc/token", f.tokenBody(f.code()), "", "192.0.2.1")
	if w.Code != 200 {
		f.t.Fatalf("token status %d: %s", w.Code, w.Body.String())
	}
	return decodeTestResponse(f.t, w)
}

func (f *oauthSecurityFixture) refreshBody(token string) url.Values {
	return url.Values{"client_id": {f.client}, "client_secret": {"fixture-secret"}, "grant_type": {"refresh_token"}, "refresh_token": {token}}
}

func decodeTestResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	return v
}

func TestOAuthTokenSecurity(t *testing.T) {
	if os.Getenv("PLATFORM93_DATABASE_URL") == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	t.Run("delegated sessions cannot create OAuth grants", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		w := f.authorize(f.accessToken(true))
		if w.Code == 200 {
			u, _ := url.Parse(decodeTestResponse(t, w)["redirect_to"].(string))
			exchange := f.call("POST", "/oidc/token", f.tokenBody(u.Query().Get("code")), "", "192.0.2.1")
			if exchange.Code == 200 {
				claims := jwt.MapClaims{}
				_, _, _ = jwt.NewParser().ParseUnverified(decodeTestResponse(t, exchange)["access_token"].(string), claims)
				t.Logf("delegation exchange scope=%v actor=%v", claims["scope"], claims["act"])
			}
			t.Fatal("delegated session created a renewable OAuth grant")
		}
		if w.Code != http.StatusSeeOther && w.Code != http.StatusFound && w.Code != http.StatusForbidden {
			t.Fatalf("unexpected refusal status %d", w.Code)
		}
		location, _ := url.Parse(w.Header().Get("Location"))
		if location.Query().Get("error") != "access_denied" || location.Query().Get("code") != "" {
			t.Fatal("delegation did not return a safe OAuth refusal")
		}
		var count int
		if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM oauth_sessions`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("delegation persisted OAuth credentials: count=%d err=%v", count, err)
		}
	})
	t.Run("revoked session cannot refresh", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		tokens := f.tokens()
		f.exec(`UPDATE user_sessions SET revoked_at=now() WHERE id=$1`, f.session)
		w := f.call("POST", "/oidc/token", f.refreshBody(tokens["refresh_token"].(string)), "", "192.0.2.1")
		if w.Code != 400 || decodeTestResponse(t, w)["error"] != "invalid_grant" {
			t.Fatalf("revoked session refreshed: status %d", w.Code)
		}
	})
	t.Run("concurrent refresh has one winner", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		tokens := f.tokens()
		body := f.refreshBody(tokens["refresh_token"].(string))
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		lock, err := f.app.DB.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(context.Background())
		if _, err = lock.Exec(ctx, `SELECT id FROM oauth_sessions WHERE kind='refresh' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		results := make(chan *httptest.ResponseRecorder, 2)
		request := func() { results <- f.call("POST", "/oidc/token", body, "", "192.0.2.1") }
		waitBlocked := func(want int) {
			t.Helper()
			for {
				var n int
				if err := f.app.DB.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%oauth_sessions%'`).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n >= want {
					return
				}
				select {
				case <-ctx.Done():
					t.Fatal("refresh requests did not reach the storage barrier")
				case <-time.After(10 * time.Millisecond):
				}
			}
		}
		go request()
		waitBlocked(1)
		// Separate JWT timestamps so the old non-atomic store cannot accidentally
		// reject a request only because identical JWT signatures collide.
		time.Sleep(1100 * time.Millisecond)
		go request()
		waitBlocked(2)
		if err = lock.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		successes := 0
		for i := 0; i < 2; i++ {
			select {
			case w := <-results:
				if w.Code == 200 {
					successes++
				} else if w.Code != 400 {
					t.Errorf("refresh status %d", w.Code)
				}
			case <-ctx.Done():
				t.Fatal("refresh did not finish")
			}
		}
		if successes != 1 {
			t.Fatalf("same refresh credential succeeded %d times, want exactly one", successes)
		}
		var active int
		if err := f.app.DB.QueryRow(ctx, `SELECT count(*) FROM oauth_sessions WHERE kind='refresh' AND active`).Scan(&active); err != nil || active != 1 {
			t.Fatalf("unexpected persisted successors: count=%d err=%v", active, err)
		}
	})
	t.Run("invalid secrets cannot exhaust another callers client capacity", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		f.exec(`UPDATE clients SET client_type='machine',pkce_required=true,allowed_grants=ARRAY['client_credentials'] WHERE id=$1`, f.client)
		body := url.Values{"client_id": {f.client}, "client_secret": {"wrong-secret"}, "grant_type": {"client_credentials"}}
		limited := false
		for i := 0; i < 40; i++ {
			w := f.call("POST", "/oidc/token", body, "", "192.0.2.99")
			if w.Code == 429 {
				limited = true
				if w.Header().Get("Retry-After") == "" {
					t.Fatal("rate limit missing retry delay")
				}
			} else if w.Code != 401 && w.Code != 400 {
				t.Fatalf("invalid secret status %d", w.Code)
			}
		}
		if !limited {
			t.Fatal("invalid credential abuse was not bounded")
		}
		body.Set("client_secret", "fixture-secret")
		w := f.call("POST", "/oidc/token", body, "", "192.0.2.1")
		if w.Code != 200 {
			t.Fatalf("legitimate client locked out by another caller: status %d", w.Code)
		}
		// A reverse proxy or shared NAT must not turn invalid requests into a
		// successful-issuance lockout for every caller behind that address.
		w = f.call("POST", "/oidc/token", body, "", "192.0.2.99")
		if w.Code != 200 {
			t.Fatalf("valid caller behind the same proxy was locked out: status %d", w.Code)
		}
	})
	t.Run("public PKCE exchange survives invalid requests behind the same proxy", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		f.exec(`UPDATE clients SET client_type='public',pkce_required=true,secret_digest=NULL WHERE id=$1`, f.client)
		verifier := strings.Repeat("v", 64)
		digest := sha256.Sum256([]byte(verifier))
		form := url.Values{"client_id": {f.client}, "response_type": {"code"}, "redirect_uri": {"https://client.example.test/callback"}, "scope": {"openid email profile offline_access"}, "state": {"fixture-state-with-enough-entropy"}, "decision": {"approve"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
		w := f.call("POST", "/oidc/authorize", form, f.accessToken(false), "192.0.2.1")
		if w.Code != 200 {
			t.Fatalf("public authorize status %d", w.Code)
		}
		redirect, _ := url.Parse(decodeTestResponse(t, w)["redirect_to"].(string))
		code := redirect.Query().Get("code")
		// Attackers know the public client ID, not this user's one-time code.
		body := f.tokenBody("invalid-code")
		body.Del("client_secret")
		body.Set("code_verifier", strings.Repeat("x", 64))
		for i := 0; i < 40; i++ {
			w = f.call("POST", "/oidc/token", body, "", "192.0.2.1")
			if w.Code != 400 && w.Code != 429 {
				t.Fatalf("invalid PKCE status %d", w.Code)
			}
		}
		body.Set("code_verifier", verifier)
		body.Set("code", code)
		w = f.call("POST", "/oidc/token", body, "", "192.0.2.1")
		if w.Code != 200 {
			t.Fatalf("valid PKCE request locked out: status %d", w.Code)
		}
	})
	t.Run("management credentials have independent failure and issuance budgets", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		id, clientID := kernel.NewID().String(), "management-"+f.client
		f.exec(`INSERT INTO installations(management_api_enabled) VALUES(true)`)
		f.exec(`INSERT INTO management_clients(id,client_id,name,secret_digest,allowed_scopes) VALUES($1,$2,'OAuth management test',$3,ARRAY['/management/organizations/*'])`, id, clientID, f.app.Vault.Digest("fixture-secret"))
		body := url.Values{"client_id": {clientID}, "client_secret": {"wrong-secret"}, "grant_type": {"client_credentials"}}
		for i := 0; i < 40; i++ {
			w := f.call("POST", "/oidc/token", body, "", "192.0.2.1")
			if w.Code != 401 && w.Code != 429 {
				t.Fatalf("invalid management secret status %d", w.Code)
			}
		}
		body.Set("client_secret", "fixture-secret")
		w := f.call("POST", "/oidc/token", body, "", "192.0.2.1")
		if w.Code != 200 {
			t.Fatalf("valid management credentials locked out: status %d", w.Code)
		}
	})
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		for _, state := range []string{"revoked session", "expired session", "revoked consent", "suspended user", "foreign session", "legacy delegation"} {
			t.Run(grant+" rejects "+state, func(t *testing.T) {
				f := newOAuthSecurityFixture(t)
				var body url.Values
				if grant == "authorization_code" {
					body = f.tokenBody(f.code())
				} else {
					body = f.refreshBody(f.tokens()["refresh_token"].(string))
				}
				switch state {
				case "revoked session":
					f.exec(`UPDATE user_sessions SET revoked_at=now() WHERE id=$1`, f.session)
				case "expired session":
					f.exec(`UPDATE user_sessions SET expires_at=now()-interval '1 second' WHERE id=$1`, f.session)
				case "revoked consent":
					f.exec(`UPDATE oauth_consents SET revoked_at=now()`)
				case "suspended user":
					f.exec(`UPDATE users SET status='suspended' WHERE id=$1`, f.user)
				case "foreign session":
					other := kernel.NewID().String()
					f.exec(`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'other@example.test','other@example.test')`, other, f.application)
					f.exec(`UPDATE user_sessions SET user_id=$1 WHERE id=$2`, other, f.session)
				case "legacy delegation":
					_ = f.accessToken(true)
				}
				w := f.call("POST", "/oidc/token", body, "", "192.0.2.1")
				if w.Code != 400 || decodeTestResponse(t, w)["error"] != "invalid_grant" {
					t.Fatalf("invalid grant issued tokens: status %d", w.Code)
				}
			})
		}
	}
	t.Run("refresh rollback preserves original and leaves no orphan", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		body := f.refreshBody(f.tokens()["refresh_token"].(string))
		f.exec(`CREATE FUNCTION reject_refresh_successor() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='refresh' THEN RAISE EXCEPTION 'fixture persistence failure'; END IF; RETURN NEW; END $$`)
		f.exec(`CREATE TRIGGER reject_refresh_successor BEFORE INSERT ON oauth_sessions FOR EACH ROW EXECUTE FUNCTION reject_refresh_successor()`)
		w := f.call("POST", "/oidc/token", body, "", "192.0.2.1")
		if w.Code != 500 {
			t.Fatalf("injected persistence failure status %d", w.Code)
		}
		var refresh, access int
		if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FILTER(WHERE kind='refresh' AND active),count(*) FILTER(WHERE kind='access') FROM oauth_sessions`).Scan(&refresh, &access); err != nil || refresh != 1 || access != 1 {
			t.Fatalf("partial rotation persisted: refresh=%d access=%d err=%v", refresh, access, err)
		}
		f.exec(`DROP TRIGGER reject_refresh_successor ON oauth_sessions`)
		w = f.call("POST", "/oidc/token", body, "", "192.0.2.1")
		if w.Code != 200 {
			t.Fatalf("original credential unusable after rollback: status %d", w.Code)
		}
	})
	t.Run("refresh rotation checks the exact signature", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		_ = f.tokens()
		var requestID string
		if err := f.app.DB.QueryRow(context.Background(), `SELECT request_id FROM oauth_sessions WHERE kind='refresh'`).Scan(&requestID); err != nil {
			t.Fatal(err)
		}
		store := &oauthserver.Store{DB: f.app.DB, Vault: f.app.Vault, ApplicationID: uuid.MustParse(f.application)}
		ctx, err := store.BeginTX(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer store.Rollback(ctx)
		if err = store.RotateRefreshToken(ctx, requestID, "wrong-signature"); !errors.Is(err, fosite.ErrInactiveToken) {
			t.Fatalf("wrong signature accepted: %v", err)
		}
		if err = store.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var active int
		if err = f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM oauth_sessions WHERE kind='refresh' AND active`).Scan(&active); err != nil || active != 1 {
			t.Fatalf("wrong signature revoked valid token: active=%d err=%v", active, err)
		}
	})
	t.Run("refresh replay revokes the successor family", func(t *testing.T) {
		f := newOAuthSecurityFixture(t)
		old := f.refreshBody(f.tokens()["refresh_token"].(string))
		w := f.call("POST", "/oidc/token", old, "", "192.0.2.1")
		if w.Code != 200 {
			t.Fatalf("refresh status %d", w.Code)
		}
		next := f.refreshBody(decodeTestResponse(t, w)["refresh_token"].(string))
		w = f.call("POST", "/oidc/token", old, "", "192.0.2.1")
		if w.Code != 400 {
			t.Fatalf("replay status %d", w.Code)
		}
		w = f.call("POST", "/oidc/token", next, "", "192.0.2.1")
		if w.Code != 400 {
			t.Fatalf("compromised family still refreshes: status %d", w.Code)
		}
		var active int
		if err := f.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM oauth_sessions WHERE kind IN ('access','refresh') AND active`).Scan(&active); err != nil || active != 0 {
			t.Fatalf("replay left active credentials: active=%d err=%v", active, err)
		}
	})
}
