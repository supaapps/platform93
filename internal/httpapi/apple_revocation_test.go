package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

func appleTestProvider(t *testing.T) externalAuthProviderConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return externalAuthProviderConfig{ID: kernel.NewID().String(), Provider: "apple", ClientID: "test.example.signin", Credentials: map[string]string{"team_id": "TESTTEAM", "key_id": "TESTKEY", "private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))}}
}

func TestAppleRevocationRequest(t *testing.T) {
	provider := appleTestProvider(t)
	for _, status := range []int{200, 400, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.ParseForm() != nil || r.Form.Get("client_id") != provider.ClientID || r.Form.Get("token") != "fixture-refresh-token" || r.Form.Get("token_type_hint") != "refresh_token" || r.Form.Get("client_secret") == "" {
					t.Error("invalid revocation request")
				}
				w.WriteHeader(status)
			}))
			defer endpoint.Close()
			err := revokeAppleToken(t.Context(), endpoint.Client(), endpoint.URL, provider, "fixture-refresh-token", time.Now())
			if (err == nil) != (status == 200) {
				t.Fatalf("status=%d error=%v", status, err)
			}
			if err != nil && strings.Contains(err.Error(), "fixture-refresh-token") {
				t.Fatal("token leaked")
			}
		})
	}
}

func TestAppleRevocationPersistence(t *testing.T) {
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL not configured")
	}
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := secure.NewVault(make([]byte, 32))
	app := platform.New(db, vault, "https://fixture.test")
	server := &Server{app: app}
	org, application, user, identity := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	provider := appleTestProvider(t)
	config, _ := json.Marshal(provider.Credentials)
	sealed, _ := vault.Encrypt(config, "auth-provider:"+provider.ID)
	fixtures := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Apple test',$2)`, []any{org, "apple-" + org.String()}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Apple test',$3)`, []any{application, org, "apple-" + application.String()}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{user, application, "apple-" + user.String() + "@example.test"}},
		{`INSERT INTO auth_provider_configs(id,application_id,provider,client_id,config_ciphertext) VALUES($1,$2,'apple',$3,$4)`, []any{provider.ID, application, provider.ClientID, sealed}},
		{`INSERT INTO user_identities(id,application_id,user_id,provider,provider_subject) VALUES($1,$2,$3,'apple','apple-subject')`, []any{identity, application, user}},
	}
	for _, fixture := range fixtures {
		if _, err = db.Exec(ctx, fixture.sql, fixture.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, operation := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"delete", server.deleteMyAccount}, {"anonymize", server.anonymizeMyAccount},
	} {
		t.Run(operation.name+" requires reauthentication without mutations", func(t *testing.T) {
			request := requestWithRoute(t, http.MethodDelete, "/", nil, map[string]string{"application_id": application.String()}, kernel.Actor{Type: "user", ID: user.String()})
			response := httptest.NewRecorder()
			operation.handler(response, request)
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "apple_reauthentication_required") {
				t.Fatalf("unexpected account response: %d %s", response.Code, response.Body.String())
			}
			var active bool
			if err := db.QueryRow(ctx, `SELECT status='active' AND deleted_at IS NULL FROM users WHERE id=$1`, user).Scan(&active); err != nil || !active {
				t.Fatalf("account changed: %v", err)
			}
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM user_identities WHERE id=$1`, identity).Scan(&count); err != nil || count != 1 {
				t.Fatalf("identity changed: %v", err)
			}
			if err := db.QueryRow(ctx, `SELECT count(*) FROM apple_token_revocations WHERE identity_id=$1`, identity).Scan(&count); err != nil || count != 0 {
				t.Fatalf("revocation unexpectedly queued: %v", err)
			}
		})
	}
	tx, _ := db.Begin(ctx)
	if err = queueAppleRevocations(ctx, tx, user.String(), application.String()); err == nil {
		t.Fatal("old identity should require Apple reauthentication")
	}
	tx.Rollback(ctx)
	if err = server.retainAppleToken(ctx, application.String(), user.String(), "apple-subject", provider, "fixture-refresh-token"); err != nil {
		t.Fatal(err)
	}
	var ciphertext string
	db.QueryRow(ctx, `SELECT token_ciphertext FROM apple_identity_tokens WHERE identity_id=$1`, identity).Scan(&ciphertext)
	if strings.Contains(ciphertext, "fixture-refresh-token") {
		t.Fatal("plaintext stored")
	}
	var signingCiphertext string
	if err := db.QueryRow(ctx, `SELECT signing_credentials_ciphertext FROM apple_identity_tokens WHERE identity_id=$1`, identity).Scan(&signingCiphertext); err != nil || strings.Contains(signingCiphertext, "PRIVATE KEY") {
		t.Fatalf("signing credentials not encrypted: %v", err)
	}
	// A subsequent provider replacement must not alter the token's signing identity.
	replacement := appleTestProvider(t)
	replacement.Credentials["team_id"] = "NEWTEAM"
	changedConfig, _ := json.Marshal(replacement.Credentials)
	changedSealed, _ := vault.Encrypt(changedConfig, "auth-provider:"+provider.ID)
	if _, err := db.Exec(ctx, `UPDATE auth_provider_configs SET config_ciphertext=$1,client_id='replacement.example' WHERE id=$2`, changedSealed, provider.ID); err != nil {
		t.Fatal(err)
	}
	tx, _ = db.Begin(ctx)
	for range 2 {
		if err = queueAppleRevocations(ctx, tx, user.String(), application.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM user_identities WHERE id=$1`, identity); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer endpoint.Close()
	if processed, err := revokeOneAppleIdentity(ctx, app, endpoint.Client(), endpoint.URL); err != nil || !processed {
		t.Fatalf("retry: %v %v", processed, err)
	}
	var attempts int
	db.QueryRow(ctx, `SELECT attempts FROM apple_token_revocations WHERE identity_id=$1`, identity).Scan(&attempts)
	if attempts != 1 {
		t.Fatalf("retry not retained: %d", attempts)
	}
	db.Exec(ctx, `UPDATE apple_token_revocations SET available_at=now() WHERE identity_id=$1`, identity)
	success := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		parts := strings.Split(r.Form.Get("client_secret"), ".")
		if len(parts) != 3 {
			t.Error("invalid client secret")
		} else {
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims struct {
				Issuer string `json:"iss"`
			}
			if json.Unmarshal(payload, &claims) != nil || claims.Issuer != provider.Credentials["team_id"] || r.Form.Get("client_id") != provider.ClientID {
				t.Error("provider replacement changed retained signing credentials")
			}
		}
		w.WriteHeader(200)
	}))
	defer success.Close()
	if processed, err := revokeOneAppleIdentity(ctx, app, success.Client(), success.URL); err != nil || !processed {
		t.Fatalf("success: %v %v", processed, err)
	}
	var count int
	db.QueryRow(ctx, `SELECT count(*) FROM apple_token_revocations WHERE identity_id=$1`, identity).Scan(&count)
	if count != 0 {
		t.Fatal("revocation credentials retained after success")
	}
}
