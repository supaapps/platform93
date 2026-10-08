package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func appleAtomicityFixture(t *testing.T) (*Server, string, externalAuthProviderConfig) {
	t.Helper()
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL not configured")
	}
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{app: platform.New(db, vault, "https://fixture.test")}
	org, application := kernel.NewID().String(), kernel.NewID().String()
	provider := appleTestProvider(t)
	config, err := json.Marshal(provider.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := vault.Encrypt(config, "auth-provider:"+provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Apple atomicity',$2)`, []any{org, "apple-" + org}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Apple atomicity',$3)`, []any{application, org, "apple-" + application}},
		{`INSERT INTO auth_provider_configs(id,application_id,provider,client_id,config_ciphertext) VALUES($1,$2,'apple',$3,$4)`, []any{provider.ID, application, provider.ClientID, sealed}},
	}
	for _, fixture := range fixtures {
		if _, err := db.Exec(t.Context(), fixture.sql, fixture.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM apple_token_revocations WHERE auth_provider_config_id=$1`, provider.ID)
		db.Close()
	})
	return server, application, provider
}

func TestAppleOnboardingTokenRetentionAtomicity(t *testing.T) {
	server, application, provider := appleAtomicityFixture(t)
	request := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": application}, kernel.Actor{})
	retain := func(provider externalAuthProviderConfig, token string) externalIdentityFinalizer {
		return func(tx pgx.Tx, userID string) error {
			return server.retainAppleTokenTx(t.Context(), tx, application, userID, "apple-subject", provider, token)
		}
	}
	assertCounts := func(users, identities, tokens int) {
		t.Helper()
		var u, i, c int
		err := server.app.DB.QueryRow(t.Context(), `SELECT
(SELECT count(*) FROM users WHERE application_id=$1),
(SELECT count(*) FROM user_identities WHERE application_id=$1),
(SELECT count(*) FROM apple_identity_tokens WHERE auth_provider_config_id=$2)`, application, provider.ID).Scan(&u, &i, &c)
		if err != nil || u != users || i != identities || c != tokens {
			t.Fatalf("counts=%d/%d/%d want=%d/%d/%d error=%v", u, i, c, users, identities, tokens, err)
		}
	}
	invalidProvider := provider
	invalidProvider.ID = kernel.NewID().String()
	for _, finalize := range []externalIdentityFinalizer{retain(provider, ""), retain(invalidProvider, "fixture-token")} {
		_, err := server.completeExternalIdentity(request, "apple", "", "automatic", nil, "apple-subject", "new@example.test", "", "", finalize)
		if err == nil || err.Error() != "provider_token_retention_failed" {
			t.Fatalf("expected retention failure: %v", err)
		}
		assertCounts(0, 0, 0)
	}
	user := kernel.NewID().String()
	if _, err := server.app.DB.Exec(t.Context(), `INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'linked@example.test','linked@example.test')`, user, application); err != nil {
		t.Fatal(err)
	}
	if _, err := server.completeExternalIdentity(request, "apple", "", "link", &user, "apple-subject", "linked@example.test", "", "", retain(provider, "")); err == nil {
		t.Fatal("link should fail without retained token")
	}
	assertCounts(1, 0, 0)
	for range 2 {
		if _, err := server.completeExternalIdentity(request, "apple", "", "link", &user, "apple-subject", "linked@example.test", "", "", retain(provider, "fixture-token")); err != nil {
			t.Fatal(err)
		}
	}
	assertCounts(1, 1, 1)
	if _, err := server.completeExternalIdentity(request, "apple", "", "automatic", nil, "signup-apple", "signup@example.test", "", "", func(tx pgx.Tx, userID string) error {
		return server.retainAppleTokenTx(t.Context(), tx, application, userID, "signup-apple", provider, "signup-token")
	}); err != nil {
		t.Fatal(err)
	}
	assertCounts(2, 2, 2)
}

func TestAppleInvitationRetentionRollsBackAcceptance(t *testing.T) {
	server, application, provider := appleAtomicityFixture(t)
	invitation, workspace, owner, role := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	queries := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'owner@example.test','owner@example.test')`, []any{owner, application}},
		{`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'invited','Invited')`, []any{workspace, application, owner}},
		{`INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,'reader','Reader','workspace',ARRAY['records:read'])`, []any{role, application}},
		{`INSERT INTO application_invitations(id,application_id,workspace_id,normalized_email,link_credential_digest,onboarding_method,workspace_roles,expires_at) VALUES($1,$2,$3,'invited@example.test',$4,'apple',ARRAY['reader'],now()+interval '1 day')`, []any{invitation, application, workspace, []byte("fixture")}},
	}
	for _, q := range queries {
		if _, err := server.app.DB.Exec(t.Context(), q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	request := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": application}, kernel.Actor{})
	external := externalProviderIdentity{Subject: "invited-apple", Email: "invited@example.test", TrustedEmail: true}
	complete := func(token string) (string, error) {
		return server.completeApplicationInvitationExternalIdentity(request, invitation, provider, external, func(tx pgx.Tx, userID string) error {
			return server.retainAppleTokenTx(t.Context(), tx, application, userID, external.Subject, provider, token)
		})
	}
	if _, err := complete(""); err == nil || err.Error() != "provider_token_retention_failed" {
		t.Fatalf("acceptance should fail at retention: %v", err)
	}
	var accepted bool
	var users, memberships, assignments, events int
	err := server.app.DB.QueryRow(t.Context(), `SELECT
(SELECT accepted_at IS NOT NULL FROM application_invitations WHERE id=$1),
(SELECT count(*) FROM users WHERE application_id=$2),
(SELECT count(*) FROM workspace_memberships WHERE workspace_id=$3),
(SELECT count(*) FROM role_assignments WHERE workspace_id=$3),
(SELECT count(*) FROM domain_events WHERE application_id=$2)`, invitation, application, workspace).Scan(&accepted, &users, &memberships, &assignments, &events)
	if err != nil || accepted || users != 1 || memberships != 0 || assignments != 0 || events != 0 {
		t.Fatalf("partial acceptance: accepted=%v users=%d memberships=%d roles=%d events=%d err=%v", accepted, users, memberships, assignments, events, err)
	}
	if _, err := complete("fixture-token"); err != nil {
		t.Fatal(err)
	}
	if err := server.app.DB.QueryRow(t.Context(), `SELECT accepted_at IS NOT NULL FROM application_invitations WHERE id=$1`, invitation).Scan(&accepted); err != nil || !accepted {
		t.Fatalf("acceptance: %v", err)
	}
}

func TestAppleUnlinkQueuesRevocation(t *testing.T) {
	server, application, provider := appleAtomicityFixture(t)
	user, identity, google := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,application_id,email,normalized_email,password_hash) VALUES($1,$2,'unlink@example.test','unlink@example.test','fixture-hash')`, []any{user, application}},
		{`INSERT INTO user_identities(id,application_id,user_id,provider,provider_subject) VALUES($1,$2,$3,'apple','unlink-apple'),($4,$2,$3,'google','unlink-google')`, []any{identity, application, user, google}},
	} {
		if _, err := server.app.DB.Exec(t.Context(), q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	unlink := func(id string) *httptest.ResponseRecorder {
		request := requestWithRoute(t, http.MethodDelete, "/", nil, map[string]string{"application_id": application, "identity_id": id}, kernel.Actor{Type: "user", ID: user})
		response := httptest.NewRecorder()
		server.unlinkMyIdentity(response, request)
		return response
	}
	if response := unlink(google); response.Code != http.StatusNoContent {
		t.Fatalf("Google unlink: %d %s", response.Code, response.Body.String())
	}
	if response := unlink(identity); response.Code != http.StatusForbidden {
		t.Fatalf("old Apple identity should require reauthentication: %d", response.Code)
	}
	if err := server.retainAppleToken(t.Context(), application, user, "unlink-apple", provider, "fixture-token"); err != nil {
		t.Fatal(err)
	}
	if response := unlink(identity); response.Code != http.StatusNoContent {
		t.Fatalf("Apple unlink: %d %s", response.Code, response.Body.String())
	}
	var identities, tokens, queued int
	err := server.app.DB.QueryRow(t.Context(), `SELECT
(SELECT count(*) FROM user_identities WHERE id=$1),
(SELECT count(*) FROM apple_identity_tokens WHERE identity_id=$1),
(SELECT count(*) FROM apple_token_revocations WHERE identity_id=$1)`, identity).Scan(&identities, &tokens, &queued)
	if err != nil || identities != 0 || tokens != 0 || queued != 1 {
		t.Fatalf("unlink lost revocation: %d/%d/%d %v", identities, tokens, queued, err)
	}
	response := httptest.NewRecorder()
	request := requestWithRoute(t, http.MethodDelete, "/", nil, map[string]string{"application_id": application}, kernel.Actor{Type: "user", ID: user})
	server.deleteMyAccount(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("deletion after unlink: %d %s", response.Code, response.Body.String())
	}
	if err := server.app.DB.QueryRow(t.Context(), `SELECT count(*) FROM apple_token_revocations WHERE identity_id=$1`, identity).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("deletion lost queued token: %d %v", queued, err)
	}
}
