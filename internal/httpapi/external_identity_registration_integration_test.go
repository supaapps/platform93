package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestExternalIdentityRegistrationPolicyAndLinking(t *testing.T) {
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
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
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{app: platform.New(db, vault, "https://platform93.test")}
	organizationID := kernel.NewID().String()
	if _, err := db.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Social registration',$2)`, organizationID, "social-"+organizationID); err != nil {
		t.Fatal(err)
	}
	applicationIDs := []string{}
	defer func() {
		for _, id := range applicationIDs {
			_, _ = db.Exec(ctx, `DELETE FROM user_identities WHERE application_id=$1`, id)
			_, _ = db.Exec(ctx, `DELETE FROM users WHERE application_id=$1`, id)
			_, _ = db.Exec(ctx, `DELETE FROM applications WHERE id=$1`, id)
		}
		_, _ = db.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, organizationID)
	}()
	createApplication := func(config string) string {
		t.Helper()
		id := kernel.NewID().String()
		internal := defaultApplicationInternalConfig()
		if err := json.Unmarshal([]byte(config), &internal); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(internal)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO applications(id,organization_id,name,slug,internal_config) VALUES($1,$2,'Social registration',$3,$4)`, id, organizationID, "social-"+id, encoded); err != nil {
			t.Fatal(err)
		}
		applicationIDs = append(applicationIDs, id)
		return id
	}
	complete := func(applicationID, flow, subject, email string, requestedBy *string) (string, error) {
		t.Helper()
		request := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": applicationID}, kernel.Actor{})
		return server.completeExternalIdentity(request, "google", "", flow, requestedBy, subject, email, "New", "User")
	}
	assertCounts := func(applicationID string, users, identities int) {
		t.Helper()
		var actualUsers, actualIdentities int
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM users WHERE application_id=$1),(SELECT count(*) FROM user_identities WHERE application_id=$1)`, applicationID).Scan(&actualUsers, &actualIdentities); err != nil {
			t.Fatal(err)
		}
		if actualUsers != users || actualIdentities != identities {
			t.Fatalf("users/identities = %d/%d, want %d/%d", actualUsers, actualIdentities, users, identities)
		}
	}
	createUser := func(applicationID, email string) string {
		t.Helper()
		id := kernel.NewID().String()
		if _, err := db.Exec(ctx, `INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, id, applicationID, email); err != nil {
			t.Fatal(err)
		}
		return id
	}
	publicApplication := createApplication(`{}`)
	var registeredUser string
	t.Run("default public registration and normalized metadata", func(t *testing.T) {
		var err error
		registeredUser, err = complete(publicApplication, "automatic", "google-subject", " New.User@Example.Test ", nil)
		if err != nil {
			t.Fatalf("automatic registration failed: %v", err)
		}
		var normalized, metadataEmail string
		var verified bool
		if err := db.QueryRow(ctx, `SELECT u.normalized_email,u.email_verified_at IS NOT NULL,i.metadata->>'email' FROM users u JOIN user_identities i ON i.user_id=u.id WHERE u.id=$1 AND i.application_id=$2`, registeredUser, publicApplication).Scan(&normalized, &verified, &metadataEmail); err != nil {
			t.Fatal(err)
		}
		if normalized != "new.user@example.test" || metadataEmail != normalized || !verified {
			t.Fatal("registration did not persist a verified user and normalized identity email")
		}
		assertCounts(publicApplication, 1, 1)
	})
	if registeredUser == "" {
		return
	}
	t.Run("repeat login does not duplicate users", func(t *testing.T) {
		id, err := complete(publicApplication, "automatic", "google-subject", "new.user@example.test", nil)
		if err != nil || id != registeredUser {
			t.Fatalf("repeat login = %s, %v; want existing user", id, err)
		}
		assertCounts(publicApplication, 1, 1)
	})
	t.Run("same email requires explicit authenticated linking", func(t *testing.T) {
		app := createApplication(`{}`)
		existing := createUser(app, "existing@example.test")
		if _, err := complete(app, "automatic", "existing-subject", "existing@example.test", nil); err == nil || err.Error() != "account_link_required" {
			t.Fatalf("same-email automatic login = %v; want account_link_required", err)
		}
		assertCounts(app, 1, 0)
		if _, err := complete(app, "link", "existing-subject", "existing@example.test", nil); err == nil || err.Error() != "authenticated_link_required" {
			t.Fatalf("unauthenticated link = %v; want authenticated_link_required", err)
		}
		id, err := complete(app, "link", "existing-subject", " EXISTING@Example.Test ", &existing)
		if err != nil || id != existing {
			t.Fatalf("explicit link = %s, %v; want existing user", id, err)
		}
		var metadataEmail string
		if err := db.QueryRow(ctx, `SELECT metadata->>'email' FROM user_identities WHERE user_id=$1`, existing).Scan(&metadataEmail); err != nil || metadataEmail != "existing@example.test" {
			t.Fatalf("linked email metadata = %q, %v", metadataEmail, err)
		}
		assertCounts(app, 1, 1)
	})
	t.Run("identities and links are application isolated", func(t *testing.T) {
		app := createApplication(`{}`)
		id, err := complete(app, "automatic", "google-subject", "new.user@example.test", nil)
		if err != nil || id == registeredUser {
			t.Fatalf("second application registration = %s, %v; want distinct user", id, err)
		}
		if _, err := complete(app, "link", "cross-application-subject", "new.user@example.test", &registeredUser); err == nil || err.Error() != "account_unavailable" {
			t.Fatalf("cross-application link = %v; want account_unavailable", err)
		}
		assertCounts(app, 1, 1)
	})
	t.Run("invite only blocks registration but permits existing identities", func(t *testing.T) {
		if _, err := db.Exec(ctx, `UPDATE applications SET internal_config=jsonb_set(internal_config,'{registration_mode}','"invite_only"') WHERE id=$1`, publicApplication); err != nil {
			t.Fatal(err)
		}
		for _, flow := range []string{"automatic", "sign_up"} {
			if _, err := complete(publicApplication, flow, "uninvited-subject", "uninvited@example.test", nil); err == nil || err.Error() != "registration_disabled" {
				t.Fatalf("%s in invite-only app = %v; want registration_disabled", flow, err)
			}
		}
		id, err := complete(publicApplication, "sign_in", "google-subject", "new.user@example.test", nil)
		if err != nil || id != registeredUser {
			t.Fatalf("existing identity sign-in = %s, %v", id, err)
		}
		assertCounts(publicApplication, 1, 1)
	})
	t.Run("sign in never creates a new account", func(t *testing.T) {
		app := createApplication(`{}`)
		if _, err := complete(app, "sign_in", "unknown-subject", "unknown@example.test", nil); err == nil || err.Error() != "provider_identity_not_found" {
			t.Fatalf("unknown sign-in = %v; want provider_identity_not_found", err)
		}
		assertCounts(app, 0, 0)
	})
}
