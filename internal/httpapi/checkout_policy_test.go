package httpapi

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestRecurringPolicyValidation(t *testing.T) {
	for _, key := range []string{"trial_once_per_subject", "single_subscription"} {
		if validateCheckoutPolicy("recurring", "EUR", map[string]any{key: true}) != nil {
			t.Fatal("valid policy rejected")
		}
		if validateCheckoutPolicy("recurring", "EUR", map[string]any{key: "true"}) == nil {
			t.Fatal("string policy accepted")
		}
		if validateCheckoutPolicy("one_time", "EUR", map[string]any{key: true}) == nil {
			t.Fatal("one-time policy accepted")
		}
	}
}

func TestSubjectCancellationRequiresMachinePermission(t *testing.T) {
	app := kernel.NewID().String()
	for _, actor := range []kernel.Actor{{Type: "user", ID: kernel.NewID().String()}, {Type: "client", ID: kernel.NewID().String()}, {Type: "client", ID: kernel.NewID().String(), Permissions: []string{"/applications/" + kernel.NewID().String() + "/billing/write"}}} {
		request := requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": app, "subject_type": "workspace", "subject_id": kernel.NewID().String()}, actor)
		response := httptest.NewRecorder()
		(&Server{}).serviceCancelSubjectBilling(response, request)
		if response.Code != 403 {
			t.Fatalf("unauthorized subject cancellation: %d", response.Code)
		}
	}
}

func TestCheckoutEligibilityDatabase(t *testing.T) {
	uri := os.Getenv("PLATFORM93_DATABASE_URL")
	if uri == "" {
		t.Skip("PLATFORM93_DATABASE_URL unset")
	}
	if err := database.Migrate(uri); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := database.Open(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{app: platform.New(db, vault, "https://platform.example")}
	org, app, user, product, price, connection := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	defer db.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org)
	statements := []struct {
		q string
		a []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Test',$2)`, []any{org, org.String()}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Test',$3)`, []any{app, org, app.String()}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'test@example.test','test@example.test')`, []any{user, app}},
		{`INSERT INTO products(id,application_id,key,name) VALUES($1,$2,'recurring','Recurring')`, []any{product, app}},
		{`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency,interval_unit,interval_count) VALUES($1,$2,$3,'monthly','recurring',1000,'EUR','month',1)`, []any{price, app, product}},
		{`INSERT INTO provider_connections(id,application_id,provider,public_id,api_version,secret_ciphertext) VALUES($1,$2,'stripe',$3,$4,'fixture')`, []any{connection, app, connection.String(), stripeAPIVersion}},
	}
	for _, s := range statements {
		if _, err = db.Exec(ctx, s.q, s.a...); err != nil {
			t.Fatal(err)
		}
	}
	request := requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": app.String()}, kernel.Actor{Type: "user", ID: user.String()})
	for _, status := range []string{"failed", "expired", "completed", "open", "pending"} {
		id := kernel.NewID()
		_, err = db.Exec(ctx, `INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri) VALUES($1,$2,'user',$3,$4,$5,$6,'{"trial_period_days":7}','https://app.test/return','https://app.test/return')`, id, app, user, price, connection, status)
		if err != nil {
			t.Fatal(err)
		}
		policy := map[string]any{"single_subscription": true, "trial_once_per_subject": true, "trial_period_days": float64(7)}
		response := httptest.NewRecorder()
		release, ok := server.guardRecurringCheckout(response, request, "user", user.String(), product.String(), price.String(), policy)
		if status == "open" || status == "pending" {
			if ok || response.Code != 409 {
				t.Fatalf("duplicate %s accepted: %d", status, response.Code)
			}
		} else {
			if !ok {
				t.Fatalf("%s: %d", status, response.Code)
			}
			_, hasTrial := policy["trial_period_days"]
			if hasTrial == (status == "completed") {
				t.Fatalf("trial eligibility %s: %+v", status, policy)
			}
		}
		release()
		if _, err = db.Exec(ctx, `DELETE FROM checkout_sessions WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	response := httptest.NewRecorder()
	server.cancelMySubscription(response, requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": app.String(), "subscription_id": kernel.NewID().String()}, kernel.Actor{Type: "user", ID: user.String()}))
	if response.Code != 404 {
		t.Fatalf("unrelated cancellation: %d", response.Code)
	}
}
