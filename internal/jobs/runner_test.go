package jobs

import (
	"context"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestDispatcherHandlesInstallationEventWithoutApplication(t *testing.T) {
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
	runner := New(platform.New(db, vault, "https://platform93.test"))
	eventID, outboxID := kernel.NewID(), kernel.NewID()
	if _, err = db.Exec(context.Background(), `INSERT INTO domain_events(id,application_id,event_type,subject,actor,data) VALUES($1,NULL,'installation.test','installation', '{}'::jsonb,'{}'::jsonb)`, eventID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO outbox(id,event_id) VALUES($1,$2)`, outboxID, eventID); err != nil {
		t.Fatal(err)
	}
	var dispatched bool
	for range 1000 {
		processed, dispatchErr := runner.dispatchOne(context.Background())
		if dispatchErr != nil {
			t.Fatal(dispatchErr)
		}
		if err = db.QueryRow(context.Background(), `SELECT dispatched_at IS NOT NULL FROM outbox WHERE id=$1`, outboxID).Scan(&dispatched); err != nil || dispatched || !processed {
			break
		}
	}
	if err != nil || !dispatched {
		t.Fatalf("installation event was not dispatched: dispatched=%v error=%v", dispatched, err)
	}
}

func TestDispatcherRoutesCustomEventOnlyToMatchingSubscribers(t *testing.T) {
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
	runner := New(platform.New(db, vault, "https://platform93.test"))
	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	matchingEndpointID, otherEndpointID := kernel.NewID(), kernel.NewID()
	eventID, outboxID := kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Events',$2)`, organizationID, "dispatch-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Events',$3)`, applicationID, organizationID, "dispatch-"+suffix); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []struct {
		id     string
		filter string
	}{
		{matchingEndpointID.String(), "vehicle.created"},
		{otherEndpointID.String(), "user.created"},
	} {
		secret, encryptErr := vault.Encrypt([]byte("p93_whsec_test"), "webhook-endpoint:"+endpoint.id)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		if _, err = db.Exec(context.Background(), `INSERT INTO webhook_endpoints(id,application_id,uri,event_filters,secret_ciphertext) VALUES($1,$2,'https://events.example.test/platform93',ARRAY[$3],$4)`, endpoint.id, applicationID, endpoint.filter, secret); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO domain_events(id,application_id,event_type,contract_source,subject,actor,data) VALUES($1,$2,'vehicle.created','application','vehicle/veh_123','{}','{"vehicle_id":"veh_123"}')`, eventID, applicationID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO outbox(id,event_id) VALUES($1,$2)`, outboxID, eventID); err != nil {
		t.Fatal(err)
	}
	processed, err := runner.dispatchOne(context.Background())
	if err != nil || !processed {
		t.Fatalf("custom event was not dispatched: processed=%v error=%v", processed, err)
	}
	var matching, unrelated int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM webhook_deliveries WHERE event_id=$1 AND webhook_endpoint_id=$2`, eventID, matchingEndpointID).Scan(&matching); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM webhook_deliveries WHERE event_id=$1 AND webhook_endpoint_id=$2`, eventID, otherEndpointID).Scan(&unrelated); err != nil {
		t.Fatal(err)
	}
	if matching != 1 || unrelated != 0 {
		t.Fatalf("unexpected custom event fan-out: matching=%d unrelated=%d", matching, unrelated)
	}
}
