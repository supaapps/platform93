package jobs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
	"github.com/supaapps/platform93/sdk/go/webhooks"
)

type deliveryTransport func(*http.Request) (*http.Response, error)

func (f deliveryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type deliveryFixture struct {
	runner                                         *Runner
	applicationID, endpointID, eventID, deliveryID string
	secret                                         string
}

func newDeliveryFixture(t *testing.T, source string) *deliveryFixture {
	t.Helper()
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	// Real workers select globally across applications. Use an isolated database so
	// these tests cannot send or consume deliveries left by another test package.
	databaseName := "p93_webhook_test_" + strings.ReplaceAll(kernel.NewID().String(), "-", "")
	quotedDatabase := pgx.Identifier{databaseName}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quotedDatabase); err != nil {
		admin.Close(ctx)
		t.Fatalf("delivery integration tests require a disposable PostgreSQL role with CREATEDB: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+quotedDatabase+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
		admin.Close(context.Background())
	})
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL.Path = "/" + databaseName
	databaseURL = parsedURL.String()
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	vault, err := secure.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := &deliveryFixture{
		runner:        New(platform.New(db, vault, "https://platform93.test")),
		applicationID: kernel.NewID().String(), endpointID: kernel.NewID().String(),
		eventID: kernel.NewID().String(), deliveryID: kernel.NewID().String(),
		secret: "test-only-webhook-secret",
	}
	organizationID := kernel.NewID().String()
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Delivery test',$2)`, []any{organizationID, "delivery-" + organizationID}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Delivery test',$3)`, []any{f.applicationID, organizationID, "delivery-" + f.applicationID}},
	} {
		if _, err = db.Exec(ctx, query.sql, query.args...); err != nil {
			t.Fatal(err)
		}
	}
	cipher, err := vault.Encrypt([]byte(f.secret), "webhook-endpoint:"+f.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO webhook_endpoints(id,application_id,uri,secret_ciphertext) VALUES($1,$2,'https://8.8.8.8/events',$3)`, f.endpointID, f.applicationID, cipher); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO domain_events(id,application_id,event_type,contract_source,subject,actor,data,occurred_at)
VALUES($1,$2,'delivery.test',$3,NULL,NULL,'{"test":true}','2026-10-15T12:34:56.123456+02:00')`, f.eventID, f.applicationID, source); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO webhook_deliveries(id,application_id,webhook_endpoint_id,event_id,next_attempt_at) VALUES($1,$2,$3,$4,'2000-01-01')`, f.deliveryID, f.applicationID, f.endpointID, f.eventID); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *deliveryFixture) deliver(t *testing.T) {
	t.Helper()
	processed, err := f.runner.deliverWebhook(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !processed {
		t.Fatal("target delivery was not attempted")
	}
}

func TestWebhookDeliveryReadsPostgresTimestampAndSignsBody(t *testing.T) {
	for _, source := range []string{"platform93", "application"} {
		t.Run(source, func(t *testing.T) {
			f := newDeliveryFixture(t, source)
			var oldDestination string
			err := f.runner.app.DB.QueryRow(context.Background(), `SELECT occurred_at FROM domain_events WHERE id=$1`, pgx.QueryResultFormats{pgx.BinaryFormatCode}, f.eventID).Scan(&oldDestination)
			if err == nil || !strings.Contains(err.Error(), "cannot scan timestamptz") {
				t.Fatalf("expected original binary scan failure, got %v", err)
			}
			requests := 0
			f.runner.client = &http.Client{Transport: deliveryTransport(func(r *http.Request) (*http.Response, error) {
				requests++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if err = webhooks.Verify(body, r.Header.Get("Platform93-Signature"), f.secret, time.Now(), time.Minute); err != nil {
					t.Fatal(err)
				}
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/cloudevents+json" {
					t.Fatal("unexpected webhook request")
				}
				var event map[string]any
				if err = json.Unmarshal(body, &event); err != nil {
					t.Fatal(err)
				}
				if event["id"] != f.eventID || event["application_id"] != f.applicationID || event["contract_source"] != source || event["time"] != "2026-10-15T10:34:56.123456Z" || event["actor"] != nil || event["subject"] != nil {
					t.Fatalf("unexpected webhook envelope: %s", body)
				}
				return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			f.deliver(t)
			var status string
			var attempts, response int
			var delivered bool
			if err = f.runner.app.DB.QueryRow(context.Background(), `SELECT status,attempt_count,response_status,delivered_at IS NOT NULL FROM webhook_deliveries WHERE id=$1`, f.deliveryID).Scan(&status, &attempts, &response, &delivered); err != nil {
				t.Fatal(err)
			}
			if status != "delivered" || attempts != 1 || response != 204 || !delivered || requests != 1 {
				t.Fatalf("unexpected delivery state: %s %d %d %v requests=%d", status, attempts, response, delivered, requests)
			}
			if _, err = f.runner.deliverWebhook(context.Background()); err != nil {
				t.Fatal(err)
			}
			if requests != 1 {
				t.Fatal("completed delivery was sent again")
			}
		})
	}
}

func TestDisabledWebhookPausesQueuedDeliveryAndResumes(t *testing.T) {
	f := newDeliveryFixture(t, "application")
	ctx := context.Background()
	if _, err := f.runner.app.DB.Exec(ctx, `UPDATE webhook_endpoints SET disabled_at=now() WHERE id=$1`, f.endpointID); err != nil {
		t.Fatal(err)
	}
	requests := 0
	f.runner.client = &http.Client{Transport: deliveryTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	if _, err := f.runner.deliverWebhook(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	var attempts int
	if err := f.runner.app.DB.QueryRow(ctx, `SELECT status,attempt_count FROM webhook_deliveries WHERE id=$1`, f.deliveryID).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attempts != 0 || requests != 0 {
		t.Fatal("disabled endpoint was attempted")
	}
	if _, err := f.runner.app.DB.Exec(ctx, `UPDATE webhook_endpoints SET disabled_at=NULL WHERE id=$1`, f.endpointID); err != nil {
		t.Fatal(err)
	}
	f.deliver(t)
	if requests != 1 {
		t.Fatal("re-enabled endpoint did not resume")
	}
}

func TestWebhookFailureRetriesAndDeadLettersWithoutBlockingNotifications(t *testing.T) {
	f := newDeliveryFixture(t, "application")
	ctx := context.Background()
	notificationID := kernel.NewID().String()
	if _, err := f.runner.app.DB.Exec(ctx, `INSERT INTO notifications(id,application_id,recipient,payload_ciphertext,next_attempt_at) VALUES($1,$2,'test@example.invalid','unavailable','2000-01-01')`, notificationID, f.applicationID); err != nil {
		t.Fatal(err)
	}
	f.runner.client = &http.Client{Transport: deliveryTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	})}
	if err := (&deliverySweepWorker{runner: f.runner}).Work(ctx, nil); err != nil {
		t.Fatal(err)
	}
	var attempts int
	if err := f.runner.app.DB.QueryRow(ctx, `SELECT attempt_count FROM notifications WHERE id=$1`, notificationID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	// No SMTP provider is configured: a recorded failure proves the email was processed.
	if attempts != 1 {
		t.Fatalf("notification was not processed: attempts=%d", attempts)
	}
	var status string
	var retryScheduled bool
	if err := f.runner.app.DB.QueryRow(ctx, `SELECT status,attempt_count,next_attempt_at>now() FROM webhook_deliveries WHERE id=$1`, f.deliveryID).Scan(&status, &attempts, &retryScheduled); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || attempts != 1 || !retryScheduled {
		t.Fatalf("retry not recorded: %s %d %v", status, attempts, retryScheduled)
	}
	if _, err := f.runner.app.DB.Exec(ctx, `UPDATE webhook_deliveries SET attempt_count=9,next_attempt_at='2000-01-01' WHERE id=$1`, f.deliveryID); err != nil {
		t.Fatal(err)
	}
	f.deliver(t)
	if err := f.runner.app.DB.QueryRow(ctx, `SELECT status,attempt_count FROM webhook_deliveries WHERE id=$1`, f.deliveryID).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || attempts != 10 {
		t.Fatalf("delivery did not dead letter: %s %d", status, attempts)
	}
}

func TestWebhookScanErrorDoesNotSkipNotification(t *testing.T) {
	f := newDeliveryFixture(t, "application")
	ctx := context.Background()
	// Simulate a future decoding defect without sending a request or altering schema.
	if _, err := f.runner.app.DB.Exec(ctx, `UPDATE domain_events SET occurred_at='infinity' WHERE id=$1`, f.eventID); err != nil {
		t.Fatal(err)
	}
	notificationID := kernel.NewID().String()
	if _, err := f.runner.app.DB.Exec(ctx, `INSERT INTO notifications(id,application_id,recipient,payload_ciphertext,next_attempt_at) VALUES($1,$2,'test@example.invalid','unavailable','2000-01-01')`, notificationID, f.applicationID); err != nil {
		t.Fatal(err)
	}
	if err := (&deliverySweepWorker{runner: f.runner}).Work(ctx, nil); err == nil {
		t.Fatal("webhook decoding error must remain retryable")
	}
	var attempts int
	if err := f.runner.app.DB.QueryRow(ctx, `SELECT attempt_count FROM notifications WHERE id=$1`, notificationID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("webhook decoding error blocked notification: attempts=%d", attempts)
	}
}

func TestConcurrentWebhookWorkersSkipLockedDelivery(t *testing.T) {
	f := newDeliveryFixture(t, "application")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started, release := make(chan struct{}, 1), make(chan struct{})
	var requests atomic.Int32
	f.runner.client = &http.Client{Transport: deliveryTransport(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
			return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})}
	done := make(chan error, 1)
	go func() {
		_, err := f.runner.deliverWebhook(ctx)
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("first worker did not start delivery")
	}
	_, secondErr := f.runner.deliverWebhook(ctx)
	close(release)
	firstErr := <-done
	if firstErr != nil || secondErr != nil || requests.Load() != 1 {
		t.Fatalf("concurrent workers duplicated delivery: requests=%d first=%v second=%v", requests.Load(), firstErr, secondErr)
	}
}
