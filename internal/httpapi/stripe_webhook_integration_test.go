package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/supaapps/platform93/internal/kernel"
)

type stripeWebhookFixture struct {
	*workspaceHTTPFixture
	connection, publicID, secret string
}

func newStripeWebhookFixture(t *testing.T) *stripeWebhookFixture {
	f := &stripeWebhookFixture{workspaceHTTPFixture: newWorkspaceHTTPFixture(t), connection: kernel.NewID().String(), publicID: "stripe_" + kernel.NewID().String(), secret: "whsec_fixture_only"}
	secret, err := f.app.Vault.Encrypt([]byte(f.secret), "billing-provider:"+f.connection+":webhook")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO provider_connections(id,provider,public_id,api_version,secret_ciphertext,webhook_secret_ciphertext,inheritable)
VALUES($1,'stripe',$2,$3,'test-only-unused',$4,true)`, f.connection, f.publicID, stripeAPIVersion, secret)
	return f
}

func (f *stripeWebhookFixture) deliver(eventID, eventType string, object map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	body, err := json.Marshal(map[string]any{"id": eventID, "type": eventType, "api_version": stripeAPIVersion, "data": map[string]any{"object": object}})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.raw(body, f.app.Now(), true)
}

func (f *stripeWebhookFixture) raw(body []byte, at time.Time, signed bool) *httptest.ResponseRecorder {
	f.t.Helper()
	timestamp := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(f.secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	r := httptest.NewRequest("POST", "/provider-webhooks/stripe/"+f.publicID, bytes.NewReader(body))
	if signed {
		r.Header.Set("Stripe-Signature", "t="+timestamp+",v1="+hex.EncodeToString(mac.Sum(nil)))
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func (f *stripeWebhookFixture) payment(id string) map[string]any {
	return map[string]any{"id": id, "object": "payment_intent", "status": "succeeded", "amount": 100, "amount_received": 100, "currency": "chf", "metadata": map[string]any{"platform93_application_id": f.application}}
}

func TestStripeWebhookSignaturesAndMalformedEventsPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	valid := []byte(`{"id":"evt_unsigned","type":"payout.updated","data":{"object":{"id":"po_other"}}}`)
	for _, tc := range []struct {
		name   string
		body   []byte
		at     time.Time
		signed bool
	}{
		{"missing signature", valid, f.app.Now(), false},
		{"expired signature", valid, f.app.Now().Add(-10 * time.Minute), true},
		{"future signature", valid, f.app.Now().Add(10 * time.Minute), true},
		{"invalid JSON", []byte(`{invalid`), f.app.Now(), true},
		{"null object", []byte(`{"id":"evt_null","type":"payout.updated","data":{"object":null}}`), f.app.Now(), true},
		{"missing type", []byte(`{"id":"evt_type","data":{"object":{"id":"po_other"}}}`), f.app.Now(), true},
		{"missing object id", []byte(`{"id":"evt_id","type":"payment_intent.succeeded","data":{"object":{}}}`), f.app.Now(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.raw(tc.body, tc.at, tc.signed)
			if w.Code != 400 {
				t.Fatalf("expected rejection: %d %s", w.Code, w.Body.String())
			}
		})
	}
	if w := f.deliver("evt_balance", "balance.available", map[string]any{"object": "balance", "available": []any{}}); w.Code != 200 || !strings.Contains(w.Body.String(), "unsupported_event") {
		t.Fatalf("valid unsupported object without id rejected: %d %s", w.Code, w.Body.String())
	}
	f.exec(`UPDATE provider_connections SET webhook_secret_ciphertext='invalid-ciphertext' WHERE id=$1`, f.connection)
	if w := f.raw(valid, f.app.Now(), true); w.Code != 500 {
		t.Fatalf("decryption outage acknowledged: %d %s", w.Code, w.Body.String())
	}
	f.exec(`UPDATE provider_connections SET status='disabled' WHERE id=$1`, f.connection)
	if w := f.raw(valid, f.app.Now(), true); w.Code != 404 {
		t.Fatalf("disabled connection accepted: %d", w.Code)
	}
	f.publicID = "stripe_unknown"
	if w := f.raw(valid, f.app.Now(), true); w.Code != 404 {
		t.Fatalf("unknown connection accepted: %d", w.Code)
	}
}

func TestStripeWebhookRoutingAndIsolationPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	f.exec(`INSERT INTO billing_customers(id,application_id,subject_type,subject_id,provider_connection_id,provider_customer_id) VALUES($1,$2,'user',$3,$4,'cus_mapped')`, kernel.NewID(), f.application, f.user, f.connection)
	object := f.payment("pi_metadata")
	if w := f.deliver("evt_metadata", "payment_intent.succeeded", object); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	delete(object, "metadata")
	object["id"] = "pi_customer"
	object["customer"] = "cus_mapped"
	if w := f.deliver("evt_customer", "payment_intent.succeeded", object); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, value := range []any{"bad-uuid", nil, kernel.NewID().String()} {
		object := f.payment("pi_rejected")
		object["metadata"] = map[string]any{"platform93_application_id": value}
		if w := f.deliver("evt_bad_"+kernel.NewID().String(), "payment_intent.succeeded", object); w.Code != 422 {
			t.Fatalf("bad application accepted: %d %s", w.Code, w.Body.String())
		}
	}
	foreignOrg, foreignApp := kernel.NewID().String(), kernel.NewID().String()
	f.exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Foreign',$1::uuid::text)`, foreignOrg)
	f.exec(`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Foreign',$1::uuid::text)`, foreignApp, foreignOrg)
	object = f.payment("pi_conflict")
	object["customer"] = "cus_mapped"
	object["metadata"] = map[string]any{"platform93_application_id": foreignApp}
	if w := f.deliver("evt_conflict", "payment_intent.succeeded", object); w.Code != 422 {
		t.Fatalf("metadata/record conflict accepted: %d %s", w.Code, w.Body.String())
	}
	object = f.payment("pi_nested_conflict")
	object["invoice"] = map[string]any{"metadata": map[string]any{"platform93_application_id": foreignApp}}
	if w := f.deliver("evt_nested_conflict", "payment_intent.succeeded", object); w.Code != 422 {
		t.Fatalf("nested conflict accepted: %d", w.Code)
	}
	object = f.payment("pi_pending")
	object["metadata"] = map[string]any{"platform93_checkout_id": kernel.NewID().String()}
	if w := f.deliver("evt_pending", "payment_intent.succeeded", object); w.Code != 503 {
		t.Fatalf("marked missing mapping ignored: %d %s", w.Code, w.Body.String())
	}
	f.exec(`UPDATE provider_connections SET inheritable=false WHERE id=$1`, f.connection)
	if w := f.deliver("evt_not_inheritable", "payment_intent.succeeded", f.payment("pi_denied")); w.Code != 422 {
		t.Fatalf("inheritance bypass: %d", w.Code)
	}
	f.exec(`UPDATE provider_connections SET application_id=$1 WHERE id=$2`, f.application, f.connection)
	unrelated := map[string]any{"id": "pi_external", "customer": "cus_external"}
	if w := f.deliver("evt_external", "payment_intent.canceled", unrelated); w.Code != 200 || !strings.Contains(w.Body.String(), "unrelated_event") {
		t.Fatalf("app-owned provider used as default owner: %d %s", w.Code, w.Body.String())
	}
	foreign := f.payment("pi_foreign")
	foreign["metadata"] = map[string]any{"platform93_application_id": foreignApp}
	if w := f.deliver("evt_foreign", "payment_intent.succeeded", foreign); w.Code != 422 {
		t.Fatalf("foreign application accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestStripeWebhookIgnoredLogsAreRedactedPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	object := map[string]any{"id": "po_log", "metadata": map[string]any{"private": "do-not-log-this"}, "email": "private@example.test"}
	w := f.deliver("evt_log", "payout.updated", object)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	log := output.String()
	for _, unsafe := range []string{"do-not-log-this", "private@example.test", f.secret, "Stripe-Signature", "metadata"} {
		if strings.Contains(log, unsafe) {
			t.Fatalf("private value in log: %s", unsafe)
		}
	}
	for _, safe := range []string{"stripe_webhook_ignored", f.connection, "evt_log", "payout.updated", "unsupported_event", "request_id"} {
		if !strings.Contains(log, safe) {
			t.Fatalf("missing diagnostic field %s", safe)
		}
	}
}

func TestStripeWebhookDuplicateConcurrencySingleConnectionPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	config := f.app.DB.Config()
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	f.app.DB = pool
	const deliveries = 8
	results := make(chan *httptest.ResponseRecorder, deliveries)
	var group sync.WaitGroup
	for range deliveries {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- f.deliver("evt_concurrent", "payment_intent.succeeded", f.payment("pi_concurrent"))
		}()
	}
	done := make(chan struct{})
	go func() { group.Wait(); close(results); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("webhook processing held an extra pool connection")
	}
	processed, duplicates := 0, 0
	for w := range results {
		var ack map[string]any
		json.Unmarshal(w.Body.Bytes(), &ack)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		switch ack["status"] {
		case "processed":
			processed++
		case "duplicate":
			duplicates++
		default:
			t.Fatal(w.Body.String())
		}
	}
	if processed != 1 || duplicates != deliveries-1 {
		t.Fatalf("wrong duplicate decisions %d %d", processed, duplicates)
	}
	var payments, events, outbox, attempts int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM payments),(SELECT count(*) FROM domain_events WHERE event_type='billing.payment.updated'),(SELECT count(*) FROM outbox),(SELECT attempts FROM provider_events WHERE provider_event_id='evt_concurrent')`).Scan(&payments, &events, &outbox, &attempts); err != nil || payments != 1 || events != 1 || outbox != 1 || attempts != 1 {
		t.Fatalf("duplicate side effects: %d %d %d %d %v", payments, events, outbox, attempts, err)
	}
}

func TestStripeWebhookCommitFailureAndReplayPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	f.exec(`CREATE FUNCTION reject_receipt_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status='processed' THEN RAISE EXCEPTION 'fixture commit failure'; END IF; RETURN NEW; END $$`)
	f.exec(`CREATE CONSTRAINT TRIGGER reject_receipt_commit AFTER UPDATE ON provider_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_receipt_commit()`)
	w := f.deliver("evt_commit", "payment_intent.succeeded", f.payment("pi_commit"))
	if w.Code != 500 {
		t.Fatalf("commit failure acknowledged: %d %s", w.Code, w.Body.String())
	}
	var count int
	if err := f.app.DB.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM payments)+(SELECT count(*) FROM domain_events)+(SELECT count(*) FROM outbox)`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("commit failure left side effects: %d %v", count, err)
	}
	f.exec(`DROP TRIGGER reject_receipt_commit ON provider_events`)
	var id string
	if err := f.app.DB.QueryRow(t.Context(), `SELECT id FROM provider_events WHERE provider_event_id='evt_commit'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	w = f.controlJSON("POST", "/billing/provider-events/"+id+"/replay", map[string]any{})
	if w.Code != 204 {
		t.Fatalf("admin replay failed: %d %s", w.Code, w.Body.String())
	}
	w = f.deliver("evt_commit", "payment_intent.succeeded", f.payment("pi_commit"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "duplicate") {
		t.Fatal(w.Code, w.Body.String())
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := f.app.DB.QueryRow(ctx, `SELECT count(*) FROM domain_events WHERE event_type='billing.payment.updated'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay emitted duplicate events: %d %v", count, err)
	}
}

func TestStripeWebhookPendingReceiptRecoveryAndDiagnosticsPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	body, err := json.Marshal(map[string]any{"id": "evt_pending_receipt", "type": "payment_intent.succeeded", "data": map[string]any{"object": f.payment("pi_pending_receipt")}})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := f.app.Vault.Encrypt(body, "provider-event:"+f.connection+":evt_pending_receipt")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO provider_events(id,application_id,provider_connection_id,provider_event_id,event_type,raw_body_ciphertext) VALUES($1,$2,$3,'evt_pending_receipt','payment_intent.succeeded',$4)`, kernel.NewID(), f.application, f.connection, cipher)
	s := &Server{app: f.app}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.processStripeReceipt(ctx, f.connection, "evt_pending_receipt", f.application, "payment_intent.succeeded"); err == nil {
		t.Fatal("cancelled processing succeeded")
	}
	var status string
	var attempts int
	if err := f.app.DB.QueryRow(t.Context(), `SELECT status,attempts FROM provider_events WHERE provider_event_id='evt_pending_receipt'`).Scan(&status, &attempts); err != nil || status != "failed" || attempts != 1 {
		t.Fatalf("cancelled request lost failure diagnostic: %s %d %v", status, attempts, err)
	}
	f.exec(`UPDATE provider_connections SET inheritable=false WHERE id=$1`, f.connection)
	if _, err := s.processStripeReceipt(t.Context(), f.connection, "evt_pending_receipt", f.application, "payment_intent.succeeded"); err != errStripeAssociation {
		t.Fatalf("association failure not rejected: %v", err)
	}
	if err := f.app.DB.QueryRow(t.Context(), `SELECT status,attempts FROM provider_events WHERE provider_event_id='evt_pending_receipt'`).Scan(&status, &attempts); err != nil || status != "failed" || attempts != 2 {
		t.Fatalf("association failure lost diagnostic: %s %d %v", status, attempts, err)
	}
	f.exec(`UPDATE provider_connections SET inheritable=true WHERE id=$1`, f.connection)
	if w := f.raw(body, f.app.Now(), true); w.Code != 200 || !strings.Contains(w.Body.String(), "processed") {
		t.Fatalf("pending receipt did not recover: %d %s", w.Code, w.Body.String())
	}
	if w := f.deliver("evt_pending_receipt", "payment_intent.canceled", f.payment("pi_pending_receipt")); w.Code != 422 {
		t.Fatalf("receipt type collision accepted: %d %s", w.Code, w.Body.String())
	}
	if err := f.app.DB.QueryRow(t.Context(), `SELECT status,attempts FROM provider_events WHERE provider_event_id='evt_pending_receipt'`).Scan(&status, &attempts); err != nil || status != "processed" || attempts != 3 {
		t.Fatalf("collision overwrote completed receipt: %s %d %v", status, attempts, err)
	}
}

func TestStripeWebhookCheckoutMissingMappingRetriesPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	object := map[string]any{"id": "cs_late", "metadata": map[string]any{"platform93_application_id": f.application}}
	if w := f.deliver("evt_late_checkout", "checkout.session.expired", object); w.Code != 503 || !strings.Contains(w.Body.String(), "provider_event_mapping_pending") {
		t.Fatalf("missing checkout not retryable: %d %s", w.Code, w.Body.String())
	}
	product, price, checkout := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	f.exec(`INSERT INTO products(id,application_id,key,name) VALUES($1,$2,'late','Late checkout')`, product, f.application)
	f.exec(`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency) VALUES($1,$2,$3,'late','one_time',100,'CHF')`, price, f.application, product)
	f.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri,provider_session_id) VALUES($1,$2,'user',$3,$4,$5,'open','{}','https://app.example/success','https://app.example/cancel','cs_late')`, checkout, f.application, f.user, price, f.connection)
	if w := f.deliver("evt_late_checkout", "checkout.session.expired", object); w.Code != 200 || !strings.Contains(w.Body.String(), "processed") {
		t.Fatalf("checkout mapping retry failed: %d %s", w.Code, w.Body.String())
	}
}

func TestStripeWebhookCheckoutRollbackAndExactlyOnceGrantPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	product, price, checkout := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	f.exec(`INSERT INTO products(id,application_id,key,name) VALUES($1,$2,'checkout-test','Checkout')`, product, f.application)
	f.exec(`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency,validity_seconds) VALUES($1,$2,$3,'once','one_time',100,'CHF',2592000)`, price, f.application, product)
	f.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri,provider_session_id)
VALUES($1,$2,'user',$3,$4,$5,'open','{}','https://app.example/success','https://app.example/cancel','cs_once')`, checkout, f.application, f.user, price, f.connection)
	object := map[string]any{"id": "cs_once", "object": "checkout.session", "payment_status": "paid", "metadata": map[string]any{"platform93_application_id": f.application, "platform93_checkout_id": checkout}}
	f.exec(`CREATE FUNCTION reject_checkout_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status='processed' THEN RAISE EXCEPTION 'fixture commit failure'; END IF; RETURN NEW; END $$`)
	f.exec(`CREATE CONSTRAINT TRIGGER reject_checkout_commit AFTER UPDATE ON provider_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_checkout_commit()`)
	if w := f.deliver("evt_once", "checkout.session.completed", object); w.Code != 500 {
		t.Fatal(w.Code, w.Body.String())
	}
	var status string
	var grants, events int
	if err := f.app.DB.QueryRow(t.Context(), `SELECT status,(SELECT count(*) FROM entitlement_grants),(SELECT count(*) FROM domain_events) FROM checkout_sessions WHERE id=$1`, checkout).Scan(&status, &grants, &events); err != nil || status != "open" || grants != 0 || events != 0 {
		t.Fatalf("checkout did not roll back: %s %d %d %v", status, grants, events, err)
	}
	f.exec(`DROP TRIGGER reject_checkout_commit ON provider_events`)
	results := make(chan *httptest.ResponseRecorder, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() { defer group.Done(); results <- f.deliver("evt_once", "checkout.session.completed", object) }()
	}
	group.Wait()
	close(results)
	processed := 0
	for w := range results {
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var ack map[string]any
		json.Unmarshal(w.Body.Bytes(), &ack)
		if ack["status"] == "processed" {
			processed++
		}
	}
	if processed != 1 {
		t.Fatalf("checkout processed %d times", processed)
	}
	var actions int
	if err := f.app.DB.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM entitlement_grants),(SELECT count(*) FROM entitlement_grant_actions),(SELECT count(*) FROM domain_events)`).Scan(&grants, &actions, &events); err != nil || grants != 1 || actions != 0 || events != 2 {
		t.Fatalf("duplicate grant effects: %d %d %d %v", grants, actions, events, err)
	}
	// A later metadata-light event must route through the stored checkout ID.
	delete(object, "metadata")
	if w := f.deliver("evt_once_expired", "checkout.session.expired", object); w.Code != 200 {
		t.Fatalf("stored session did not route: %d %s", w.Code, w.Body.String())
	}
	f.exec(`UPDATE checkout_sessions SET provider_session_id=NULL WHERE id=$1`, checkout)
	object["client_reference_id"] = checkout
	if w := f.deliver("evt_client_reference", "checkout.session.expired", object); w.Code != 200 || !strings.Contains(w.Body.String(), "processed") {
		t.Fatalf("known client reference did not route: %d %s", w.Code, w.Body.String())
	}
}

func TestStripeWebhookUnsupportedSkipsApplicationQueriesPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	f.exec(`ALTER TABLE payments RENAME TO payments_not_available`)
	object := map[string]any{"id": "po_skip", "metadata": map[string]any{"platform93_application_id": "invalid"}}
	w := f.deliver("evt_skip", "payout.updated", object)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "unsupported_event") {
		t.Fatalf("unsupported event attempted routing: %d %s", w.Code, w.Body.String())
	}
}

func TestStripeWebhookIgnoresUnsupportedAndUnrelatedPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	for _, tc := range []struct {
		eventType, reason string
		object            map[string]any
	}{
		{"payout.updated", "unsupported_event", map[string]any{"id": "po_other", "object": "payout"}},
		{"customer.updated", "unsupported_event", map[string]any{"id": "cus_other", "object": "customer"}},
		{"payment_intent.canceled", "unrelated_event", map[string]any{"id": "pi_other", "object": "payment_intent", "customer": "cus_other"}},
	} {
		t.Run(tc.eventType, func(t *testing.T) {
			for range 2 {
				w := f.deliver("evt_"+tc.eventType, tc.eventType, tc.object)
				var result map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &result)
				if w.Code != 200 || result["received"] != true || result["status"] != "ignored" || result["reason"] != tc.reason {
					t.Fatalf("expected ignored: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
	var count int
	if err := f.app.DB.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM provider_events)+(SELECT count(*) FROM payments)+(SELECT count(*) FROM domain_events)+(SELECT count(*) FROM entitlement_grants)`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("ignored event side effects: %d %v", count, err)
	}
}

func TestStripeWebhookDatabaseFailureIsRetryablePostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	f.exec(`ALTER TABLE payments RENAME TO payments_unavailable`)
	w := f.deliver("evt_lookup_outage", "payment_intent.canceled", map[string]any{"id": "pi_unknown", "customer": "cus_unknown"})
	if w.Code < 500 {
		t.Fatalf("lookup failure must be retryable: %d %s", w.Code, w.Body.String())
	}
}

func TestStripeWebhookFailedReceiptRetriesAtomicallyPostgres(t *testing.T) {
	f := newStripeWebhookFixture(t)
	object := map[string]any{"id": "pi_retry", "object": "payment_intent", "status": "succeeded", "amount": 100, "amount_received": 100, "currency": "chf", "metadata": map[string]any{"platform93_application_id": f.application}}
	f.exec(`CREATE FUNCTION reject_payment_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture event failure'; END $$`)
	f.exec(`CREATE TRIGGER reject_payment_event BEFORE INSERT ON domain_events FOR EACH ROW EXECUTE FUNCTION reject_payment_event()`)
	w := f.deliver("evt_retry", "payment_intent.succeeded", object)
	if w.Code != 500 {
		t.Fatalf("expected injected failure: %d %s", w.Code, w.Body.String())
	}
	var count int
	if err := f.app.DB.QueryRow(t.Context(), `SELECT count(*) FROM payments`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial payment survived: %d %v", count, err)
	}
	f.exec(`DROP TRIGGER reject_payment_event ON domain_events`)
	w = f.deliver("evt_retry", "payment_intent.succeeded", object)
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if w.Code != 200 || result["status"] != "processed" {
		t.Fatalf("retry not processed: %d %s", w.Code, w.Body.String())
	}
	if err := f.app.DB.QueryRow(t.Context(), `SELECT count(*) FROM payments`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retry payment missing: %d %v", count, err)
	}
}
