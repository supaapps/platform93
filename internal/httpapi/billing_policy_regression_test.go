package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/supaapps/platform93/internal/generated"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
)

type billingReviewFixture struct {
	*workspaceHTTPFixture
	s                                   *Server
	product, price, provider, workspace string
}

func newBillingReviewFixture(t *testing.T) *billingReviewFixture {
	f := newWorkspaceHTTPFixture(t)
	b := &billingReviewFixture{workspaceHTTPFixture: f, s: &Server{app: f.app}, product: kernel.NewID().String(), price: kernel.NewID().String(), provider: kernel.NewID().String(), workspace: kernel.NewID().String()}
	f.exec(`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'billing','Billing')`, b.workspace, f.application, f.user)
	f.exec(`INSERT INTO products(id,application_id,key,name,status) VALUES($1,$2,'billing','Billing','active')`, b.product, f.application)
	f.exec(`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency,interval_unit,interval_count,checkout_config) VALUES($1,$2,$3,'monthly','recurring',1000,'EUR','month',1,'{"single_subscription":true,"trial_once_per_subject":true,"trial_period_days":7}')`, b.price, f.application, b.product)
	sealed, err := f.app.Vault.Encrypt([]byte("fixture-billing-secret"), "billing-provider:"+b.provider+":secret")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO provider_connections(id,application_id,provider,public_id,api_version,secret_ciphertext) VALUES($1,$2,'stripe',$1::uuid::text,$3,$4)`, b.provider, f.application, stripeAPIVersion, sealed)
	f.exec(`INSERT INTO provider_mappings(id,application_id,provider_connection_id,object_type,internal_id,provider_id) VALUES($1,$2,$3,'price',$4,'price_fixture')`, kernel.NewID(), f.application, b.provider, b.price)
	for _, subject := range []struct{ kind, id string }{{"user", f.user}, {"workspace", b.workspace}} {
		f.exec(`INSERT INTO billing_customers(id,application_id,subject_type,subject_id,provider_connection_id,provider_customer_id) VALUES($1,$2,$3,$4,$5,$6)`, kernel.NewID(), f.application, subject.kind, subject.id, b.provider, "cus_"+subject.kind)
	}
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	return b
}

func billingProviderJSON(value any, status int) *http.Response {
	body, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}
}

func (b *billingReviewFixture) checkoutBody(workspace bool) map[string]any {
	body := map[string]any{"price_id": b.price, "success_uri": "https://client.example.test/callback", "cancel_uri": "https://client.example.test/callback"}
	if workspace {
		body["subject_type"] = "workspace"
		body["subject_id"] = b.workspace
	}
	return body
}

func (b *billingReviewFixture) jsonCall(path string, body any, token, key string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/v1/applications/"+b.application+path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	b.router.ServeHTTP(w, r)
	return w
}

func (b *billingReviewFixture) machineToken() string {
	b.t.Helper()
	b.exec(`UPDATE clients SET allowed_grants=array_append(allowed_grants,'client_credentials') WHERE id=$1`, b.client)
	kid, key, err := b.app.ActiveSigningKey(context.Background())
	if err != nil {
		b.t.Fatal(err)
	}
	now := time.Now()
	token, err := identity.Sign(key, kid, identity.Claims{Issuer: b.app.Issuer(), Subject: b.client, Audience: []string{"platform93:application:" + b.application}, ApplicationID: b.application, ActorType: "client", TokenKind: "machine", Scope: b.scope("billing/write") + " " + b.scope("billing/read"), Roles: emptyRoleClaims(), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), JWTID: kernel.NewID().String()})
	if err != nil {
		b.t.Fatal(err)
	}
	return token
}

func (b *billingReviewFixture) subscription(checkout, status string, workspace bool) map[string]any {
	return map[string]any{"id": "sub_fixture", "status": status, "metadata": map[string]any{"platform93_checkout_id": checkout}, "trial_end": time.Now().Add(-time.Hour).Unix(), "canceled_at": time.Now().Unix(), "items": map[string]any{"data": []any{map[string]any{"id": "si_fixture", "current_period_start": time.Now().Add(-time.Hour).Unix(), "current_period_end": time.Now().Add(time.Hour).Unix()}}}}
}

func TestBillingPolicyPostgresConcurrencyAndRecovery(t *testing.T) {
	b := newBillingReviewFixture(t)
	config := b.app.DB.Config()
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	b.app.DB = pool
	token := b.accessToken(false)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
		once.Do(func() { close(entered) })
		<-release
		return billingProviderJSON(map[string]any{"id": "cs_fixture", "url": "https://checkout.stripe.com/fixture", "status": "open"}, 200), nil
	})
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		first <- b.jsonCall("/billing/checkout-sessions", b.checkoutBody(false), token, "initial-checkout")
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("first checkout did not reach provider")
	}
	var wg sync.WaitGroup
	responses := make(chan int, 25)
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			responses <- b.jsonCall("/billing/checkout-sessions", b.checkoutBody(false), token, fmt.Sprintf("concurrent-%d", i)).Code
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("checkout exhausted database pool during provider I/O")
	}
	close(release)
	if w := <-first; w.Code != 201 {
		t.Fatalf("first checkout: %d %s", w.Code, w.Body)
	}
	close(responses)
	for code := range responses {
		if code != 409 {
			t.Fatalf("concurrent checkout: %d", code)
		}
	}
	// Lose the local provider response; retry must replay the exact form/key.
	b.exec(`UPDATE checkout_sessions SET provider_session_id=NULL,checkout_uri=NULL,status='pending' WHERE application_id=$1`, b.application)
	var recoveryKey string
	http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
		recoveryKey = r.Header.Get("Idempotency-Key")
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		if r.Form.Get("subscription_data[trial_period_days]") != "7" {
			t.Error("recovery changed original trial form")
		}
		return billingProviderJSON(map[string]any{"id": "cs_fixture", "url": "https://checkout.stripe.com/fixture", "status": "open"}, 200), nil
	})
	// A 5xx normally removes the generic HTTP receipt, as this interrupted request would.
	b.exec(`DELETE FROM idempotency_records WHERE application_id=$1`, b.application)
	w := b.jsonCall("/billing/checkout-sessions", b.checkoutBody(false), token, "initial-checkout")
	if w.Code != 200 || !strings.HasPrefix(recoveryKey, "platform93-checkout-"+b.application+"-") {
		t.Fatalf("recovery: %d %s key=%s", w.Code, w.Body, recoveryKey)
	}
}

func TestBillingPolicyPostgresCancellationAndResubscription(t *testing.T) {
	b := newBillingReviewFixture(t)
	checkout := kernel.NewID().String()
	b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri,provider_session_id) VALUES($1,$2,'workspace',$3,$4,$5,'completed','{"trial_period_days":7}','https://client.example.test/callback','https://client.example.test/callback','cs_existing')`, checkout, b.application, b.workspace, b.price, b.provider)
	if err := b.s.normalizeStripeSubscription(context.Background(), b.application, b.provider, b.subscription(checkout, "past_due", true)); err != nil {
		t.Fatal(err)
	}
	manual := kernel.NewID().String()
	b.exec(`INSERT INTO entitlement_grants(id,application_id,subject_type,subject_id,source_type,feature_values,configuration,starts_at) VALUES($1,$2,'workspace',$3,'manual','{}','{}',now())`, manual, b.application, b.workspace)
	deleteCalls := 0
	http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "DELETE" {
			deleteCalls++
			if deleteCalls == 1 {
				return nil, fmt.Errorf("lost provider response")
			}
		}
		return billingProviderJSON(b.subscription(checkout, "canceled", true), 200), nil
	})
	token := b.machineToken()
	w := b.jsonCall("/subjects/workspace/"+b.workspace+"/billing/cancel", map[string]any{"at_period_end": false}, token, "cancel-workspace")
	if w.Code != 204 {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	var pending, manualChanges int
	var since *time.Time
	var status, action string
	if err := b.app.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM billing_subject_cancellations WHERE application_id=$1),(SELECT count(*) FROM entitlement_grant_actions WHERE grant_id=$2),status,past_due_since FROM subscriptions WHERE application_id=$1`, b.application, manual).Scan(&pending, &manualChanges, &status, &since); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || manualChanges != 0 || status != "canceled" || since != nil {
		t.Fatalf("cancel state pending=%d manual=%d status=%s since=%v", pending, manualChanges, status, since)
	}
	if err := b.app.DB.QueryRow(context.Background(), `SELECT action FROM entitlement_grant_actions a JOIN entitlement_grants g ON g.id=a.grant_id WHERE g.application_id=$1 AND g.source_type='subscription' ORDER BY a.created_at DESC,a.id DESC LIMIT 1`, b.application).Scan(&action); err != nil || action != "revoked" {
		t.Fatalf("provider access not revoked: %s %v", action, err)
	}
	if w = b.jsonCall("/subjects/workspace/"+b.workspace+"/billing/cancel", map[string]any{"at_period_end": false}, token, "cancel-workspace"); w.Code != 204 || deleteCalls != 1 {
		t.Fatalf("idempotent retry: %d deletes=%d", w.Code, deleteCalls)
	}
	http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
		_ = r.ParseForm()
		if r.Form.Get("subscription_data[trial_period_days]") != "" {
			t.Error("second subscription received another trial")
		}
		return billingProviderJSON(map[string]any{"id": "cs_next", "url": "https://checkout.stripe.com/next", "status": "open"}, 200), nil
	})
	if w = b.jsonCall("/billing/checkout-sessions", b.checkoutBody(true), b.accessToken(false), "resubscribe-workspace"); w.Code != 201 {
		t.Fatalf("resubscribe: %d %s", w.Code, w.Body)
	}
}

func TestBillingPolicyPostgresSummaryAndStaleGrace(t *testing.T) {
	b := newBillingReviewFixture(t)
	id := kernel.NewID().String()
	b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri) VALUES($1,$2,'workspace',$3,$4,$5,'completed','{}','https://client.example.test/callback','https://client.example.test/callback')`, id, b.application, b.workspace, b.price, b.provider)
	first := time.Now().Add(-48 * time.Hour).UTC()
	for _, v := range []struct {
		status string
		at     time.Time
	}{{"past_due", first}, {"past_due", first.Add(time.Hour)}, {"active", first.Add(24 * time.Hour)}, {"past_due", first.Add(2 * time.Hour)}} {
		ctx := context.WithValue(context.Background(), stripeObservationTime{}, v.at)
		if err := b.s.normalizeStripeSubscription(ctx, b.application, b.provider, b.subscription(id, v.status, true)); err != nil {
			t.Fatal(err)
		}
	}
	var status string
	var since *time.Time
	if err := b.app.DB.QueryRow(context.Background(), `SELECT status,past_due_since FROM subscriptions WHERE application_id=$1`, b.application).Scan(&status, &since); err != nil || status != "active" || since != nil {
		t.Fatalf("stale failure restored grace: %s %v %v", status, since, err)
	}
	r := httptest.NewRequest("GET", "/v1/applications/"+b.application+"/subjects/workspace/"+b.workspace+"/billing", nil)
	r.Header.Set("Authorization", "Bearer "+b.machineToken())
	w := httptest.NewRecorder()
	b.router.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("summary: %d %s", w.Code, w.Body)
	}
	spec, err := generated.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err = json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if err = spec.Components.Schemas["SubjectBillingSummary"].Value.VisitJSON(value); err != nil {
		t.Fatalf("summary contract: %v body=%s", err, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"provider_subscription_id":"sub_fixture"`) {
		t.Fatal("summary lacks provider identifier")
	}
}

func TestBillingPolicyPostgresProviderFailures(t *testing.T) {
	for _, status := range []int{400, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			b := newBillingReviewFixture(t)
			calls := 0
			var firstKey string
			http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if firstKey == "" {
					firstKey = r.Header.Get("Idempotency-Key")
				}
				if calls == 1 {
					return billingProviderJSON(map[string]any{"error": "fixture rejection"}, status), nil
				}
				if status == 500 && r.Header.Get("Idempotency-Key") != firstKey {
					t.Error("unknown outcome replay used a new provider key")
				}
				return billingProviderJSON(map[string]any{"id": "cs_recovered", "url": "https://checkout.stripe.com/recovered", "status": "open"}, 200), nil
			})
			token := b.accessToken(false)
			if w := b.jsonCall("/billing/checkout-sessions", b.checkoutBody(false), token, "provider-recovery"); w.Code != 502 {
				t.Fatalf("initial failure: %d %s", w.Code, w.Body)
			}
			var stored string
			if err := b.app.DB.QueryRow(context.Background(), `SELECT status FROM checkout_sessions WHERE application_id=$1`, b.application).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			want := "pending"
			if status == 400 {
				want = "failed"
			}
			if stored != want {
				t.Fatalf("provider %d => %s, want %s", status, stored, want)
			}
			w := b.jsonCall("/billing/checkout-sessions", b.checkoutBody(false), token, "provider-recovery")
			wantCode := 200
			if status == 400 {
				wantCode = 201
			}
			if w.Code != wantCode {
				t.Fatalf("recovery: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestBillingPolicyPostgresEligibilityAndArchive(t *testing.T) {
	b := newBillingReviewFixture(t)
	ctx := context.Background()
	request := requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": b.application}, kernel.Actor{Type: "user", ID: b.user})
	for _, status := range []string{"active", "trialing", "past_due", "paused", "incomplete", "unpaid", "canceled"} {
		sub := kernel.NewID().String()
		b.exec(`INSERT INTO subscriptions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,provider_subscription_id,status,trial_end) VALUES($1,$2,'user',$3,$4,$5,$1::uuid::text,$6,now()-interval '1 day')`, sub, b.application, b.user, b.price, b.provider, status)
		w := httptest.NewRecorder()
		policy := map[string]any{"single_subscription": true, "trial_once_per_subject": true, "trial_period_days": 7}
		tx, ok := b.s.guardRecurringCheckout(w, request, "user", b.user, b.product, b.price, policy)
		if ok != (status == "canceled") {
			t.Fatalf("single subscription status=%s accepted=%v response=%s", status, ok, w.Body)
		}
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		w = httptest.NewRecorder()
		policy = map[string]any{"trial_once_per_subject": true, "trial_period_days": 7}
		tx, ok = b.s.guardRecurringCheckout(w, request, "user", b.user, b.product, b.price, policy)
		if !ok || policy["trial_period_days"] != nil {
			t.Fatalf("trial-only policy blocked paid enrollment or repeated trial: %s %s", status, w.Body)
		}
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		b.exec(`DELETE FROM subscriptions WHERE id=$1`, sub)
	}
	// Unresolved outcomes do not become safe merely by aging past a day.
	id := kernel.NewID().String()
	b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri,created_at) VALUES($1,$2,'workspace',$3,$4,$5,'pending','{}','https://client.example.test/callback','https://client.example.test/callback',now()-interval '27 hours')`, id, b.application, b.workspace, b.price, b.provider)
	w := httptest.NewRecorder()
	tx, ok := b.s.guardRecurringCheckout(w, request, "workspace", b.workspace, b.product, b.price, map[string]any{"single_subscription": true})
	if tx != nil {
		_ = tx.Rollback(ctx)
	}
	if ok || w.Code != 409 {
		t.Fatalf("aged pending checkout ignored: %d", w.Code)
	}
	if w = b.controlJSON("DELETE", "/workspaces/"+b.workspace, nil); w.Code != 409 {
		t.Fatalf("archive with pending billing: %d %s", w.Code, w.Body)
	}
	b.exec(`UPDATE checkout_sessions SET status='expired' WHERE id=$1`, id)
	if w = b.controlJSON("DELETE", "/workspaces/"+b.workspace, nil); w.Code != 204 {
		t.Fatalf("settled archive: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	tx, ok = b.s.guardRecurringCheckout(w, request, "workspace", b.workspace, b.product, b.price, map[string]any{})
	if tx != nil {
		_ = tx.Rollback(ctx)
	}
	if ok {
		t.Fatal("archived workspace can checkout")
	}
}

func TestBillingPolicyPostgresCheckoutExpiration(t *testing.T) {
	for _, mode := range []string{"recurring", "one_time"} {
		t.Run(mode, func(t *testing.T) {
			b := newBillingReviewFixture(t)
			if mode == "one_time" {
				b.exec(`UPDATE prices SET mode='one_time',interval_unit=NULL,interval_count=NULL,checkout_config='{}' WHERE id=$1`, b.price)
			}
			id := kernel.NewID().String()
			b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,provider_session_id,status,policy_snapshot,success_uri,cancel_uri) VALUES($1,$2,'workspace',$3,$4,$5,'cs_expiration','open','{}','https://client.example.test/callback','https://client.example.test/callback')`, id, b.application, b.workspace, b.price, b.provider)
			expired := false
			http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/expire") {
					expired = true
				}
				return billingProviderJSON(map[string]any{"id": "cs_expiration", "url": "https://checkout.stripe.com/expiration", "status": "open", "client_reference_id": id}, 200), nil
			})
			w := b.jsonCall("/subjects/workspace/"+b.workspace+"/billing/cancel", map[string]any{}, b.machineToken(), "expire-workspace-checkout")
			if w.Code != 204 || !expired {
				t.Fatalf("expire %s: %d %s", mode, w.Code, w.Body)
			}
			var stored string
			_ = b.app.DB.QueryRow(context.Background(), `SELECT status FROM checkout_sessions WHERE id=$1`, id).Scan(&stored)
			if stored != "expired" {
				t.Fatalf("expiration persisted %s", stored)
			}
		})
	}
}

func TestBillingPolicyPostgresResolutionAndArchiveRaces(t *testing.T) {
	b := newBillingReviewFixture(t)
	id := kernel.NewID().String()
	b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri,created_at,provider_request) VALUES($1,$2,'workspace',$3,$4,$5,'pending','{}','https://client.example.test/callback','https://client.example.test/callback',now()-interval '26 hours','{"customer":["cus_workspace"]}')`, id, b.application, b.workspace, b.price, b.provider)
	posts := 0
	http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			posts++
			return billingProviderJSON(map[string]any{"id": "cs_new", "status": "open", "url": "https://checkout.stripe.com/new"}, 200), nil
		}
		return billingProviderJSON(map[string]any{"data": []any{}, "has_more": false}, 200), nil
	})
	w := b.jsonCall("/billing/checkout-sessions", b.checkoutBody(true), b.accessToken(false), "unknown-outcome")
	if w.Code != 503 || posts != 0 {
		t.Fatalf("old provider key was recreated: %d posts=%d", w.Code, posts)
	}
	path := "/billing/checkout-sessions/" + id + "/resolve-not-created"
	if w = b.controlJSON("POST", path, map[string]any{"confirm_no_provider_session": false, "reason": "Provider investigation completed"}); w.Code != 422 {
		t.Fatalf("unconfirmed resolution: %d", w.Code)
	}
	body := map[string]any{"confirm_no_provider_session": true, "reason": "Provider investigation confirmed no session was created"}
	if w = b.controlJSON("POST", path, body); w.Code != 204 {
		t.Fatalf("resolution: %d %s", w.Code, w.Body)
	}
	if w = b.controlJSON("POST", path, body); w.Code != 204 {
		t.Fatalf("resolution retry: %d %s", w.Code, w.Body)
	}
	var audits int
	if err := b.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_records WHERE application_id=$1 AND target_id=$2 AND action='billing.checkout.resolved_not_created'`, b.application, id).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("resolution audit: %d %v", audits, err)
	}
	if w = b.jsonCall("/billing/checkout-sessions", b.checkoutBody(true), b.accessToken(false), "after-resolution"); w.Code != 201 {
		t.Fatalf("checkout after resolution: %d %s", w.Code, w.Body)
	}
	// A completed checkout is still unsettled until its subscription is known.
	b.exec(`UPDATE checkout_sessions SET status='completed' WHERE application_id=$1`, b.application)
	if w = b.controlJSON("DELETE", "/workspaces/"+b.workspace, nil); w.Code != 409 {
		t.Fatalf("archive before subscription webhook: %d %s", w.Code, w.Body)
	}
}

func TestBillingPolicyPostgresAbandonedPreparationCancellation(t *testing.T) {
	b := newBillingReviewFixture(t)
	id := kernel.NewID().String()
	b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri,created_at) VALUES($1,$2,'workspace',$3,$4,$5,'pending','{}','https://client.example.test/callback','https://client.example.test/callback',now()-interval '2 minutes')`, id, b.application, b.workspace, b.price, b.provider)
	http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
		t.Error("abandoned preparation contacted provider")
		return nil, fmt.Errorf("unexpected provider call")
	})
	w := b.jsonCall("/subjects/workspace/"+b.workspace+"/billing/cancel", map[string]any{}, b.machineToken(), "cancel-preparation")
	if w.Code != 204 {
		t.Fatalf("first cancellation of abandoned preparation: %d %s", w.Code, w.Body)
	}
}

func TestBillingPolicyPostgresResolutionAuthorizationAndAtomicity(t *testing.T) {
	b := newBillingReviewFixture(t)
	id := kernel.NewID().String()
	b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri,created_at) VALUES($1,$2,'workspace',$3,$4,$5,'pending','{}','https://client.example.test/callback','https://client.example.test/callback',now()-interval '26 hours')`, id, b.application, b.workspace, b.price, b.provider)
	body := map[string]any{"confirm_no_provider_session": true, "reason": "Provider investigation confirmed no session was created"}
	path := "/billing/checkout-sessions/" + id + "/resolve-not-created"
	b.exec(`UPDATE organization_memberships SET role='auditor' WHERE control_user_id=$1`, b.controlUser)
	if w := b.controlJSON("POST", path, body); w.Code != 403 {
		t.Fatalf("auditor resolved billing: %d %s", w.Code, w.Body)
	}
	b.exec(`UPDATE organization_memberships SET role='admin' WHERE control_user_id=$1`, b.controlUser)
	for _, state := range []struct {
		status   string
		external *string
		age      string
	}{{"pending", nil, "1 hour"}, {"completed", nil, "26 hours"}, {"pending", func() *string { v := "cs_known"; return &v }(), "26 hours"}} {
		b.exec(`UPDATE checkout_sessions SET status=$1,provider_session_id=$2,created_at=now()-$3::interval WHERE id=$4`, state.status, state.external, state.age, id)
		if w := b.controlJSON("POST", path, body); w.Code != 409 {
			t.Fatalf("unsafe resolution state=%+v: %d %s", state, w.Code, w.Body)
		}
	}
	b.exec(`UPDATE checkout_sessions SET status='pending',provider_session_id=NULL,created_at=now()-interval '26 hours' WHERE id=$1`, id)
	b.exec(`CREATE FUNCTION reject_resolution_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='billing.checkout.resolved_not_created' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$`)
	b.exec(`CREATE TRIGGER reject_resolution BEFORE INSERT ON audit_records FOR EACH ROW EXECUTE FUNCTION reject_resolution_audit()`)
	if w := b.controlJSON("POST", path, body); w.Code != 503 {
		t.Fatalf("unaudited resolution accepted: %d %s", w.Code, w.Body)
	}
	var status string
	if err := b.app.DB.QueryRow(context.Background(), `SELECT status FROM checkout_sessions WHERE id=$1`, id).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("audit failure did not roll back: %s %v", status, err)
	}
}

func TestBillingPolicyPostgresUpgradeFromReleasedSchema(t *testing.T) {
	b := newBillingReviewFixture(t)
	db, err := sql.Open("pgx", b.app.DB.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = goose.DownTo(db, ".", 8); err != nil {
		t.Fatal(err)
	}
	id := kernel.NewID().String()
	b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri) VALUES($1,$2,'workspace',$3,$4,$5,'pending','{}','https://client.example.test/callback','https://client.example.test/callback')`, id, b.application, b.workspace, b.price, b.provider)
	if err = goose.Up(db, "."); err != nil {
		t.Fatal(err)
	}
	var preserved bool
	if err = b.app.DB.QueryRow(context.Background(), `SELECT provider_request='{"legacy_unknown":true}'::jsonb FROM checkout_sessions WHERE id=$1`, id).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("upgrade treated unknown legacy outcome as unsent: %v %v", preserved, err)
	}
	if err = goose.DownTo(db, ".", 8); err != nil {
		t.Fatal(err)
	}
	if err = goose.Up(db, "."); err != nil {
		t.Fatal(err)
	}
}

func TestBillingPolicyPostgresCancelBeforeSubscriptionWebhook(t *testing.T) {
	b := newBillingReviewFixture(t)
	id := kernel.NewID().String()
	b.exec(`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri,provider_session_id) VALUES($1,$2,'workspace',$3,$4,$5,'completed','{}','https://client.example.test/callback','https://client.example.test/callback','cs_completed')`, id, b.application, b.workspace, b.price, b.provider)
	cancelled := false
	http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/checkout/sessions/cs_completed" {
			return billingProviderJSON(map[string]any{"id": "cs_completed", "status": "complete", "client_reference_id": id, "subscription": b.subscription(id, "active", true)}, 200), nil
		}
		if r.Method == "DELETE" && r.URL.Path == "/v1/subscriptions/sub_fixture" {
			cancelled = true
			return billingProviderJSON(b.subscription(id, "canceled", true), 200), nil
		}
		return nil, fmt.Errorf("unexpected provider call")
	})
	w := b.jsonCall("/subjects/workspace/"+b.workspace+"/billing/cancel", map[string]any{"at_period_end": false}, b.machineToken(), "cancel-before-webhook")
	if w.Code != 204 || !cancelled {
		t.Fatalf("cancel lost completed enrollment: %d %s cancelled=%v", w.Code, w.Body, cancelled)
	}
	if w = b.controlJSON("DELETE", "/workspaces/"+b.workspace, nil); w.Code != 204 {
		t.Fatalf("settled workspace cannot archive: %d %s", w.Code, w.Body)
	}
}
