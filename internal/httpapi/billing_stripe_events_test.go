package httpapi

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestStripeEventsNormalizeOutOfOrder(t *testing.T) {
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

	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	productID, priceID, connectionID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	customerID, checkoutID, subjectID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	providerCiphertext, err := vault.Encrypt([]byte("sk_test"), "billing-provider:"+connectionID.String()+":secret")
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Test',$2)`, []any{organizationID, "test-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Test',$3)`, []any{applicationID, organizationID, "test-" + suffix}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{subjectID, applicationID, "billing-" + suffix + "@example.test"}},
		{`INSERT INTO products(id,application_id,key,name) VALUES($1,$2,$3,'Recurring')`, []any{productID, applicationID, "product-" + suffix}},
		{`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency,interval_unit,interval_count) VALUES($1,$2,$3,$4,'recurring',1000,'CHF','month',1)`, []any{priceID, applicationID, productID, "price-" + suffix}},
		{`INSERT INTO provider_connections(id,application_id,provider,public_id,api_version,secret_ciphertext) VALUES($1,$2,'stripe',$3,$4,$5)`, []any{connectionID, applicationID, "stripe_" + suffix, stripeAPIVersion, providerCiphertext}},
		{`INSERT INTO billing_customers(id,application_id,subject_type,subject_id,provider_connection_id,provider_customer_id) VALUES($1,$2,'user',$3,$4,'cus_test')`, []any{customerID, applicationID, subjectID, connectionID}},
		{`INSERT INTO checkout_sessions(id,application_id,subject_type,subject_id,price_id,provider_connection_id,status,policy_snapshot,success_uri,cancel_uri) VALUES($1,$2,'user',$3,$4,$5,'open','{}','https://app.test/success','https://app.test/cancel')`, []any{checkoutID, applicationID, subjectID, priceID, connectionID}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	providerRequest := requestWithRoute(t, "POST", "/", nil, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "user", ID: subjectID.String()})
	providerResponse := httptest.NewRecorder()
	resolvedProviderID, secret, version, ok := server.billingProviderSecretByID(providerResponse, providerRequest, "")
	if !ok || resolvedProviderID != connectionID.String() || secret != "sk_test" || version != stripeAPIVersion {
		t.Fatalf("default billing provider was not resolved: id=%q secret=%q version=%q status=%d", resolvedProviderID, secret, version, providerResponse.Code)
	}
	resolvedApplicationID, err := server.stripeEventApplicationFromRecords(ctx, connectionID.String(), "invoice.paid", map[string]any{"id": "unknown", "customer": "cus_test"})
	if err != nil || resolvedApplicationID != applicationID.String() {
		t.Fatalf("shared provider event was not attributed through its customer: application=%q err=%v", resolvedApplicationID, err)
	}

	if err = server.normalizeStripeRefund(ctx, applicationID.String(), connectionID.String(), map[string]any{
		"id": "re_test", "payment_intent": "pi_test", "status": "succeeded", "amount": float64(500), "currency": "chf",
	}); err != nil {
		t.Fatal(err)
	}
	if err = server.normalizeStripeDispute(ctx, applicationID.String(), connectionID.String(), map[string]any{
		"id": "dp_test", "payment_intent": "pi_test", "status": "needs_response", "amount": float64(1000), "currency": "chf",
		"evidence_details": map[string]any{"due_by": float64(1_900_000_000)},
	}); err != nil {
		t.Fatal(err)
	}
	if err = server.normalizeStripePayment(ctx, applicationID.String(), connectionID.String(), map[string]any{
		"id": "pi_test", "customer": "cus_test", "invoice": "in_test", "status": "succeeded", "amount": float64(1000),
		"amount_received": float64(1000), "currency": "chf", "payment_method_types": []any{"card"},
		"metadata": map[string]any{"platform93_checkout_id": checkoutID.String()},
	}); err != nil {
		t.Fatal(err)
	}
	if err = server.normalizeStripeInvoice(ctx, applicationID.String(), connectionID.String(), map[string]any{
		"id": "in_test", "customer": "cus_test", "status": "paid", "amount_due": float64(1000), "amount_paid": float64(1000),
		"currency": "chf", "parent": map[string]any{"subscription_details": map[string]any{"subscription": "sub_test"}},
		"status_transitions": map[string]any{"paid_at": float64(1_800_000_000)},
	}); err != nil {
		t.Fatal(err)
	}
	periodStart, periodEnd := int64(1_800_000_000), int64(1_802_592_000)
	if err = server.normalizeStripeSubscription(ctx, applicationID.String(), connectionID.String(), map[string]any{
		"id": "sub_test", "status": "active", "cancel_at_period_end": false,
		"metadata": map[string]any{"platform93_checkout_id": checkoutID.String()},
		"items":    map[string]any{"data": []any{map[string]any{"id": "si_test", "current_period_start": float64(periodStart), "current_period_end": float64(periodEnd)}}},
	}); err != nil {
		t.Fatal(err)
	}

	var refundLinked, disputeLinked, paymentInvoiceLinked, invoiceSubscriptionLinked bool
	if err = db.QueryRow(ctx, `SELECT
(SELECT payment_id IS NOT NULL FROM refunds WHERE provider_refund_id='re_test' AND application_id=$1),
(SELECT payment_id IS NOT NULL FROM disputes WHERE provider_dispute_id='dp_test' AND application_id=$1),
(SELECT invoice_id IS NOT NULL FROM payments WHERE provider_payment_id='pi_test' AND application_id=$1),
(SELECT subscription_id IS NOT NULL FROM invoices WHERE provider_invoice_id='in_test' AND application_id=$1)`, applicationID).
		Scan(&refundLinked, &disputeLinked, &paymentInvoiceLinked, &invoiceSubscriptionLinked); err != nil {
		t.Fatal(err)
	}
	if !refundLinked || !disputeLinked || !paymentInvoiceLinked || !invoiceSubscriptionLinked {
		t.Fatalf("relationships not repaired: refund=%v dispute=%v payment_invoice=%v invoice_subscription=%v", refundLinked, disputeLinked, paymentInvoiceLinked, invoiceSubscriptionLinked)
	}
	var storedStart, storedEnd time.Time
	var grants int
	if err = db.QueryRow(ctx, `SELECT current_period_start,current_period_end,
(SELECT count(*) FROM entitlement_grants WHERE application_id=$1 AND source_type='subscription')
FROM subscriptions WHERE application_id=$1 AND provider_subscription_id='sub_test'`, applicationID).Scan(&storedStart, &storedEnd, &grants); err != nil {
		t.Fatal(err)
	}
	if storedStart.Unix() != periodStart || storedEnd.Unix() != periodEnd || grants != 1 {
		t.Fatalf("unexpected period or grants: %s %s %d", storedStart, storedEnd, grants)
	}
	if err = server.normalizeStripeSubscription(ctx, applicationID.String(), connectionID.String(), map[string]any{
		"id": "sub_test", "status": "active", "metadata": map[string]any{"platform93_checkout_id": checkoutID.String()},
		"items": map[string]any{"data": []any{map[string]any{"id": "si_test", "current_period_start": float64(periodStart), "current_period_end": float64(periodEnd)}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM entitlement_grants WHERE application_id=$1 AND source_type='subscription'`, applicationID).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("subscription replay was not idempotent: grants=%d err=%v", grants, err)
	}
	terminal := map[string]any{
		"id": "sub_test", "status": "canceled", "metadata": map[string]any{"platform93_checkout_id": checkoutID.String()},
		"items": map[string]any{"data": []any{map[string]any{"id": "si_test", "current_period_start": float64(periodStart), "current_period_end": float64(periodEnd)}}},
	}
	if err = server.normalizeStripeSubscription(ctx, applicationID.String(), connectionID.String(), terminal); err != nil {
		t.Fatal(err)
	}
	if err = server.normalizeStripeSubscription(ctx, applicationID.String(), connectionID.String(), terminal); err != nil {
		t.Fatal(err)
	}
	var latestAction string
	var legacyRevoked *time.Time
	var actionCount int
	if err = db.QueryRow(ctx, `SELECT g.revoked_at,
(SELECT action FROM entitlement_grant_actions WHERE grant_id=g.id ORDER BY created_at DESC,id DESC LIMIT 1),
(SELECT count(*) FROM entitlement_grant_actions WHERE grant_id=g.id)
FROM entitlement_grants g WHERE g.application_id=$1 AND g.source_type='subscription'`, applicationID).Scan(&legacyRevoked, &latestAction, &actionCount); err != nil {
		t.Fatal(err)
	}
	if legacyRevoked != nil || latestAction != "revoked" || actionCount != 2 {
		t.Fatalf("provider revocation was not append-only/idempotent: legacy=%v action=%s count=%d", legacyRevoked, latestAction, actionCount)
	}
	newPeriodEnd := periodEnd + 2_592_000
	if err = server.normalizeStripeSubscription(ctx, applicationID.String(), connectionID.String(), map[string]any{
		"id": "sub_test", "status": "active", "metadata": map[string]any{"platform93_checkout_id": checkoutID.String()},
		"items": map[string]any{"data": []any{map[string]any{"id": "si_test", "current_period_start": float64(periodEnd), "current_period_end": float64(newPeriodEnd)}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT action FROM entitlement_grant_actions a JOIN entitlement_grants g ON g.id=a.grant_id
WHERE g.application_id=$1 AND g.source_type='subscription' ORDER BY a.created_at DESC,a.id DESC LIMIT 1`, applicationID).Scan(&latestAction); err != nil || latestAction != "restored" {
		t.Fatalf("provider reactivation was not append-only: action=%s err=%v", latestAction, err)
	}
}
