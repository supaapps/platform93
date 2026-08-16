package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) normalizeStripeCheckout(ctx context.Context, applicationID, connectionID string, object map[string]any, completed bool) error {
	checkoutID := metadataString(object, "platform93_checkout_id")
	if checkoutID == "" {
		checkoutID = stringValue(object["client_reference_id"])
	}
	if checkoutID == "" {
		return nil
	}
	status := "expired"
	if completed {
		status = "completed"
	}
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var mode, subjectType, subjectID, productID, priceID string
	var externalReference *string
	var validity *int64
	err = tx.QueryRow(ctx, `UPDATE checkout_sessions c SET status=$1,provider_session_id=COALESCE(NULLIF($2,''),provider_session_id),updated_at=now()
FROM prices pr WHERE c.id=$3 AND c.application_id=$4 AND pr.id=c.price_id
RETURNING pr.mode,c.subject_type,c.subject_id,pr.product_id,pr.id,pr.validity_seconds,c.external_reference`, status, stringValue(object["id"]), checkoutID, applicationID).
		Scan(&mode, &subjectType, &subjectID, &productID, &priceID, &validity, &externalReference)
	if err != nil {
		return fmt.Errorf("resolve checkout %s: %w", checkoutID, err)
	}
	if completed && mode == "one_time" {
		paymentStatus := stringValue(object["payment_status"])
		if paymentStatus == "paid" || paymentStatus == "no_payment_required" {
			var expires *time.Time
			if validity != nil {
				value := s.app.Now().Add(time.Duration(*validity) * time.Second)
				expires = &value
			}
			if err = s.upsertProviderGrant(ctx, tx, applicationID, subjectType, subjectID, productID, priceID, "one_time", checkoutID, externalReference, expires, false); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func (s *Server) normalizeStripeSubscription(ctx context.Context, applicationID, connectionID string, object map[string]any) error {
	providerSubscriptionID := stringValue(object["id"])
	if providerSubscriptionID == "" {
		return fmt.Errorf("Stripe subscription is missing id")
	}
	checkoutID := metadataString(object, "platform93_checkout_id")
	var subjectType, subjectID, priceID string
	var externalReference *string
	if checkoutID != "" {
		_ = s.app.DB.QueryRow(ctx, `SELECT subject_type,subject_id,price_id,external_reference FROM checkout_sessions
WHERE id=$1 AND application_id=$2 AND provider_connection_id=$3`, checkoutID, applicationID, connectionID).
			Scan(&subjectType, &subjectID, &priceID, &externalReference)
	}
	if priceID == "" {
		_ = s.app.DB.QueryRow(ctx, `SELECT subject_type,subject_id,price_id FROM subscriptions
WHERE provider_connection_id=$1 AND provider_subscription_id=$2`, connectionID, providerSubscriptionID).
			Scan(&subjectType, &subjectID, &priceID)
	}
	if priceID == "" {
		return nil
	}
	item := firstStripeListObject(object["items"])
	providerItemID := stringValue(item["id"])
	if mappedPriceID := s.internalProviderMapping(ctx, connectionID, "price", stripeObjectID(item["price"])); mappedPriceID != "" {
		priceID = mappedPriceID
	}
	periodStart := unixTimeValue(item["current_period_start"])
	periodEnd := unixTimeValue(item["current_period_end"])
	if periodStart == nil {
		periodStart = unixTimeValue(object["current_period_start"])
	}
	if periodEnd == nil {
		periodEnd = unixTimeValue(object["current_period_end"])
	}
	status := stringValue(object["status"])
	if status == "" {
		status = "unknown"
	}
	metadata, _ := json.Marshal(mapValue(object["metadata"]))
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var subscriptionID, productID string
	err = tx.QueryRow(ctx, `INSERT INTO subscriptions
(id,application_id,subject_type,subject_id,price_id,provider_connection_id,provider_subscription_id,provider_item_id,status,
current_period_start,current_period_end,cancel_at,canceled_at,trial_end,cancel_at_period_end,metadata,external_reference)
VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12,$13,$14,$15,$16,$17)
ON CONFLICT(provider_connection_id,provider_subscription_id) DO UPDATE SET
price_id=EXCLUDED.price_id,provider_item_id=COALESCE(EXCLUDED.provider_item_id,subscriptions.provider_item_id),status=EXCLUDED.status,
current_period_start=EXCLUDED.current_period_start,current_period_end=EXCLUDED.current_period_end,cancel_at=EXCLUDED.cancel_at,
canceled_at=EXCLUDED.canceled_at,trial_end=EXCLUDED.trial_end,cancel_at_period_end=EXCLUDED.cancel_at_period_end,
metadata=EXCLUDED.metadata,external_reference=COALESCE(EXCLUDED.external_reference,subscriptions.external_reference),updated_at=now() RETURNING id`, kernel.NewID(), applicationID, subjectType, subjectID, priceID,
		connectionID, providerSubscriptionID, providerItemID, status, periodStart, periodEnd, unixTimeValue(object["cancel_at"]),
		unixTimeValue(object["canceled_at"]), unixTimeValue(object["trial_end"]), boolValue(object["cancel_at_period_end"]), metadata, externalReference).
		Scan(&subscriptionID)
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT product_id FROM prices WHERE id=$1 AND application_id=$2`, priceID, applicationID).Scan(&productID)
	}
	if err != nil {
		return err
	}
	active := status == "active" || status == "trialing" || status == "past_due"
	if err = s.upsertProviderGrant(ctx, tx, applicationID, subjectType, subjectID, productID, priceID, "subscription", subscriptionID, externalReference, periodEnd, !active); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE invoices SET subscription_id=$1,
external_reference=COALESCE(external_reference,$4),updated_at=now()
WHERE provider_connection_id=$2 AND provider_subscription_id=$3
AND (subscription_id IS NULL OR external_reference IS NULL)`, subscriptionID, connectionID, providerSubscriptionID, externalReference); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE payments p SET external_reference=COALESCE(p.external_reference,i.external_reference),updated_at=now()
FROM invoices i WHERE p.invoice_id=i.id AND i.subscription_id=$1 AND p.external_reference IS NULL`, subscriptionID); err != nil {
		return err
	}
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if parseErr != nil {
		return parseErr
	}
	if _, err = s.app.Emit(ctx, tx, &parsedApplicationID, "billing.subscription.updated", "subscription/"+subscriptionID, map[string]any{"type": "provider"}, map[string]any{"subscription_id": subscriptionID, "status": status, "subject_type": subjectType, "subject_id": subjectID, "external_reference": externalReference}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) normalizeStripeInvoice(ctx context.Context, applicationID, connectionID string, object map[string]any) error {
	providerInvoiceID := stringValue(object["id"])
	if providerInvoiceID == "" {
		return fmt.Errorf("Stripe invoice is missing id")
	}
	customerID := s.billingCustomerID(ctx, connectionID, stripeObjectID(object["customer"]))
	providerSubscriptionID := stripeObjectID(nestedValue(object, "parent", "subscription_details", "subscription"))
	if providerSubscriptionID == "" {
		providerSubscriptionID = stripeObjectID(object["subscription"])
	}
	subscriptionID := s.subscriptionID(ctx, connectionID, providerSubscriptionID)
	status := stringValue(object["status"])
	if status == "" {
		status = "draft"
	}
	providerCustomerID := stripeObjectID(object["customer"])
	externalReference := metadataString(object, "platform93_external_reference")
	if externalReference == "" && subscriptionID != nil {
		_ = s.app.DB.QueryRow(ctx, `SELECT COALESCE(external_reference,'') FROM subscriptions WHERE id=$1`, *subscriptionID).Scan(&externalReference)
	}
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var invoiceID string
	err = tx.QueryRow(ctx, `INSERT INTO invoices
(id,application_id,provider_connection_id,provider_invoice_id,provider_customer_id,provider_subscription_id,billing_customer_id,subscription_id,status,
amount_due_minor,amount_paid_minor,tax_minor,currency,due_at,paid_at,hosted_uri,external_reference)
VALUES($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10,$11,$12,upper($13),$14,$15,NULLIF($16,''),NULLIF($17,''))
ON CONFLICT(provider_connection_id,provider_invoice_id) DO UPDATE SET
provider_customer_id=COALESCE(EXCLUDED.provider_customer_id,invoices.provider_customer_id),
provider_subscription_id=COALESCE(EXCLUDED.provider_subscription_id,invoices.provider_subscription_id),
billing_customer_id=COALESCE(EXCLUDED.billing_customer_id,invoices.billing_customer_id),
subscription_id=COALESCE(EXCLUDED.subscription_id,invoices.subscription_id),status=EXCLUDED.status,
amount_due_minor=EXCLUDED.amount_due_minor,amount_paid_minor=EXCLUDED.amount_paid_minor,tax_minor=EXCLUDED.tax_minor,
currency=EXCLUDED.currency,due_at=EXCLUDED.due_at,paid_at=EXCLUDED.paid_at,hosted_uri=EXCLUDED.hosted_uri,
external_reference=COALESCE(EXCLUDED.external_reference,invoices.external_reference),updated_at=now() RETURNING id`,
		kernel.NewID(), applicationID, connectionID, providerInvoiceID, providerCustomerID, providerSubscriptionID, customerID, subscriptionID, status,
		int64Number(object["amount_due"]), int64Number(object["amount_paid"]), stripeTaxAmount(object), normalizedCurrency(object["currency"]),
		unixTimeValue(object["due_date"]), unixTimeValue(nestedValue(object, "status_transitions", "paid_at")), stringValue(object["hosted_invoice_url"]), externalReference).Scan(&invoiceID)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE payments p SET invoice_id=i.id,external_reference=COALESCE(p.external_reference,i.external_reference),updated_at=now() FROM invoices i
WHERE i.provider_connection_id=$1 AND i.provider_invoice_id=$2 AND p.provider_connection_id=i.provider_connection_id
AND p.provider_invoice_id=i.provider_invoice_id AND p.invoice_id IS NULL`, connectionID, providerInvoiceID)
	}
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(ctx, tx, &parsedApplicationID, "billing.invoice.updated", "invoice/"+invoiceID, map[string]any{"type": "provider"}, map[string]any{"invoice_id": invoiceID, "status": status, "external_reference": nullableString(externalReference)})
	}
	if err != nil {
		return err
	}
	if parseErr != nil {
		return parseErr
	}
	return tx.Commit(ctx)
}

func (s *Server) normalizeStripePayment(ctx context.Context, applicationID, connectionID string, object map[string]any) error {
	providerPaymentID := stringValue(object["id"])
	if providerPaymentID == "" {
		return fmt.Errorf("Stripe payment intent is missing id")
	}
	checkoutID := s.checkoutSessionID(ctx, applicationID, connectionID, metadataString(object, "platform93_checkout_id"))
	providerInvoiceID := stripeObjectID(object["invoice"])
	invoiceID := s.invoiceID(ctx, connectionID, providerInvoiceID)
	providerCustomerID := stripeObjectID(object["customer"])
	method := firstString(object["payment_method_types"])
	if method == "" {
		method = stringValue(nestedValue(object, "latest_charge", "payment_method_details", "type"))
	}
	failureCode := stringValue(nestedValue(object, "last_payment_error", "code"))
	failureMessage := stringValue(nestedValue(object, "last_payment_error", "message"))
	externalReference := metadataString(object, "platform93_external_reference")
	if externalReference == "" && checkoutID != nil {
		_ = s.app.DB.QueryRow(ctx, `SELECT COALESCE(external_reference,'') FROM checkout_sessions WHERE id=$1`, *checkoutID).Scan(&externalReference)
	}
	if externalReference == "" && invoiceID != nil {
		_ = s.app.DB.QueryRow(ctx, `SELECT COALESCE(external_reference,'') FROM invoices WHERE id=$1`, *invoiceID).Scan(&externalReference)
	}
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var paymentID string
	err = tx.QueryRow(ctx, `INSERT INTO payments
(id,application_id,provider_connection_id,provider_payment_id,provider_customer_id,provider_invoice_id,billing_customer_id,checkout_session_id,invoice_id,status,
amount_minor,amount_received_minor,currency,payment_method_type,failure_code,failure_message,external_reference)
VALUES($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10,$11,$12,upper($13),NULLIF($14,''),NULLIF($15,''),NULLIF($16,''),NULLIF($17,''))
ON CONFLICT(provider_connection_id,provider_payment_id) DO UPDATE SET
provider_customer_id=COALESCE(EXCLUDED.provider_customer_id,payments.provider_customer_id),
provider_invoice_id=COALESCE(EXCLUDED.provider_invoice_id,payments.provider_invoice_id),
billing_customer_id=COALESCE(EXCLUDED.billing_customer_id,payments.billing_customer_id),
checkout_session_id=COALESCE(EXCLUDED.checkout_session_id,payments.checkout_session_id),invoice_id=COALESCE(EXCLUDED.invoice_id,payments.invoice_id),
status=EXCLUDED.status,amount_minor=EXCLUDED.amount_minor,amount_received_minor=EXCLUDED.amount_received_minor,external_reference=COALESCE(EXCLUDED.external_reference,payments.external_reference),
currency=EXCLUDED.currency,payment_method_type=EXCLUDED.payment_method_type,failure_code=EXCLUDED.failure_code,
failure_message=EXCLUDED.failure_message,updated_at=now() RETURNING id`, kernel.NewID(), applicationID, connectionID, providerPaymentID,
		providerCustomerID, providerInvoiceID, s.billingCustomerID(ctx, connectionID, providerCustomerID), checkoutID, invoiceID, stringValue(object["status"]),
		int64Number(object["amount"]), int64Number(object["amount_received"]), normalizedCurrency(object["currency"]), method, failureCode, failureMessage, externalReference).Scan(&paymentID)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE refunds r SET payment_id=p.id,updated_at=now() FROM payments p
WHERE p.provider_connection_id=$1 AND p.provider_payment_id=$2 AND r.provider_connection_id=p.provider_connection_id
AND r.provider_payment_id=p.provider_payment_id AND r.payment_id IS NULL`, connectionID, providerPaymentID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE disputes d SET payment_id=p.id,updated_at=now() FROM payments p
WHERE p.provider_connection_id=$1 AND p.provider_payment_id=$2 AND d.provider_connection_id=p.provider_connection_id
AND d.provider_payment_id=p.provider_payment_id AND d.payment_id IS NULL`, connectionID, providerPaymentID)
	}
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(ctx, tx, &parsedApplicationID, "billing.payment.updated", "payment/"+paymentID, map[string]any{"type": "provider"}, map[string]any{"payment_id": paymentID, "status": stringValue(object["status"]), "external_reference": nullableString(externalReference)})
	}
	if err != nil {
		return err
	}
	if parseErr != nil {
		return parseErr
	}
	return tx.Commit(ctx)
}

func (s *Server) normalizeStripeRefund(ctx context.Context, applicationID, connectionID string, object map[string]any) error {
	providerRefundID := stringValue(object["id"])
	if providerRefundID == "" {
		return fmt.Errorf("Stripe refund is missing id")
	}
	paymentID := s.paymentID(ctx, connectionID, stripeObjectID(object["payment_intent"]))
	providerPaymentID := stripeObjectID(object["payment_intent"])
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var refundID string
	err = tx.QueryRow(ctx, `INSERT INTO refunds
(id,application_id,provider_connection_id,provider_payment_id,payment_id,provider_refund_id,status,amount_minor,currency,reason)
VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,upper($9),NULLIF($10,'')) ON CONFLICT(provider_connection_id,provider_refund_id) DO UPDATE SET
provider_payment_id=COALESCE(EXCLUDED.provider_payment_id,refunds.provider_payment_id),
payment_id=COALESCE(EXCLUDED.payment_id,refunds.payment_id),status=EXCLUDED.status,amount_minor=EXCLUDED.amount_minor,
currency=EXCLUDED.currency,reason=EXCLUDED.reason,updated_at=now() RETURNING id`, kernel.NewID(), applicationID, connectionID, providerPaymentID, paymentID,
		providerRefundID, stringValue(object["status"]), int64Number(object["amount"]), normalizedCurrency(object["currency"]), stringValue(object["reason"])).Scan(&refundID)
	var externalReference string
	if err == nil && paymentID != nil {
		_ = tx.QueryRow(ctx, `SELECT COALESCE(external_reference,'') FROM payments WHERE id=$1`, *paymentID).Scan(&externalReference)
	}
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(ctx, tx, &parsedApplicationID, "billing.refund.updated", "refund/"+refundID, map[string]any{"type": "provider"}, map[string]any{"refund_id": refundID, "status": stringValue(object["status"]), "external_reference": nullableString(externalReference)})
	}
	if err != nil {
		return err
	}
	if parseErr != nil {
		return parseErr
	}
	return tx.Commit(ctx)
}

func (s *Server) normalizeStripeDispute(ctx context.Context, applicationID, connectionID string, object map[string]any) error {
	providerDisputeID := stringValue(object["id"])
	if providerDisputeID == "" {
		return fmt.Errorf("Stripe dispute is missing id")
	}
	providerPaymentID := stripeObjectID(object["payment_intent"])
	if providerPaymentID == "" {
		providerPaymentID = stripeObjectID(nestedValue(object, "charge", "payment_intent"))
	}
	paymentID := s.paymentID(ctx, connectionID, providerPaymentID)
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var disputeID string
	err = tx.QueryRow(ctx, `INSERT INTO disputes
(id,application_id,provider_connection_id,provider_payment_id,payment_id,provider_dispute_id,status,amount_minor,currency,reason,evidence_due_at)
VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,upper($9),NULLIF($10,''),$11) ON CONFLICT(provider_connection_id,provider_dispute_id) DO UPDATE SET
provider_payment_id=COALESCE(EXCLUDED.provider_payment_id,disputes.provider_payment_id),
payment_id=COALESCE(EXCLUDED.payment_id,disputes.payment_id),status=EXCLUDED.status,amount_minor=EXCLUDED.amount_minor,
currency=EXCLUDED.currency,reason=EXCLUDED.reason,evidence_due_at=EXCLUDED.evidence_due_at,updated_at=now() RETURNING id`, kernel.NewID(), applicationID,
		connectionID, providerPaymentID, paymentID, providerDisputeID, stringValue(object["status"]),
		int64Number(object["amount"]), normalizedCurrency(object["currency"]), stringValue(object["reason"]), unixTimeValue(nestedValue(object, "evidence_details", "due_by"))).Scan(&disputeID)
	var externalReference string
	if err == nil && paymentID != nil {
		_ = tx.QueryRow(ctx, `SELECT COALESCE(external_reference,'') FROM payments WHERE id=$1`, *paymentID).Scan(&externalReference)
	}
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(ctx, tx, &parsedApplicationID, "billing.dispute.updated", "dispute/"+disputeID, map[string]any{"type": "provider"}, map[string]any{"dispute_id": disputeID, "status": stringValue(object["status"]), "external_reference": nullableString(externalReference)})
	}
	if err != nil {
		return err
	}
	if parseErr != nil {
		return parseErr
	}
	return tx.Commit(ctx)
}

func (s *Server) billingCustomerID(ctx context.Context, connectionID, providerID string) *string {
	if providerID == "" {
		return nil
	}
	var id string
	if s.app.DB.QueryRow(ctx, `SELECT id FROM billing_customers WHERE provider_connection_id=$1 AND provider_customer_id=$2`, connectionID, providerID).Scan(&id) != nil {
		return nil
	}
	return &id
}

func (s *Server) subscriptionID(ctx context.Context, connectionID, providerID string) *string {
	if providerID == "" {
		return nil
	}
	var id string
	if s.app.DB.QueryRow(ctx, `SELECT id FROM subscriptions WHERE provider_connection_id=$1 AND provider_subscription_id=$2`, connectionID, providerID).Scan(&id) != nil {
		return nil
	}
	return &id
}

func (s *Server) invoiceID(ctx context.Context, connectionID, providerID string) *string {
	if providerID == "" {
		return nil
	}
	var id string
	if s.app.DB.QueryRow(ctx, `SELECT id FROM invoices WHERE provider_connection_id=$1 AND provider_invoice_id=$2`, connectionID, providerID).Scan(&id) != nil {
		return nil
	}
	return &id
}

func (s *Server) paymentID(ctx context.Context, connectionID, providerID string) *string {
	if providerID == "" {
		return nil
	}
	var id string
	if s.app.DB.QueryRow(ctx, `SELECT id FROM payments WHERE provider_connection_id=$1 AND provider_payment_id=$2`, connectionID, providerID).Scan(&id) != nil {
		return nil
	}
	return &id
}

func (s *Server) checkoutSessionID(ctx context.Context, applicationID, connectionID, checkoutID string) *string {
	if checkoutID == "" {
		return nil
	}
	var id string
	if s.app.DB.QueryRow(ctx, `SELECT id FROM checkout_sessions WHERE id=$1 AND application_id=$2 AND provider_connection_id=$3`, checkoutID, applicationID, connectionID).Scan(&id) != nil {
		return nil
	}
	return &id
}

func nestedValue(value any, path ...string) any {
	current := value
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[key]
	}
	return current
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	if result == nil {
		return map[string]any{}
	}
	return result
}

func firstStripeListObject(value any) map[string]any {
	data, _ := nestedValue(value, "data").([]any)
	if len(data) == 0 {
		return map[string]any{}
	}
	return mapValue(data[0])
}

func firstString(value any) string {
	values, _ := value.([]any)
	if len(values) == 0 {
		return ""
	}
	return stringValue(values[0])
}

func stripeObjectID(value any) string {
	if id, ok := value.(string); ok {
		return id
	}
	return stringValue(nestedValue(value, "id"))
}

func normalizedCurrency(value any) string {
	currency := strings.ToUpper(stringValue(value))
	if len(currency) == 3 {
		return currency
	}
	return "XXX"
}

func unixTimeValue(value any) *time.Time {
	seconds := int64Number(value)
	if seconds == 0 {
		return nil
	}
	result := time.Unix(seconds, 0).UTC()
	return &result
}

func stripeTaxAmount(object map[string]any) int64 {
	for _, key := range []string{"total_taxes", "total_tax_amounts"} {
		values, _ := object[key].([]any)
		var total int64
		for _, value := range values {
			total += int64Number(nestedValue(value, "amount"))
		}
		if total != 0 {
			return total
		}
	}
	return int64Number(object["tax"])
}
