package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

const stripeAPIVersion = "2026-04-22.dahlia"

func (s *Server) createBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.storeBillingProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) createInstallationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.storeBillingProvider(w, r, installationProviderScope())
}

func (s *Server) createOrganizationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.storeBillingProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) storeBillingProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	var request struct {
		Provider      string `json:"provider"`
		Secret        string `json:"secret"`
		WebhookSecret string `json:"webhook_secret,omitempty"`
		APIVersion    string `json:"api_version,omitempty"`
		Inheritable   bool   `json:"inheritable,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Provider != "stripe" || !strings.HasPrefix(request.Secret, "sk_") {
		kernel.WriteProblem(w, r, 422, "invalid_provider", "A valid Stripe secret is required.")
		return
	}
	if request.APIVersion == "" {
		request.APIVersion = stripeAPIVersion
	}
	if request.APIVersion != stripeAPIVersion {
		kernel.WriteProblem(w, r, 422, "unsupported_stripe_version", "Platform93 1.0 supports Stripe API 2026-04-22.dahlia.")
		return
	}
	id := kernel.NewID()
	publicID := "stripe_" + strings.ReplaceAll(id.String(), "-", "")[:20]
	secret, err := s.app.Vault.Encrypt([]byte(request.Secret), "billing-provider:"+id.String()+":secret")
	if err != nil {
		kernel.WriteProblem(w, r, 500, "secret_encryption_failed", "The provider secret could not be stored.")
		return
	}
	var webhook any
	if request.WebhookSecret != "" {
		encrypted, encryptErr := s.app.Vault.Encrypt([]byte(request.WebhookSecret), "billing-provider:"+id.String()+":webhook")
		if encryptErr != nil {
			kernel.WriteProblem(w, r, 500, "secret_encryption_failed", "The webhook secret could not be stored.")
			return
		}
		webhook = encrypted
	}
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO provider_connections (id,application_id,organization_id,provider,public_id,api_version,secret_ciphertext,webhook_secret_ciphertext,inheritable) VALUES ($1,$2,$3,'stripe',$4,$5,$6,$7,$8)`, id, scope.ApplicationID, scope.OrganizationID, publicID, request.APIVersion, secret, webhook, scope.inheritable(request.Inheritable))
	if err != nil {
		kernel.WriteProblem(w, r, 409, "provider_creation_failed", "The billing provider could not be created.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "provider": "stripe", "public_id": publicID, "api_version": request.APIVersion, "status": "active", "scope": scope.name(), "inheritable": scope.inheritable(request.Inheritable), "webhook_uri": s.app.PublicURL + "/provider-webhooks/stripe/" + publicID})
}

func (s *Server) listBillingProviders(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	rows, err := s.app.DB.Query(r.Context(), `SELECT pc.id,pc.provider,pc.public_id,pc.api_version,pc.status,pc.webhook_secret_ciphertext IS NOT NULL,pc.metadata,pc.created_at,pc.updated_at,pc.inheritable,
CASE WHEN pc.application_id IS NOT NULL THEN 'application' WHEN pc.organization_id IS NOT NULL THEN 'organization' ELSE 'installation' END
FROM provider_connections pc JOIN applications a ON a.id=$1
WHERE pc.application_id=$1 OR (pc.application_id IS NULL AND pc.organization_id=a.organization_id AND pc.inheritable) OR
(pc.application_id IS NULL AND pc.organization_id IS NULL AND pc.inheritable)
ORDER BY CASE WHEN pc.application_id IS NOT NULL THEN 0 WHEN pc.organization_id IS NOT NULL THEN 1 ELSE 2 END,pc.created_at DESC`, applicationID)
	s.writeBillingProviderPage(w, r, rows, err)
}

func (s *Server) listInstallationBillingProviders(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), false) {
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,provider,public_id,api_version,status,webhook_secret_ciphertext IS NOT NULL,metadata,created_at,updated_at,inheritable,'installation'
FROM provider_connections WHERE application_id IS NULL AND organization_id IS NULL ORDER BY created_at DESC`)
	s.writeBillingProviderPage(w, r, rows, err)
}

func (s *Server) listOrganizationBillingProviders(w http.ResponseWriter, r *http.Request) {
	scope := organizationProviderScope(chi.URLParam(r, "organization_id"))
	if !s.authorizeProviderScope(w, r, scope, false) {
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,provider,public_id,api_version,status,webhook_secret_ciphertext IS NOT NULL,metadata,created_at,updated_at,inheritable,
CASE WHEN organization_id IS NOT NULL THEN 'organization' ELSE 'installation' END
FROM provider_connections WHERE organization_id=$1 OR (application_id IS NULL AND organization_id IS NULL AND inheritable)
ORDER BY organization_id NULLS LAST,created_at DESC`, *scope.OrganizationID)
	s.writeBillingProviderPage(w, r, rows, err)
}

type billingProviderRows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
}

func (s *Server) writeBillingProviderPage(w http.ResponseWriter, r *http.Request, rows billingProviderRows, err error) {
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Billing providers could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, provider, publicID, version, status string
		var created, updated time.Time
		var webhookConfigured bool
		var metadata []byte
		var inheritable bool
		var scope string
		if rows.Scan(&id, &provider, &publicID, &version, &status, &webhookConfigured, &metadata, &created, &updated, &inheritable, &scope) == nil {
			items = append(items, map[string]any{"id": id, "provider": provider, "public_id": publicID, "api_version": version, "status": status, "webhook_configured": webhookConfigured, "metadata": decodeMap(metadata), "webhook_uri": s.app.PublicURL + "/provider-webhooks/" + provider + "/" + publicID, "created_at": created, "updated_at": updated, "scope": scope, "inheritable": inheritable, "effective": true})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) createCheckoutSession(w http.ResponseWriter, r *http.Request) {
	var request struct {
		PriceID        string   `json:"price_id"`
		SubjectType    string   `json:"subject_type"`
		SubjectID      string   `json:"subject_id"`
		ProviderID     string   `json:"provider_id"`
		PaymentMethods []string `json:"payment_methods,omitempty"`
		SuccessURI     string   `json:"success_uri"`
		CancelURI      string   `json:"cancel_uri"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.SubjectType == "" {
		request.SubjectType = "user"
		request.SubjectID = actor(r).ID
	}
	if request.SubjectType == "user" && request.SubjectID != actor(r).ID {
		kernel.WriteProblem(w, r, 403, "subject_forbidden", "Users can checkout only for themselves.")
		return
	}
	if request.SubjectType == "workspace" {
		if !s.canManageWorkspaceBillingFor(r, request.SubjectID) {
			kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_billing_required", "Workspace billing permission is required.")
			return
		}
	}
	if request.SubjectType != "user" && request.SubjectType != "workspace" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_subject", "Subject type must be user or workspace.")
		return
	}
	if !s.billingRedirectAllowed(r, request.SuccessURI) || !s.billingRedirectAllowed(r, request.CancelURI) {
		kernel.WriteProblem(w, r, 422, "redirect_not_allowed", "Checkout redirects must exactly match an enabled client redirect URI.")
		return
	}
	var mode, currency, secretCipher, apiVersion, providerConnectionID, productID string
	var checkoutConfig []byte
	err := s.app.DB.QueryRow(r.Context(), `SELECT pr.mode,pr.currency,pr.checkout_config,pc.secret_ciphertext,pc.api_version,pc.id,pr.product_id
FROM prices pr JOIN products p ON p.id=pr.product_id JOIN applications a ON a.id=pr.application_id
JOIN LATERAL (SELECT candidate.* FROM provider_connections candidate WHERE candidate.provider='stripe' AND candidate.status='active'
AND ($2='' OR candidate.id::text=$2) AND (candidate.application_id=pr.application_id OR
(candidate.application_id IS NULL AND candidate.organization_id=a.organization_id AND candidate.inheritable) OR
(candidate.application_id IS NULL AND candidate.organization_id IS NULL AND candidate.inheritable))
ORDER BY CASE WHEN candidate.application_id IS NOT NULL THEN 0 WHEN candidate.organization_id IS NOT NULL THEN 1 ELSE 2 END,candidate.created_at DESC LIMIT 1) pc ON true
WHERE pr.id=$1 AND pr.application_id=$3 AND pr.mode IN ('recurring','one_time') AND pr.active=true AND p.status='active'`, request.PriceID, request.ProviderID, chi.URLParam(r, "application_id")).Scan(&mode, &currency, &checkoutConfig, &secretCipher, &apiVersion, &providerConnectionID, &productID)
	if err != nil {
		kernel.WriteProblem(w, r, 422, "checkout_unavailable", "The selected price or provider is unavailable.")
		return
	}
	config := decodeMap(checkoutConfig)
	if len(request.PaymentMethods) == 0 {
		request.PaymentMethods = stringSlice(config["payment_methods"])
	}
	if err := validatePaymentMethods(mode, currency, request.PaymentMethods); err != nil {
		kernel.WriteProblem(w, r, 422, "invalid_payment_methods", err.Error())
		return
	}
	policy := cloneMap(config)
	policy["payment_methods"] = request.PaymentMethods
	policyJSON, _ := json.Marshal(policy)
	sessionID := kernel.NewID()
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO checkout_sessions (id,application_id,subject_type,subject_id,price_id,provider_connection_id,payment_methods,policy_snapshot,success_uri,cancel_uri) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, sessionID, chi.URLParam(r, "application_id"), request.SubjectType, request.SubjectID, request.PriceID, providerConnectionID, request.PaymentMethods, policyJSON, request.SuccessURI, request.CancelURI)
	if err != nil {
		kernel.WriteProblem(w, r, 409, "checkout_creation_failed", "The checkout record could not be created.")
		return
	}
	secret, err := s.app.Vault.Decrypt(secretCipher, "billing-provider:"+providerConnectionID+":secret")
	if err != nil {
		kernel.WriteProblem(w, r, 500, "provider_secret_unavailable", "The billing provider cannot be used.")
		return
	}
	providerPriceID, err := s.ensureStripePrice(r.Context(), chi.URLParam(r, "application_id"), providerConnectionID, request.PriceID, string(secret), apiVersion)
	if err != nil {
		_, _ = s.app.DB.Exec(r.Context(), "UPDATE checkout_sessions SET status='failed',updated_at=now() WHERE id=$1", sessionID)
		kernel.WriteProblem(w, r, http.StatusBadGateway, "provider_catalog_failed", "The provider product and price could not be prepared.")
		return
	}
	customerID, err := s.ensureStripeCustomer(r.Context(), chi.URLParam(r, "application_id"), providerConnectionID, request.SubjectType, request.SubjectID, string(secret), apiVersion)
	if err != nil {
		_, _ = s.app.DB.Exec(r.Context(), "UPDATE checkout_sessions SET status='failed',updated_at=now() WHERE id=$1", sessionID)
		kernel.WriteProblem(w, r, http.StatusBadGateway, "provider_customer_failed", "The billing customer could not be prepared.")
		return
	}
	form := url.Values{}
	if mode == "recurring" {
		form.Set("mode", "subscription")
	} else {
		form.Set("mode", "payment")
	}
	form.Set("success_url", request.SuccessURI)
	form.Set("cancel_url", request.CancelURI)
	form.Set("client_reference_id", sessionID.String())
	form.Set("metadata[platform93_checkout_id]", sessionID.String())
	form.Set("metadata[platform93_application_id]", chi.URLParam(r, "application_id"))
	form.Set("metadata[platform93_product_id]", productID)
	form.Set("metadata[platform93_price_id]", request.PriceID)
	form.Set("metadata[platform93_subject_type]", request.SubjectType)
	form.Set("metadata[platform93_subject_id]", request.SubjectID)
	form.Set("customer", customerID)
	form.Set("line_items[0][quantity]", "1")
	form.Set("line_items[0][price]", providerPriceID)
	if mode == "recurring" {
		form.Set("subscription_data[metadata][platform93_checkout_id]", sessionID.String())
		form.Set("subscription_data[metadata][platform93_application_id]", chi.URLParam(r, "application_id"))
		form.Set("subscription_data[metadata][platform93_product_id]", productID)
		form.Set("subscription_data[metadata][platform93_price_id]", request.PriceID)
		form.Set("subscription_data[metadata][platform93_subject_type]", request.SubjectType)
		form.Set("subscription_data[metadata][platform93_subject_id]", request.SubjectID)
		applyStripeTrialPolicy(form, policy)
	}
	if mode == "one_time" {
		form.Set("payment_intent_data[metadata][platform93_checkout_id]", sessionID.String())
		form.Set("payment_intent_data[metadata][platform93_application_id]", chi.URLParam(r, "application_id"))
		form.Set("payment_intent_data[metadata][platform93_product_id]", productID)
		form.Set("payment_intent_data[metadata][platform93_price_id]", request.PriceID)
		form.Set("payment_intent_data[metadata][platform93_subject_type]", request.SubjectType)
		form.Set("payment_intent_data[metadata][platform93_subject_id]", request.SubjectID)
	}
	for index, method := range request.PaymentMethods {
		form.Set(fmt.Sprintf("payment_method_types[%d]", index), method)
	}
	applyStripeCheckoutPolicy(form, policy)
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		idempotencyKey = sessionID.String()
	}
	response, err := stripeRequest(r.Context(), "POST", "https://api.stripe.com/v1/checkout/sessions", string(secret), apiVersion, idempotencyKey, form)
	if err != nil {
		_, _ = s.app.DB.Exec(r.Context(), "UPDATE checkout_sessions SET status='failed',updated_at=now() WHERE id=$1", sessionID)
		kernel.WriteProblem(w, r, 502, "provider_checkout_failed", err.Error())
		return
	}
	var stripeSession struct {
		ID     string `json:"id"`
		URL    string `json:"url"`
		Status string `json:"status"`
	}
	if json.Unmarshal(response, &stripeSession) != nil || stripeSession.ID == "" || stripeSession.URL == "" {
		kernel.WriteProblem(w, r, 502, "invalid_provider_response", "Stripe returned an invalid checkout session.")
		return
	}
	_, err = s.app.DB.Exec(r.Context(), `UPDATE checkout_sessions SET provider_session_id=$1,checkout_uri=$2,status='open',updated_at=now() WHERE id=$3`, stripeSession.ID, stripeSession.URL, sessionID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "checkout_update_failed", "The provider checkout could not be saved.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": sessionID, "status": "open", "checkout_uri": stripeSession.URL, "provider_session_id": stripeSession.ID})
}

func (s *Server) stripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		kernel.WriteProblem(w, r, 400, "invalid_webhook_body", "The webhook body is invalid.")
		return
	}
	publicID := chi.URLParam(r, "connection_public_id")
	var connectionID, webhookCipher, apiVersion string
	err = s.app.DB.QueryRow(r.Context(), `SELECT pc.id,pc.webhook_secret_ciphertext,pc.api_version
FROM provider_connections pc LEFT JOIN applications a ON a.id=pc.application_id
WHERE pc.public_id=$1 AND pc.provider='stripe' AND pc.status='active'
AND (pc.application_id IS NULL OR a.deleted_at IS NULL)`, publicID).Scan(&connectionID, &webhookCipher, &apiVersion)
	if err != nil || webhookCipher == "" {
		kernel.WriteProblem(w, r, 404, "provider_connection_not_found", "The provider connection was not found.")
		return
	}
	secret, err := s.app.Vault.Decrypt(webhookCipher, "billing-provider:"+connectionID+":webhook")
	if err != nil || !verifyStripeSignature(r.Header.Get("Stripe-Signature"), body, string(secret), s.app.Now()) {
		kernel.WriteProblem(w, r, 400, "invalid_webhook_signature", "The Stripe webhook signature is invalid.")
		return
	}
	var event struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		APIVersion string `json:"api_version"`
		Data       struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &event) != nil || event.ID == "" {
		kernel.WriteProblem(w, r, 400, "invalid_webhook_event", "The Stripe event is invalid.")
		return
	}
	applicationID := stripeEventApplicationID(event.Data.Object)
	if applicationID == "" {
		applicationID, _ = s.stripeEventApplicationFromRecords(r.Context(), connectionID, event.Type, event.Data.Object)
	}
	var applicationAllowed bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM applications a JOIN provider_connections pc ON pc.id=$2
WHERE a.id=$1 AND a.deleted_at IS NULL AND (pc.application_id=a.id OR (pc.application_id IS NULL AND pc.organization_id=a.organization_id AND pc.inheritable) OR
(pc.application_id IS NULL AND pc.organization_id IS NULL AND pc.inheritable)))`, applicationID, connectionID).Scan(&applicationAllowed)
	if !applicationAllowed {
		kernel.WriteProblem(w, r, 422, "provider_event_application_unavailable", "The Stripe event does not identify an application allowed to use this connection.")
		return
	}
	ciphertext, err := s.app.Vault.Encrypt(body, "provider-event:"+connectionID+":"+event.ID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "webhook_storage_failed", "The webhook event could not be stored.")
		return
	}
	receiptID := kernel.NewID()
	result, err := s.app.DB.Exec(r.Context(), `INSERT INTO provider_events (id,application_id,provider_connection_id,provider_event_id,api_version,event_type,raw_body_ciphertext) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (provider_connection_id,provider_event_id) DO NOTHING`, receiptID, applicationID, connectionID, event.ID, event.APIVersion, event.Type, ciphertext)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "webhook_storage_failed", "The webhook event could not be stored.")
		return
	}
	if result.RowsAffected() == 0 {
		w.WriteHeader(200)
		return
	}
	if err = s.processStripeEvent(r, receiptID.String(), applicationID, connectionID, event.Type, event.Data.Object); err != nil {
		_, _ = s.app.DB.Exec(r.Context(), "UPDATE provider_events SET status='failed',attempts=attempts+1,last_error=$1 WHERE id=$2", truncate(err.Error(), 1000), receiptID)
		kernel.WriteProblem(w, r, 500, "webhook_processing_failed", "The webhook was stored but processing failed.")
		return
	}
	_, _ = s.app.DB.Exec(r.Context(), "UPDATE provider_events SET status='processed',attempts=attempts+1,processed_at=now() WHERE id=$1", receiptID)
	w.WriteHeader(200)
}

func (s *Server) processStripeEvent(r *http.Request, receiptID, applicationID, connectionID, eventType string, object map[string]any) error {
	_ = receiptID
	switch eventType {
	case "checkout.session.completed", "checkout.session.async_payment_succeeded":
		return s.normalizeStripeCheckout(r.Context(), applicationID, connectionID, object, true)
	case "checkout.session.expired":
		return s.normalizeStripeCheckout(r.Context(), applicationID, connectionID, object, false)
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		return s.normalizeStripeSubscription(r.Context(), applicationID, connectionID, object)
	case "invoice.created", "invoice.finalized", "invoice.paid", "invoice.payment_failed", "invoice.voided", "invoice.marked_uncollectible":
		return s.normalizeStripeInvoice(r.Context(), applicationID, connectionID, object)
	case "payment_intent.created", "payment_intent.processing", "payment_intent.succeeded", "payment_intent.payment_failed", "payment_intent.canceled", "payment_intent.amount_capturable_updated":
		return s.normalizeStripePayment(r.Context(), applicationID, connectionID, object)
	case "refund.created", "refund.updated", "refund.failed":
		return s.normalizeStripeRefund(r.Context(), applicationID, connectionID, object)
	case "charge.dispute.created", "charge.dispute.updated", "charge.dispute.closed":
		return s.normalizeStripeDispute(r.Context(), applicationID, connectionID, object)
	}
	return nil
}

func stripeEventApplicationID(object map[string]any) string {
	var find func(map[string]any, int) string
	find = func(current map[string]any, depth int) string {
		if depth > 4 {
			return ""
		}
		if metadata, ok := current["metadata"].(map[string]any); ok {
			if value, ok := metadata["platform93_application_id"].(string); ok {
				return value
			}
		}
		for _, key := range []string{"subscription_details", "payment_intent", "invoice", "subscription", "customer"} {
			if nested, ok := current[key].(map[string]any); ok {
				if value := find(nested, depth+1); value != "" {
					return value
				}
			}
		}
		return ""
	}
	return find(object, 0)
}

func (s *Server) stripeEventApplicationFromRecords(ctx context.Context, connectionID, eventType string, object map[string]any) (string, error) {
	objectID := stringValue(object["id"])
	customerID := stripeObjectID(object["customer"])
	subscriptionID := stripeObjectID(object["subscription"])
	invoiceID := stripeObjectID(object["invoice"])
	paymentID := stripeObjectID(object["payment_intent"])
	checkoutID := ""
	switch {
	case strings.HasPrefix(eventType, "checkout.session."):
		checkoutID = objectID
	case strings.HasPrefix(eventType, "customer.subscription."):
		subscriptionID = objectID
	case strings.HasPrefix(eventType, "invoice."):
		invoiceID = objectID
	case strings.HasPrefix(eventType, "payment_intent."):
		paymentID = objectID
	}
	if parent, ok := object["parent"].(map[string]any); ok {
		if details, ok := parent["subscription_details"].(map[string]any); ok && subscriptionID == "" {
			subscriptionID = stripeObjectID(details["subscription"])
		}
	}
	var applicationID string
	err := s.app.DB.QueryRow(ctx, `SELECT application_id FROM (
SELECT application_id,1 AS priority FROM checkout_sessions WHERE provider_connection_id=$1 AND provider_session_id=NULLIF($2,'')
UNION ALL SELECT application_id,2 FROM subscriptions WHERE provider_connection_id=$1 AND provider_subscription_id=NULLIF($3,'')
UNION ALL SELECT application_id,3 FROM invoices WHERE provider_connection_id=$1 AND provider_invoice_id=NULLIF($4,'')
UNION ALL SELECT application_id,4 FROM payments WHERE provider_connection_id=$1 AND provider_payment_id=NULLIF($5,'')
UNION ALL SELECT application_id,5 FROM billing_customers WHERE provider_connection_id=$1 AND provider_customer_id=NULLIF($6,'')
) candidates ORDER BY priority LIMIT 1`, connectionID, checkoutID, subscriptionID, invoiceID, paymentID, customerID).Scan(&applicationID)
	return applicationID, err
}

func (s *Server) ensureStripeCustomer(ctx context.Context, applicationID, providerConnectionID, subjectType, subjectID, secret, apiVersion string) (string, error) {
	var providerCustomerID *string
	err := s.app.DB.QueryRow(ctx, `SELECT provider_customer_id FROM billing_customers
WHERE provider_connection_id=$1 AND subject_type=$2 AND subject_id=$3`, providerConnectionID, subjectType, subjectID).Scan(&providerCustomerID)
	if err == nil && providerCustomerID != nil && *providerCustomerID != "" {
		return *providerCustomerID, nil
	}
	form := url.Values{}
	form.Set("metadata[platform93_application_id]", applicationID)
	form.Set("metadata[platform93_subject_type]", subjectType)
	form.Set("metadata[platform93_subject_id]", subjectID)
	profileID, err := s.ensureBillingProfile(ctx, s.app.DB, applicationID, subjectType, subjectID)
	if err != nil {
		return "", err
	}
	var email, name string
	var taxID *string
	if err = s.app.DB.QueryRow(ctx, `SELECT name,COALESCE(email,''),tax_id FROM billing_profiles WHERE id=$1`, profileID).Scan(&name, &email, &taxID); err != nil {
		return "", err
	}
	var addressSnapshot []byte
	if email != "" {
		form.Set("email", email)
	}
	if name != "" {
		form.Set("name", name)
	}
	if taxID != nil && *taxID != "" {
		form.Set("metadata[platform93_tax_id]", *taxID)
	}
	var line1, line2, city, region, postal, country string
	if s.app.DB.QueryRow(ctx, `SELECT a.line1,a.line2,a.city,a.region,a.postal_code,a.country_code,to_jsonb(a)
FROM addresses a WHERE a.application_id=$1 AND a.billing_profile_id=$2 AND a.is_active=true`, applicationID, profileID).Scan(&line1, &line2, &city, &region, &postal, &country, &addressSnapshot) == nil {
		form.Set("address[line1]", line1)
		form.Set("address[line2]", line2)
		form.Set("address[city]", city)
		form.Set("address[state]", region)
		form.Set("address[postal_code]", postal)
		form.Set("address[country]", country)
	}
	response, err := stripeRequest(ctx, "POST", "https://api.stripe.com/v1/customers", secret, apiVersion, "platform93-customer-"+providerConnectionID+"-"+subjectType+"-"+subjectID, form)
	if err != nil {
		return "", err
	}
	var customer struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(response, &customer) != nil || customer.ID == "" {
		return "", fmt.Errorf("Stripe returned an invalid customer")
	}
	_, err = s.app.DB.Exec(ctx, `INSERT INTO billing_customers
(id,application_id,subject_type,subject_id,provider_connection_id,provider_customer_id,name,email,address_snapshot)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (provider_connection_id,subject_type,subject_id) DO UPDATE SET
provider_customer_id=EXCLUDED.provider_customer_id,name=EXCLUDED.name,email=EXCLUDED.email,address_snapshot=EXCLUDED.address_snapshot,updated_at=now()`,
		kernel.NewID(), applicationID, subjectType, subjectID, providerConnectionID, customer.ID, name, email, nullableBytes(addressSnapshot))
	if err != nil {
		return "", err
	}
	return customer.ID, nil
}

func (s *Server) userBelongsToWorkspace(ctx context.Context, applicationID, userID, workspaceID string) bool {
	var belongs bool
	_ = s.app.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM workspaces w
WHERE w.application_id=$1 AND w.id=$3 AND w.deleted_at IS NULL AND
(w.owner_user_id=$2 OR EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=w.id AND m.user_id=$2)))`, applicationID, userID, workspaceID).Scan(&belongs)
	return belongs
}

func stripeRequest(ctx context.Context, method, uri, secret, version, idempotencyKey string, form url.Values) ([]byte, error) {
	var requestBody io.Reader
	if method == http.MethodGet {
		if encoded := form.Encode(); encoded != "" {
			uri += "?" + encoded
		}
	} else {
		requestBody = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, uri, requestBody)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(secret, "")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Stripe-Version", version)
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Stripe request failed")
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("Stripe request failed with status %d", response.StatusCode)
	}
	return body, nil
}

func (s *Server) upsertProviderGrant(ctx context.Context, tx pgx.Tx, applicationID, subjectType, subjectID, productID, priceID, sourceType, sourceID string, expiresAt *time.Time, revoke bool) error {
	var grantID string
	lookupErr := tx.QueryRow(ctx, `SELECT id FROM entitlement_grants
WHERE application_id=$1 AND source_type=$2 AND source_id=$3 AND product_id=$4`, applicationID, sourceType, sourceID, productID).Scan(&grantID)
	if revoke {
		if lookupErr == pgx.ErrNoRows {
			return nil
		}
		if lookupErr != nil {
			return lookupErr
		}
		var graceSeconds int64
		if err := tx.QueryRow(ctx, "SELECT grace_seconds FROM prices WHERE id=$1 AND application_id=$2", priceID, applicationID).Scan(&graceSeconds); err != nil {
			return err
		}
		marker := "none"
		if expiresAt != nil {
			marker = expiresAt.UTC().Format(time.RFC3339Nano)
		}
		if graceSeconds > 0 {
			base := s.app.Now()
			if expiresAt != nil {
				base = *expiresAt
			}
			expires := base.Add(time.Duration(graceSeconds) * time.Second)
			_, err := tx.Exec(ctx, `INSERT INTO entitlement_grant_actions
(id,grant_id,action,action_key,expires_at,reason,actor_type) VALUES($1,$2,'adjusted',$3,$4,'provider_access_ended','provider')
ON CONFLICT(grant_id,action_key) DO NOTHING`, kernel.NewID(), grantID, "provider_ended_grace:"+marker, expires)
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO entitlement_grant_actions
(id,grant_id,action,action_key,reason,actor_type) VALUES($1,$2,'revoked',$3,'provider_access_ended','provider')
ON CONFLICT(grant_id,action_key) DO NOTHING`, kernel.NewID(), grantID, "provider_ended:"+marker)
		return err
	}
	if lookupErr != nil && lookupErr != pgx.ErrNoRows {
		return lookupErr
	}
	if lookupErr == nil {
		marker := "none"
		if expiresAt != nil {
			marker = expiresAt.UTC().Format(time.RFC3339Nano)
		}
		var latestAction string
		_ = tx.QueryRow(ctx, `SELECT action FROM entitlement_grant_actions WHERE grant_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, grantID).Scan(&latestAction)
		action := "adjusted"
		if latestAction == "revoked" {
			action = "restored"
		}
		_, err := tx.Exec(ctx, `INSERT INTO entitlement_grant_actions
(id,grant_id,action,action_key,expires_at,reason,actor_type) VALUES($1,$2,$3,$4,$5,'provider_access_active','provider')
ON CONFLICT(grant_id,action_key) DO NOTHING`, kernel.NewID(), grantID, action, "provider_active:"+marker, expiresAt)
		return err
	}
	features := map[string]any{}
	rows, err := tx.Query(ctx, `SELECT f.key,pf.boolean_value,pf.quantity_value,pf.free_form_value
FROM price_features pf JOIN features f ON f.id=pf.feature_id WHERE pf.price_id=$1`, priceID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key string
		var booleanValue *bool
		var quantityValue *int64
		var freeFormValue []byte
		if err = rows.Scan(&key, &booleanValue, &quantityValue, &freeFormValue); err != nil {
			rows.Close()
			return err
		}
		if booleanValue != nil {
			features[key] = *booleanValue
		} else if quantityValue != nil {
			features[key] = *quantityValue
		} else {
			features[key] = decodeJSONValue(freeFormValue)
		}
	}
	rows.Close()
	featuresJSON, _ := json.Marshal(features)
	var configuration []byte
	if err = tx.QueryRow(ctx, "SELECT entitlement_config FROM prices WHERE id=$1", priceID).Scan(&configuration); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO entitlement_grants
(id,application_id,subject_type,subject_id,product_id,price_id,source_type,source_id,feature_values,configuration,starts_at,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now(),$11)
ON CONFLICT (application_id,source_type,source_id,product_id) WHERE source_id IS NOT NULL DO NOTHING`, kernel.NewID(), applicationID, subjectType, subjectID, productID, priceID, sourceType, sourceID, featuresJSON, configuration, expiresAt)
	return err
}
func applyStripeCheckoutPolicy(form url.Values, policy map[string]any) {
	if boolValue(policy["billing_address_required"]) {
		form.Set("billing_address_collection", "required")
	}
	if boolValue(policy["customer_update_address"]) {
		form.Set("customer_update[address]", "auto")
	}
	if boolValue(policy["customer_update_name"]) {
		form.Set("customer_update[name]", "auto")
	}
	if boolValue(policy["automatic_tax"]) {
		form.Set("automatic_tax[enabled]", "true")
	}
	if boolValue(policy["tax_id_collection"]) {
		form.Set("tax_id_collection[enabled]", "true")
	}
	if boolValue(policy["promotion_codes"]) {
		form.Set("allow_promotion_codes", "true")
	}
}
func validatePaymentMethods(mode, currency string, methods []string) error {
	for _, method := range methods {
		switch method {
		case "card":
		case "twint":
			if mode != "one_time" || currency != "CHF" {
				return fmt.Errorf("TWINT is available only for CHF one-time checkout")
			}
		default:
			return fmt.Errorf("payment method %q is not supported", method)
		}
	}
	return nil
}
func verifyStripeSignature(header string, body []byte, secret string, now time.Time) bool {
	var timestamp int64
	signatures := []string{}
	for _, part := range strings.Split(header, ",") {
		pair := strings.SplitN(part, "=", 2)
		if len(pair) != 2 {
			continue
		}
		if pair[0] == "t" {
			timestamp, _ = strconv.ParseInt(pair[1], 10, 64)
		}
		if pair[0] == "v1" {
			signatures = append(signatures, pair[1])
		}
	}
	if timestamp == 0 || now.Sub(time.Unix(timestamp, 0)) > 5*time.Minute || time.Unix(timestamp, 0).Sub(now) > time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "."))
	_, _ = mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, signature := range signatures {
		if hmac.Equal([]byte(expected), []byte(signature)) {
			return true
		}
	}
	return false
}
func safeRedirect(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == "https" || (parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))
}

func (s *Server) billingRedirectAllowed(r *http.Request, value string) bool {
	if !safeRedirect(value) {
		return false
	}
	var allowed bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients
WHERE application_id=$1 AND disabled_at IS NULL AND $2=ANY(redirect_uris))`, chi.URLParam(r, "application_id"), value).Scan(&allowed)
	return allowed
}
func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	values := []string{}
	for _, entry := range raw {
		if text, ok := entry.(string); ok {
			values = append(values, text)
		}
	}
	return values
}
func cloneMap(value map[string]any) map[string]any {
	result := map[string]any{}
	for key, item := range value {
		result[key] = item
	}
	return result
}
func boolValue(value any) bool { result, _ := value.(bool); return result }
func metadataString(object map[string]any, key string) string {
	metadata, _ := object["metadata"].(map[string]any)
	value, _ := metadata[key].(string)
	return value
}
func unixTime(value any) any {
	seconds := int64Number(value)
	if seconds == 0 {
		return nil
	}
	return time.Unix(seconds, 0)
}
func int64Number(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case json.Number:
		number, _ := typed.Int64()
		return number
	}
	return 0
}
