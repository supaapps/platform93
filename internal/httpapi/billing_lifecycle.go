package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) getBillingProvider(w http.ResponseWriter, r *http.Request) {
	var id, provider, publicID, apiVersion, status string
	var providerScope string
	var webhookConfigured bool
	var inheritable bool
	var metadata []byte
	var createdAt, updatedAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,provider,public_id,api_version,status,
webhook_secret_ciphertext IS NOT NULL,metadata,created_at,updated_at,inheritable,
CASE WHEN application_id IS NOT NULL THEN 'application' WHEN organization_id IS NOT NULL THEN 'organization' ELSE 'installation' END
FROM provider_connections WHERE id=$1 AND (application_id=$2 OR
(application_id IS NULL AND organization_id=(SELECT organization_id FROM applications WHERE id=$2) AND inheritable) OR
(application_id IS NULL AND organization_id IS NULL AND inheritable))`, chi.URLParam(r, "provider_id"), chi.URLParam(r, "application_id")).
		Scan(&id, &provider, &publicID, &apiVersion, &status, &webhookConfigured, &metadata, &createdAt, &updatedAt, &inheritable, &providerScope)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_provider_not_found", "The billing provider was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "provider": provider, "public_id": publicID, "api_version": apiVersion,
		"status": status, "webhook_configured": webhookConfigured, "metadata": decodeMap(metadata),
		"webhook_uri": s.app.PublicURL + "/provider-webhooks/" + provider + "/" + publicID, "created_at": createdAt, "updated_at": updatedAt,
		"scope": providerScope, "inheritable": inheritable, "inherited": providerScope != "application"})
}

func (s *Server) updateBillingProvider(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Secret        string         `json:"secret,omitempty"`
		WebhookSecret string         `json:"webhook_secret,omitempty"`
		Metadata      map[string]any `json:"metadata,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	providerID := chi.URLParam(r, "provider_id")
	var exists bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM provider_connections
WHERE id=$1 AND application_id=$2 AND provider='stripe')`, providerID, chi.URLParam(r, "application_id")).Scan(&exists)
	if !exists {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_provider_not_found", "The billing provider was not found.")
		return
	}
	var secretCiphertext, webhookCiphertext any
	var err error
	if request.Secret != "" {
		if !strings.HasPrefix(request.Secret, "sk_") {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_provider_secret", "A valid Stripe secret is required.")
			return
		}
		secretCiphertext, err = s.app.Vault.Encrypt([]byte(request.Secret), "billing-provider:"+providerID+":secret")
	}
	if err == nil && request.WebhookSecret != "" {
		if !strings.HasPrefix(request.WebhookSecret, "whsec_") {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_webhook_secret", "A valid Stripe webhook signing secret is required.")
			return
		}
		webhookCiphertext, err = s.app.Vault.Encrypt([]byte(request.WebhookSecret), "billing-provider:"+providerID+":webhook")
	}
	metadata, _ := json.Marshal(request.Metadata)
	var metadataPointer *map[string]any
	if request.Metadata != nil {
		metadataPointer = &request.Metadata
	}
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `UPDATE provider_connections SET
secret_ciphertext=COALESCE($1,secret_ciphertext),webhook_secret_ciphertext=COALESCE($2,webhook_secret_ciphertext),
metadata=CASE WHEN $3::jsonb IS NULL THEN metadata ELSE $3 END,status='active',updated_at=now()
WHERE id=$4 AND application_id=$5`, secretCiphertext, webhookCiphertext, nullableJSON(metadataPointer, metadata),
			providerID, chi.URLParam(r, "application_id"))
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "billing_provider_update_failed", "The billing provider could not be updated.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) verifyBillingProvider(w http.ResponseWriter, r *http.Request) {
	var owned bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM provider_connections WHERE id=$1 AND application_id=$2)`, chi.URLParam(r, "provider_id"), chi.URLParam(r, "application_id")).Scan(&owned)
	if !owned {
		kernel.WriteProblem(w, r, http.StatusForbidden, "inherited_provider_read_only", "Inherited providers must be managed at their owning scope.")
		return
	}
	providerID, secret, version, ok := s.billingProviderSecret(w, r)
	if !ok {
		return
	}
	_, err := stripeRequest(r.Context(), http.MethodGet, "https://api.stripe.com/v1/balance", secret, version,
		"platform93-provider-verify-"+providerID, url.Values{})
	if err != nil {
		_, _ = s.app.DB.Exec(r.Context(), `UPDATE provider_connections SET status='error',updated_at=now() WHERE id=$1`, providerID)
		kernel.WriteProblem(w, r, http.StatusBadGateway, "billing_provider_verification_failed", "Stripe credentials could not be verified.")
		return
	}
	_, _ = s.app.DB.Exec(r.Context(), `UPDATE provider_connections SET status='active',updated_at=now() WHERE id=$1`, providerID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) disableBillingProvider(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE provider_connections pc SET status='disabled',updated_at=now()
WHERE pc.id=$1 AND pc.application_id=$2 AND NOT EXISTS(SELECT 1 FROM subscriptions s
WHERE s.provider_connection_id=pc.id AND s.status IN ('active','trialing','past_due','paused'))`,
		chi.URLParam(r, "provider_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "billing_provider_in_use", "The provider was not found or still has active subscriptions.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createPortalSession(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ProviderID  string `json:"provider_id"`
		SubjectType string `json:"subject_type,omitempty"`
		SubjectID   string `json:"subject_id,omitempty"`
		ReturnURI   string `json:"return_uri"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.SubjectType == "" {
		request.SubjectType, request.SubjectID = "user", actor(r).ID
	}
	if request.SubjectType == "user" && request.SubjectID != actor(r).ID ||
		request.SubjectType == "workspace" && !s.userBelongsToWorkspace(r.Context(), chi.URLParam(r, "application_id"), actor(r).ID, request.SubjectID) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "billing_subject_forbidden", "The billing subject is not available to this user.")
		return
	}
	if !s.billingRedirectAllowed(r, request.ReturnURI) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "redirect_not_allowed", "The portal return URI must exactly match an enabled client redirect URI.")
		return
	}
	providerID, secret, version, ok := s.billingProviderSecretByID(w, r, request.ProviderID)
	if !ok {
		return
	}
	customerID, err := s.ensureStripeCustomer(r.Context(), chi.URLParam(r, "application_id"), providerID,
		request.SubjectType, request.SubjectID, secret, version)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "provider_customer_failed", "The billing customer could not be prepared.")
		return
	}
	form := url.Values{"customer": {customerID}, "return_url": {request.ReturnURI}}
	response, err := stripeRequest(r.Context(), http.MethodPost, "https://api.stripe.com/v1/billing_portal/sessions", secret, version,
		"platform93-portal-"+kernel.NewID().String(), form)
	var portal struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err != nil || json.Unmarshal(response, &portal) != nil || portal.ID == "" || portal.URL == "" {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "provider_portal_failed", "Stripe could not create a customer portal session.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"provider_session_id": portal.ID, "portal_uri": portal.URL})
}

func (s *Server) getCheckoutSession(w http.ResponseWriter, r *http.Request) {
	var id, subjectType, subjectID, priceID, status, successURI, cancelURI string
	var providerID, providerSessionID, checkoutURI, externalReference *string
	var paymentMethods []string
	var policy []byte
	var createdAt, updatedAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,subject_type,subject_id,price_id,provider_connection_id,provider_session_id,
status,payment_methods,policy_snapshot,success_uri,cancel_uri,checkout_uri,external_reference,created_at,updated_at FROM checkout_sessions
WHERE id=$1 AND application_id=$2 AND ((subject_type='user' AND subject_id=$3) OR
(subject_type='workspace' AND workspace_accessible_to_user(application_id,subject_id,$3)))`,
		chi.URLParam(r, "session_id"), chi.URLParam(r, "application_id"), actor(r).ID).
		Scan(&id, &subjectType, &subjectID, &priceID, &providerID, &providerSessionID, &status, &paymentMethods, &policy,
			&successURI, &cancelURI, &checkoutURI, &externalReference, &createdAt, &updatedAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "checkout_session_not_found", "The checkout session was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "subject_type": subjectType, "subject_id": subjectID,
		"price_id": priceID, "provider_id": providerID, "provider_session_id": providerSessionID, "status": status,
		"payment_methods": paymentMethods, "policy": decodeMap(policy), "success_uri": successURI, "cancel_uri": cancelURI,
		"checkout_uri": checkoutURI, "external_reference": externalReference, "created_at": createdAt, "updated_at": updatedAt})
}

func (s *Server) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	s.writeSubscriptions(w, r, "")
}
func (s *Server) listMySubscriptions(w http.ResponseWriter, r *http.Request) {
	s.writeSubscriptions(w, r, actor(r).ID)
}

func (s *Server) writeSubscriptions(w http.ResponseWriter, r *http.Request, userID string) {
	var filter *string
	if userID != "" {
		filter = &userID
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,subject_type,subject_id,price_id,provider_connection_id,status,
current_period_start,current_period_end,cancel_at,canceled_at,trial_end,cancel_at_period_end,external_reference,created_at,updated_at
FROM subscriptions s WHERE s.application_id=$1 AND ($2::uuid IS NULL OR
s.subject_type='user' AND s.subject_id=$2::uuid OR s.subject_type='workspace' AND
workspace_accessible_to_user(s.application_id,s.subject_id,$2::uuid))
ORDER BY created_at DESC,id DESC`, chi.URLParam(r, "application_id"), filter)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Subscriptions could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, subjectType, subjectID, priceID, providerID, status string
		var periodStart, periodEnd, cancelAt, canceledAt, trialEnd *time.Time
		var cancelAtPeriodEnd bool
		var externalReference *string
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &subjectType, &subjectID, &priceID, &providerID, &status, &periodStart, &periodEnd, &cancelAt, &canceledAt, &trialEnd, &cancelAtPeriodEnd, &externalReference, &createdAt, &updatedAt) == nil {
			items = append(items, map[string]any{"id": id, "subject_type": subjectType, "subject_id": subjectID, "price_id": priceID, "provider_id": providerID,
				"status": status, "current_period_start": periodStart, "current_period_end": periodEnd, "cancel_at": cancelAt, "canceled_at": canceledAt,
				"trial_end": trialEnd, "cancel_at_period_end": cancelAtPeriodEnd, "external_reference": externalReference, "created_at": createdAt, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getSubscription(w http.ResponseWriter, r *http.Request) {
	var id, subjectType, subjectID, priceID, providerID, status string
	var periodStart, periodEnd, cancelAt, canceledAt, trialEnd *time.Time
	var cancelAtPeriodEnd bool
	var externalReference *string
	var createdAt, updatedAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,subject_type,subject_id,price_id,provider_connection_id,status,
current_period_start,current_period_end,cancel_at,canceled_at,trial_end,cancel_at_period_end,external_reference,created_at,updated_at
FROM subscriptions WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "subscription_id"), chi.URLParam(r, "application_id")).
		Scan(&id, &subjectType, &subjectID, &priceID, &providerID, &status, &periodStart, &periodEnd, &cancelAt, &canceledAt, &trialEnd, &cancelAtPeriodEnd, &externalReference, &createdAt, &updatedAt)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "subscription_not_found", "The subscription was not found.")
		return
	}
	kernel.WriteJSON(w, 200, map[string]any{"id": id, "subject_type": subjectType, "subject_id": subjectID, "price_id": priceID, "provider_id": providerID,
		"status": status, "current_period_start": periodStart, "current_period_end": periodEnd, "cancel_at": cancelAt, "canceled_at": canceledAt,
		"trial_end": trialEnd, "cancel_at_period_end": cancelAtPeriodEnd, "external_reference": externalReference, "created_at": createdAt, "updated_at": updatedAt})
}

func (s *Server) cancelSubscription(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AtPeriodEnd *bool `json:"at_period_end,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	atPeriodEnd := true
	if request.AtPeriodEnd != nil {
		atPeriodEnd = *request.AtPeriodEnd
	}
	providerID, providerSubscriptionID, secret, version, ok := s.subscriptionProvider(w, r)
	if !ok {
		return
	}
	method := http.MethodPost
	form := url.Values{}
	if atPeriodEnd {
		form.Set("cancel_at_period_end", "true")
	} else {
		method = http.MethodDelete
	}
	response, err := stripeRequest(r.Context(), method, "https://api.stripe.com/v1/subscriptions/"+url.PathEscape(providerSubscriptionID), secret, version,
		providerIdempotencyKey(r, "subscription-cancel"), form)
	if err != nil {
		kernel.WriteProblem(w, r, 502, "subscription_cancel_failed", "Stripe could not cancel the subscription.")
		return
	}
	var subscription map[string]any
	if json.Unmarshal(response, &subscription) != nil {
		kernel.WriteProblem(w, r, 502, "invalid_provider_response", "Stripe returned an invalid subscription.")
		return
	}
	_, _ = s.app.DB.Exec(r.Context(), `UPDATE subscriptions SET status=$1,cancel_at_period_end=$2,cancel_at=$3,canceled_at=$4,updated_at=now()
WHERE id=$5 AND provider_connection_id=$6`, stringValue(subscription["status"]), boolValue(subscription["cancel_at_period_end"]),
		unixTime(subscription["cancel_at"]), unixTime(subscription["canceled_at"]), chi.URLParam(r, "subscription_id"), providerID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) resumeSubscription(w http.ResponseWriter, r *http.Request) {
	providerID, providerSubscriptionID, secret, version, ok := s.subscriptionProvider(w, r)
	if !ok {
		return
	}
	form := url.Values{"cancel_at_period_end": {"false"}}
	response, err := stripeRequest(r.Context(), http.MethodPost, "https://api.stripe.com/v1/subscriptions/"+url.PathEscape(providerSubscriptionID), secret, version,
		providerIdempotencyKey(r, "subscription-resume"), form)
	if err != nil {
		kernel.WriteProblem(w, r, 502, "subscription_resume_failed", "Stripe could not resume the subscription.")
		return
	}
	var subscription map[string]any
	if json.Unmarshal(response, &subscription) != nil {
		kernel.WriteProblem(w, r, 502, "invalid_provider_response", "Stripe returned an invalid subscription.")
		return
	}
	_, _ = s.app.DB.Exec(r.Context(), `UPDATE subscriptions SET status=$1,cancel_at_period_end=false,cancel_at=NULL,canceled_at=$2,updated_at=now()
WHERE id=$3 AND provider_connection_id=$4`, stringValue(subscription["status"]), unixTime(subscription["canceled_at"]), chi.URLParam(r, "subscription_id"), providerID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) changeSubscriptionPrice(w http.ResponseWriter, r *http.Request) {
	var request struct {
		PriceID           string `json:"price_id"`
		ProrationBehavior string `json:"proration_behavior,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.ProrationBehavior == "" {
		request.ProrationBehavior = "create_prorations"
	}
	if request.ProrationBehavior != "create_prorations" && request.ProrationBehavior != "always_invoice" && request.ProrationBehavior != "none" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_proration_behavior", "Proration behavior must be create_prorations, always_invoice, or none.")
		return
	}
	var providerID, providerSubscriptionID, providerItemID, ciphertext, version, currentCurrency, targetCurrency, targetMode string
	err := s.app.DB.QueryRow(r.Context(), `SELECT s.provider_connection_id,s.provider_subscription_id,COALESCE(s.provider_item_id,''),pc.secret_ciphertext,pc.api_version,
current_price.currency,target_price.currency,target_price.mode FROM subscriptions s
JOIN provider_connections pc ON pc.id=s.provider_connection_id AND pc.status='active'
JOIN prices current_price ON current_price.id=s.price_id
JOIN prices target_price ON target_price.id=$3 AND target_price.application_id=s.application_id AND target_price.active=true
WHERE s.id=$1 AND s.application_id=$2 AND s.status IN('active','trialing','past_due')`, chi.URLParam(r, "subscription_id"), chi.URLParam(r, "application_id"), request.PriceID).
		Scan(&providerID, &providerSubscriptionID, &providerItemID, &ciphertext, &version, &currentCurrency, &targetCurrency, &targetMode)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "subscription_change_unavailable", "The subscription or target price is unavailable.")
		return
	}
	if providerItemID == "" {
		kernel.WriteProblem(w, r, http.StatusConflict, "subscription_item_unavailable", "The provider subscription item is not synchronized; replay or reconcile provider events first.")
		return
	}
	if targetMode != "recurring" || currentCurrency != targetCurrency {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "incompatible_subscription_price", "The target must be a recurring price in the subscription currency.")
		return
	}
	secret, err := s.app.Vault.Decrypt(ciphertext, "billing-provider:"+providerID+":secret")
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "provider_secret_unavailable", "The billing provider cannot be used.")
		return
	}
	providerPriceID, err := s.ensureStripePrice(r.Context(), chi.URLParam(r, "application_id"), providerID, request.PriceID, string(secret), version)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "provider_catalog_failed", "The target provider price could not be prepared.")
		return
	}
	form := url.Values{
		"items[0][id]":       {providerItemID},
		"items[0][price]":    {providerPriceID},
		"proration_behavior": {request.ProrationBehavior},
	}
	response, err := stripeRequest(r.Context(), http.MethodPost, "https://api.stripe.com/v1/subscriptions/"+url.PathEscape(providerSubscriptionID),
		string(secret), version, providerIdempotencyKey(r, "subscription-change"), form)
	var subscription map[string]any
	if err != nil || json.Unmarshal(response, &subscription) != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "subscription_change_failed", "Stripe could not change the subscription price.")
		return
	}
	if err = s.normalizeStripeSubscription(r.Context(), chi.URLParam(r, "application_id"), providerID, subscription); err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "subscription_sync_failed", "Stripe changed the subscription but local synchronization failed; reconciliation is required.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": chi.URLParam(r, "subscription_id"), "price_id": request.PriceID, "proration_behavior": request.ProrationBehavior})
}

func (s *Server) listInvoices(w http.ResponseWriter, r *http.Request) { s.writeInvoices(w, r, "") }
func (s *Server) listMyInvoices(w http.ResponseWriter, r *http.Request) {
	s.writeInvoices(w, r, actor(r).ID)
}

func (s *Server) writeInvoices(w http.ResponseWriter, r *http.Request, userID string) {
	var filter *string
	if userID != "" {
		filter = &userID
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT i.id,i.provider_connection_id,i.provider_invoice_id,i.subscription_id,i.status,
i.amount_due_minor,i.amount_paid_minor,i.tax_minor,i.currency,i.due_at,i.paid_at,i.hosted_uri,i.external_reference,i.created_at,i.updated_at
FROM invoices i LEFT JOIN billing_customers bc ON bc.id=i.billing_customer_id
WHERE i.application_id=$1 AND ($2::uuid IS NULL OR bc.subject_type='user' AND bc.subject_id=$2::uuid OR
bc.subject_type='workspace' AND workspace_accessible_to_user(i.application_id,bc.subject_id,$2::uuid))
ORDER BY i.created_at DESC,i.id DESC`, chi.URLParam(r, "application_id"), filter)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Invoices could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, providerID, providerInvoiceID, status, currency string
		var subscriptionID, hostedURI, externalReference *string
		var dueAt, paidAt *time.Time
		var due, paid, tax int64
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &providerID, &providerInvoiceID, &subscriptionID, &status, &due, &paid, &tax, &currency, &dueAt, &paidAt, &hostedURI, &externalReference, &createdAt, &updatedAt) == nil {
			items = append(items, map[string]any{"id": id, "provider_id": providerID, "provider_invoice_id": providerInvoiceID, "subscription_id": subscriptionID,
				"status": status, "amount_due_minor": due, "amount_paid_minor": paid, "tax_minor": tax, "currency": currency, "due_at": dueAt, "paid_at": paidAt,
				"hosted_uri": hostedURI, "external_reference": externalReference, "created_at": createdAt, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) listPayments(w http.ResponseWriter, r *http.Request) { s.writePayments(w, r, "") }
func (s *Server) listMyPayments(w http.ResponseWriter, r *http.Request) {
	s.writePayments(w, r, actor(r).ID)
}
func (s *Server) writePayments(w http.ResponseWriter, r *http.Request, userID string) {
	var filter *string
	if userID != "" {
		filter = &userID
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT p.id,p.provider_connection_id,p.provider_payment_id,p.checkout_session_id,p.invoice_id,
p.status,p.amount_minor,p.amount_received_minor,p.currency,p.payment_method_type,p.failure_code,p.failure_message,p.external_reference,p.created_at,p.updated_at
FROM payments p LEFT JOIN billing_customers bc ON bc.id=p.billing_customer_id WHERE p.application_id=$1
AND ($2::uuid IS NULL OR bc.subject_type='user' AND bc.subject_id=$2::uuid OR
bc.subject_type='workspace' AND workspace_accessible_to_user(p.application_id,bc.subject_id,$2::uuid))
ORDER BY p.created_at DESC,p.id DESC`, chi.URLParam(r, "application_id"), filter)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Payments could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, providerID, providerPaymentID, status, currency string
		var checkoutID, invoiceID, method, failureCode, failureMessage, externalReference *string
		var amount, received int64
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &providerID, &providerPaymentID, &checkoutID, &invoiceID, &status, &amount, &received, &currency, &method, &failureCode, &failureMessage, &externalReference, &createdAt, &updatedAt) == nil {
			items = append(items, map[string]any{"id": id, "provider_id": providerID, "provider_payment_id": providerPaymentID, "checkout_session_id": checkoutID,
				"invoice_id": invoiceID, "status": status, "amount_minor": amount, "amount_received_minor": received, "currency": currency,
				"payment_method_type": method, "failure_code": failureCode, "failure_message": failureMessage, "external_reference": externalReference, "created_at": createdAt, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) createRefund(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AmountMinor *int64 `json:"amount_minor,omitempty"`
		Reason      string `json:"reason,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Reason != "" && request.Reason != "duplicate" && request.Reason != "fraudulent" && request.Reason != "requested_by_customer" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_refund_reason", "Refund reason must be duplicate, fraudulent, or requested_by_customer.")
		return
	}
	var providerID, providerPaymentID, secretCipher, version, currency string
	var received, refunded int64
	err := s.app.DB.QueryRow(r.Context(), `SELECT p.provider_connection_id,p.provider_payment_id,pc.secret_ciphertext,pc.api_version,p.currency,
p.amount_received_minor,COALESCE((SELECT sum(amount_minor) FROM refunds WHERE payment_id=p.id AND status<>'failed'),0)
FROM payments p JOIN provider_connections pc ON pc.id=p.provider_connection_id WHERE p.id=$1 AND p.application_id=$2 AND pc.status='active'`,
		chi.URLParam(r, "payment_id"), chi.URLParam(r, "application_id")).Scan(&providerID, &providerPaymentID, &secretCipher, &version, &currency, &received, &refunded)
	amount := received - refunded
	if request.AmountMinor != nil {
		amount = *request.AmountMinor
	}
	if err != nil || amount <= 0 || amount > received-refunded {
		kernel.WriteProblem(w, r, 422, "refund_unavailable", "The payment or refund amount is unavailable.")
		return
	}
	secret, err := s.app.Vault.Decrypt(secretCipher, "billing-provider:"+providerID+":secret")
	if err != nil {
		kernel.WriteProblem(w, r, 500, "provider_secret_unavailable", "The billing provider cannot be used.")
		return
	}
	form := url.Values{"payment_intent": {providerPaymentID}, "amount": {strconv.FormatInt(amount, 10)}, "metadata[platform93_payment_id]": {chi.URLParam(r, "payment_id")}}
	if request.Reason != "" {
		form.Set("reason", request.Reason)
	}
	response, err := stripeRequest(r.Context(), http.MethodPost, "https://api.stripe.com/v1/refunds", string(secret), version, providerIdempotencyKey(r, "refund"), form)
	var refund struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		Currency string `json:"currency"`
		Reason   string `json:"reason"`
		Amount   int64  `json:"amount"`
	}
	if err != nil || json.Unmarshal(response, &refund) != nil || refund.ID == "" {
		kernel.WriteProblem(w, r, 502, "refund_failed", "Stripe could not create the refund.")
		return
	}
	id := kernel.NewID()
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO refunds(id,application_id,provider_connection_id,payment_id,provider_refund_id,status,amount_minor,currency,reason)
VALUES($1,$2,$3,$4,$5,$6,$7,upper($8),$9) ON CONFLICT(provider_connection_id,provider_refund_id) DO UPDATE SET status=EXCLUDED.status,updated_at=now()`,
		id, chi.URLParam(r, "application_id"), providerID, chi.URLParam(r, "payment_id"), refund.ID, refund.Status, amount, currency, request.Reason)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "refund_storage_failed", "The refund was created but could not be stored.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "provider_refund_id": refund.ID, "status": refund.Status, "amount_minor": amount, "currency": currency})
}

func (s *Server) listRefunds(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,payment_id,provider_connection_id,provider_refund_id,status,amount_minor,currency,reason,created_at,updated_at
FROM refunds WHERE application_id=$1 ORDER BY created_at DESC,id DESC`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Refunds could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, providerID, providerRefundID, status, currency string
		var paymentID, reason *string
		var amount int64
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &paymentID, &providerID, &providerRefundID, &status, &amount, &currency, &reason, &createdAt, &updatedAt) == nil {
			items = append(items, map[string]any{"id": id, "payment_id": paymentID, "provider_id": providerID, "provider_refund_id": providerRefundID, "status": status, "amount_minor": amount, "currency": currency, "reason": reason, "created_at": createdAt, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) listDisputes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,payment_id,provider_connection_id,provider_dispute_id,status,amount_minor,currency,reason,evidence_due_at,created_at,updated_at
FROM disputes WHERE application_id=$1 ORDER BY created_at DESC,id DESC`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Disputes could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, providerID, providerDisputeID, status, currency string
		var paymentID, reason *string
		var amount int64
		var evidenceDue *time.Time
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &paymentID, &providerID, &providerDisputeID, &status, &amount, &currency, &reason, &evidenceDue, &createdAt, &updatedAt) == nil {
			items = append(items, map[string]any{"id": id, "payment_id": paymentID, "provider_id": providerID, "provider_dispute_id": providerDisputeID, "status": status, "amount_minor": amount, "currency": currency, "reason": reason, "evidence_due_at": evidenceDue, "created_at": createdAt, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) listProviderEvents(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,provider_connection_id,provider_event_id,api_version,event_type,status,attempts,last_error,received_at,processed_at
FROM provider_events WHERE application_id=$1 ORDER BY received_at DESC,id DESC LIMIT 101`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Provider events could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, providerID, providerEventID, eventType, status string
		var apiVersion, lastError *string
		var attempts int
		var receivedAt time.Time
		var processedAt *time.Time
		if rows.Scan(&id, &providerID, &providerEventID, &apiVersion, &eventType, &status, &attempts, &lastError, &receivedAt, &processedAt) == nil {
			items = append(items, map[string]any{"id": id, "provider_id": providerID, "provider_event_id": providerEventID, "api_version": apiVersion, "event_type": eventType, "status": status, "attempts": attempts, "last_error": lastError, "received_at": receivedAt, "processed_at": processedAt})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) replayProviderEvent(w http.ResponseWriter, r *http.Request) {
	var connectionID, eventType, ciphertext string
	err := s.app.DB.QueryRow(r.Context(), `SELECT provider_connection_id,event_type,raw_body_ciphertext FROM provider_events
WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "event_id"), chi.URLParam(r, "application_id")).Scan(&connectionID, &eventType, &ciphertext)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "provider_event_not_found", "The provider event was not found.")
		return
	}
	var providerEventID string
	_ = s.app.DB.QueryRow(r.Context(), `SELECT provider_event_id FROM provider_events WHERE id=$1`, chi.URLParam(r, "event_id")).Scan(&providerEventID)
	body, err := s.app.Vault.Decrypt(ciphertext, "provider-event:"+connectionID+":"+providerEventID)
	var event struct {
		Data struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(body, &event) != nil {
		kernel.WriteProblem(w, r, 500, "provider_event_unavailable", "The provider event could not be read.")
		return
	}
	if err = s.processStripeEvent(r, chi.URLParam(r, "event_id"), chi.URLParam(r, "application_id"), connectionID, eventType, event.Data.Object); err != nil {
		_, _ = s.app.DB.Exec(r.Context(), `UPDATE provider_events SET status='failed',attempts=attempts+1,last_error=$1 WHERE id=$2`, truncate(err.Error(), 1000), chi.URLParam(r, "event_id"))
		kernel.WriteProblem(w, r, 500, "provider_event_replay_failed", "The provider event replay failed.")
		return
	}
	_, _ = s.app.DB.Exec(r.Context(), `UPDATE provider_events SET status='processed',attempts=attempts+1,last_error=NULL,processed_at=now() WHERE id=$1`, chi.URLParam(r, "event_id"))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) myBillingSummary(w http.ResponseWriter, r *http.Request) {
	var customers, subscriptions, invoices, payments int
	err := s.app.DB.QueryRow(r.Context(), `SELECT
(SELECT count(*) FROM billing_customers bc WHERE bc.application_id=$1 AND (bc.subject_type='user' AND bc.subject_id=$2 OR bc.subject_type='workspace' AND workspace_accessible_to_user(bc.application_id,bc.subject_id,$2))),
(SELECT count(*) FROM subscriptions s WHERE s.application_id=$1 AND s.status IN('active','trialing','past_due') AND (s.subject_type='user' AND s.subject_id=$2 OR s.subject_type='workspace' AND workspace_accessible_to_user(s.application_id,s.subject_id,$2))),
(SELECT count(*) FROM invoices i JOIN billing_customers bc ON bc.id=i.billing_customer_id WHERE i.application_id=$1 AND (bc.subject_type='user' AND bc.subject_id=$2 OR bc.subject_type='workspace' AND workspace_accessible_to_user(i.application_id,bc.subject_id,$2))),
(SELECT count(*) FROM payments p JOIN billing_customers bc ON bc.id=p.billing_customer_id WHERE p.application_id=$1 AND (bc.subject_type='user' AND bc.subject_id=$2 OR bc.subject_type='workspace' AND workspace_accessible_to_user(p.application_id,bc.subject_id,$2)))`, chi.URLParam(r, "application_id"), actor(r).ID).Scan(&customers, &subscriptions, &invoices, &payments)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Billing summary could not be loaded.")
		return
	}
	kernel.WriteJSON(w, 200, map[string]any{"billing_customers": customers, "active_subscriptions": subscriptions, "invoices": invoices, "payments": payments})
}

func (s *Server) billingProviderSecret(w http.ResponseWriter, r *http.Request) (string, string, string, bool) {
	return s.billingProviderSecretByID(w, r, chi.URLParam(r, "provider_id"))
}
func (s *Server) billingProviderSecretByID(w http.ResponseWriter, r *http.Request, providerID string) (string, string, string, bool) {
	var ciphertext, version string
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,secret_ciphertext,api_version FROM provider_connections
WHERE ($1='' OR id::text=$1) AND provider='stripe' AND status IN('active','error') AND (
application_id=$2 OR (application_id IS NULL AND organization_id=(SELECT organization_id FROM applications WHERE id=$2) AND inheritable) OR
(application_id IS NULL AND organization_id IS NULL AND inheritable))
ORDER BY CASE WHEN application_id IS NOT NULL THEN 0 WHEN organization_id IS NOT NULL THEN 1 ELSE 2 END,created_at DESC LIMIT 1`, providerID, chi.URLParam(r, "application_id")).Scan(&providerID, &ciphertext, &version)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "billing_provider_not_found", "The active billing provider was not found.")
		return "", "", "", false
	}
	secret, err := s.app.Vault.Decrypt(ciphertext, "billing-provider:"+providerID+":secret")
	if err != nil {
		kernel.WriteProblem(w, r, 500, "provider_secret_unavailable", "The billing provider cannot be used.")
		return "", "", "", false
	}
	return providerID, string(secret), version, true
}

func (s *Server) subscriptionProvider(w http.ResponseWriter, r *http.Request) (string, string, string, string, bool) {
	var providerID, providerSubscriptionID, ciphertext, version string
	err := s.app.DB.QueryRow(r.Context(), `SELECT s.provider_connection_id,s.provider_subscription_id,pc.secret_ciphertext,pc.api_version FROM subscriptions s JOIN provider_connections pc ON pc.id=s.provider_connection_id WHERE s.id=$1 AND s.application_id=$2 AND pc.status='active'`, chi.URLParam(r, "subscription_id"), chi.URLParam(r, "application_id")).Scan(&providerID, &providerSubscriptionID, &ciphertext, &version)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "subscription_not_found", "The active subscription was not found.")
		return "", "", "", "", false
	}
	secret, err := s.app.Vault.Decrypt(ciphertext, "billing-provider:"+providerID+":secret")
	if err != nil {
		kernel.WriteProblem(w, r, 500, "provider_secret_unavailable", "The billing provider cannot be used.")
		return "", "", "", "", false
	}
	return providerID, providerSubscriptionID, string(secret), version, true
}

func stringValue(value any) string { result, _ := value.(string); return result }

func providerIdempotencyKey(r *http.Request, operation string) string {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return key
	}
	return "platform93-" + operation + "-" + kernel.NewID().String()
}
