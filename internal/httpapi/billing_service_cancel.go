package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
)

// The durable operation blocks new checkout only until cancellation succeeds.
// Failed batches reuse the same provider keys; cancellation is not retirement.
func (s *Server) serviceCancelSubjectBilling(w http.ResponseWriter, r *http.Request) {
	if !requireApplicationPermission(w, r, "billing/write") {
		return
	}
	app, subject := chi.URLParam(r, "application_id"), chi.URLParam(r, "subject_id")
	if chi.URLParam(r, "subject_type") != "workspace" {
		kernel.WriteProblem(w, r, 422, "invalid_subject", "A workspace subject is required.")
		return
	}
	if _, err := uuid.Parse(subject); err != nil {
		kernel.WriteProblem(w, r, 422, "invalid_subject", "A workspace UUID is required.")
		return
	}
	if r.Header.Get("Idempotency-Key") == "" {
		kernel.WriteProblem(w, r, 400, "idempotency_key_required", "Idempotency-Key is required.")
		return
	}
	var input struct {
		AtPeriodEnd *bool `json:"at_period_end"`
	}
	if !kernel.DecodeJSON(w, r, &input) {
		return
	}
	end := true
	if input.AtPeriodEnd != nil {
		end = *input.AtPeriodEnd
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 503, "billing_unavailable", "Cancellation could not be reserved.")
		return
	}
	defer tx.Rollback(context.Background())
	var locked, exists bool
	err = tx.QueryRow(r.Context(), `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0)),EXISTS(SELECT 1 FROM workspaces WHERE id=$2 AND application_id=$3)`, app+":workspace:"+subject, subject, app).Scan(&locked, &exists)
	if err != nil || !locked {
		kernel.WriteProblem(w, r, 409, "billing_operation_in_progress", "Another billing operation is in progress. Retry shortly.")
		return
	}
	if !exists {
		kernel.WriteProblem(w, r, 404, "workspace_not_found", "The workspace was not found.")
		return
	}
	var operation string
	err = tx.QueryRow(r.Context(), `INSERT INTO billing_subject_cancellations(application_id,subject_type,subject_id,operation_id,at_period_end)
VALUES($1,'workspace',$2,$3,$4) ON CONFLICT(application_id,subject_type,subject_id) DO UPDATE SET operation_id=billing_subject_cancellations.operation_id
WHERE billing_subject_cancellations.at_period_end=EXCLUDED.at_period_end RETURNING operation_id`, app, subject, kernel.NewID(), end).Scan(&operation)
	if err != nil {
		kernel.WriteProblem(w, r, 409, "cancellation_in_progress", "Retry the pending cancellation with its original at_period_end value.")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		kernel.WriteProblem(w, r, 503, "billing_unavailable", "Cancellation could not be reserved.")
		return
	}
	if err = s.expireSubjectCheckouts(r.Context(), app, subject, "cancel-"+operation); err != nil {
		kernel.WriteProblem(w, r, 503, "checkout_reconciliation_pending", "Checkout reconciliation is pending. Retry cancellation with the same idempotency key.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT s.id,s.provider_connection_id,s.provider_subscription_id,p.secret_ciphertext,p.api_version FROM subscriptions s JOIN provider_connections p ON p.id=s.provider_connection_id
WHERE s.application_id=$1 AND s.subject_type='workspace' AND s.subject_id=$2 AND s.status IN('active','trialing','past_due','paused','incomplete','unpaid')`, app, subject)
	if err != nil {
		kernel.WriteProblem(w, r, 503, "billing_unavailable", "Subscriptions could not be loaded.")
		return
	}
	type pending struct{ id, provider, external, sealed, version string }
	var subscriptions []pending
	for rows.Next() {
		var sub pending
		if err = rows.Scan(&sub.id, &sub.provider, &sub.external, &sub.sealed, &sub.version); err != nil {
			rows.Close()
			kernel.WriteProblem(w, r, 503, "billing_unavailable", "Subscriptions could not be loaded.")
			return
		}
		subscriptions = append(subscriptions, sub)
	}
	rows.Close()
	if rows.Err() != nil {
		kernel.WriteProblem(w, r, 503, "billing_unavailable", "Subscriptions could not be loaded.")
		return
	}
	for _, sub := range subscriptions {
		secret, e := s.app.Vault.Decrypt(sub.sealed, "billing-provider:"+sub.provider+":secret")
		if e == nil {
			e = s.cancelProviderSubscription(r.Context(), app, sub.provider, sub.external, string(secret), sub.version, "cancel-"+operation+"-"+sub.id, end)
		}
		if e != nil {
			kernel.WriteProblem(w, r, 502, "subscription_cancel_failed", "Provider cancellation or reconciliation is pending. Retry with the same idempotency key.")
			return
		}
	}
	if _, err = s.app.DB.Exec(r.Context(), `DELETE FROM billing_subject_cancellations WHERE application_id=$1 AND subject_type='workspace' AND subject_id=$2 AND operation_id=$3`, app, subject, operation); err != nil {
		kernel.WriteProblem(w, r, 503, "billing_update_failed", "Retry to finalize cancellation.")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) cancelProviderSubscription(ctx context.Context, app, provider, external, secret, version, key string, end bool) error {
	method := http.MethodPost
	form := url.Values{"cancel_at_period_end": {"true"}}
	if !end {
		method = http.MethodDelete
		form = url.Values{}
	}
	body, err := stripeRequest(ctx, method, "https://api.stripe.com/v1/subscriptions/"+url.PathEscape(external), secret, version, key, form)
	if err != nil {
		// DELETE may already have succeeded when its response was lost.
		body, err = stripeRequest(ctx, http.MethodGet, "https://api.stripe.com/v1/subscriptions/"+url.PathEscape(external), secret, version, "", nil)
		if err != nil {
			return err
		}
	}
	var value map[string]any
	if err = json.Unmarshal(body, &value); err != nil {
		return err
	}
	if stringValue(value["id"]) != external || stringValue(value["status"]) == "" {
		return fmt.Errorf("invalid subscription response")
	}
	if end && !boolValue(value["cancel_at_period_end"]) && stringValue(value["status"]) != "canceled" || !end && stringValue(value["status"]) != "canceled" {
		return fmt.Errorf("cancellation not confirmed")
	}
	return s.normalizeStripeSubscription(ctx, app, provider, value)
}

func (s *Server) expireSubjectCheckouts(ctx context.Context, app, subject, key string) error {
	rows, err := s.app.DB.Query(ctx, `SELECT c.id,c.provider_connection_id,COALESCE(c.provider_session_id,''),p.secret_ciphertext,p.api_version,pr.mode,c.status,c.provider_request,c.created_at,c.request_key,c.request_hash,c.checkout_uri,c.external_reference
FROM checkout_sessions c JOIN provider_connections p ON p.id=c.provider_connection_id JOIN prices pr ON pr.id=c.price_id
WHERE c.application_id=$1 AND c.subject_type='workspace' AND c.subject_id=$2 AND c.status IN('pending','open')`, app, subject)
	if err != nil {
		return err
	}
	var attempts []checkoutAttempt
	for rows.Next() {
		var a checkoutAttempt
		if err = rows.Scan(&a.id, &a.provider, &a.external, &a.sealed, &a.version, &a.mode, &a.status, &a.form, &a.created, &a.requestKey, &a.requestHash, &a.uri, &a.reference); err != nil {
			rows.Close()
			return err
		}
		attempts = append(attempts, a)
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	for _, a := range attempts {
		current, e := s.resolveCheckoutAttempt(ctx, app, a)
		if e != nil {
			return e
		}
		if current == nil {
			// Cancellation prevents a preparing request from saving its provider form.
			result, e := s.app.DB.Exec(ctx, `UPDATE checkout_sessions SET status='expired',updated_at=now() WHERE id=$1 AND application_id=$2 AND status='pending' AND provider_request IS NULL`, a.id, app)
			if e != nil {
				return e
			}
			if result.RowsAffected() != 1 {
				var terminal bool
				if e = s.app.DB.QueryRow(ctx, `SELECT status IN('failed','expired') FROM checkout_sessions WHERE id=$1 AND application_id=$2`, a.id, app).Scan(&terminal); e != nil || !terminal {
					return fmt.Errorf("checkout changed concurrently; retry")
				}
			}
			continue
		}
		if stringValue(current["status"]) != "open" {
			continue
		}
		secret, e := s.app.Vault.Decrypt(a.sealed, "billing-provider:"+a.provider+":secret")
		if e != nil {
			return e
		}
		_, e = stripeRequest(ctx, "POST", "https://api.stripe.com/v1/checkout/sessions/"+url.PathEscape(stringValue(current["id"]))+"/expire", string(secret), a.version, key+"-"+a.id, url.Values{})
		if e != nil {
			return e
		}
		current["client_reference_id"] = a.id
		if e = s.normalizeStripeCheckout(ctx, app, a.provider, current, false); e != nil {
			return e
		}
	}
	return nil
}
