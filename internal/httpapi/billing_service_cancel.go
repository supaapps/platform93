package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"net/http"
	"net/url"
)

// Machine callers need explicit application billing/write permission. Each
// provider operation is independently idempotent so interrupted batches can retry.
func (s *Server) serviceCancelSubjectBilling(w http.ResponseWriter, r *http.Request) {
	if !requireApplicationPermission(w, r, "billing/write") {
		return
	}
	if chi.URLParam(r, "subject_type") != "workspace" {
		kernel.WriteProblem(w, r, 422, "invalid_subject", "A workspace subject is required.")
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
	if !end {
		tx, err := s.app.DB.Begin(r.Context())
		if err != nil {
			kernel.WriteProblem(w, r, 503, "billing_unavailable", "Billing closure could not be recorded.")
			return
		}
		defer tx.Rollback(r.Context())
		app, subject := chi.URLParam(r, "application_id"), chi.URLParam(r, "subject_id")
		if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, app+":workspace:"+subject); err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO billing_subject_closures(application_id,subject_type,subject_id) VALUES($1,'workspace',$2) ON CONFLICT DO NOTHING`, app, subject)
		}
		if err != nil || tx.Commit(r.Context()) != nil {
			kernel.WriteProblem(w, r, 503, "billing_unavailable", "Billing closure could not be recorded.")
			return
		}
	}
	if err := s.expireSubjectCheckouts(r.Context(), chi.URLParam(r, "application_id"), chi.URLParam(r, "subject_id"), providerIdempotencyKey(r, "expire-checkouts")); err != nil {
		kernel.WriteProblem(w, r, 503, "checkout_reconciliation_pending", "Checkout reconciliation is pending. Cancellation will need to be retried.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT s.id,s.provider_connection_id,s.provider_subscription_id,p.secret_ciphertext,p.api_version FROM subscriptions s JOIN provider_connections p ON p.id=s.provider_connection_id WHERE s.application_id=$1 AND s.subject_type='workspace' AND s.subject_id=$2 AND s.status IN ('active','trialing','past_due','paused','incomplete','unpaid')`, chi.URLParam(r, "application_id"), chi.URLParam(r, "subject_id"))
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
		secret, err := s.app.Vault.Decrypt(sub.sealed, "billing-provider:"+sub.provider+":secret")
		if err != nil {
			kernel.WriteProblem(w, r, 503, "provider_secret_unavailable", "Billing credentials are unavailable.")
			return
		}
		method := "POST"
		form := url.Values{"cancel_at_period_end": {"true"}}
		if !end {
			method = "DELETE"
			form = url.Values{}
		}
		body, err := stripeRequest(r.Context(), method, "https://api.stripe.com/v1/subscriptions/"+url.PathEscape(sub.external), string(secret), sub.version, providerIdempotencyKey(r, "subject-cancel")+"-"+sub.id, form)
		var value struct {
			Status            string `json:"status"`
			CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
		}
		if err != nil || json.Unmarshal(body, &value) != nil || value.Status == "" {
			kernel.WriteProblem(w, r, 502, "subscription_cancel_failed", "Provider cancellation is pending. Retry with the same idempotency key.")
			return
		}
		if _, err = s.app.DB.Exec(r.Context(), `UPDATE subscriptions SET status=$1,cancel_at_period_end=$2,updated_at=now() WHERE id=$3 AND application_id=$4`, value.Status, value.CancelAtPeriodEnd, sub.id, chi.URLParam(r, "application_id")); err != nil {
			kernel.WriteProblem(w, r, 503, "billing_update_failed", "Cancellation reconciliation is pending.")
			return
		}
	}
	w.WriteHeader(204)
}

func (s *Server) expireSubjectCheckouts(ctx context.Context, app, subject, key string) error {
	rows, err := s.app.DB.Query(ctx, `SELECT c.id,c.provider_connection_id,COALESCE(c.provider_session_id,''),p.secret_ciphertext,p.api_version FROM checkout_sessions c JOIN provider_connections p ON p.id=c.provider_connection_id WHERE c.application_id=$1 AND c.subject_type='workspace' AND c.subject_id=$2 AND c.status IN('pending','open') AND c.created_at>now()-interval '25 hours'`, app, subject)
	if err != nil {
		return err
	}
	type checkout struct{ id, provider, external, sealed, version string }
	var items []checkout
	for rows.Next() {
		var item checkout
		if err = rows.Scan(&item.id, &item.provider, &item.external, &item.sealed, &item.version); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	for _, item := range items {
		if item.external == "" {
			return fmt.Errorf("pending checkout requires reconciliation")
		}
		secret, err := s.app.Vault.Decrypt(item.sealed, "billing-provider:"+item.provider+":secret")
		if err != nil {
			return err
		}
		uri := "https://api.stripe.com/v1/checkout/sessions/" + url.PathEscape(item.external)
		data, err := stripeRequest(ctx, "GET", uri, string(secret), item.version, "", url.Values{"expand[]": {"subscription"}})
		if err != nil {
			return err
		}
		var current map[string]any
		if err = json.Unmarshal(data, &current); err != nil {
			return err
		}
		status := stringValue(current["status"])
		if status == "complete" {
			subscription, ok := current["subscription"].(map[string]any)
			if !ok {
				return fmt.Errorf("completed checkout subscription unavailable")
			}
			if err = s.normalizeStripeSubscription(ctx, app, item.provider, subscription); err != nil {
				return err
			}
			status = "completed"
		} else if status == "open" {
			if _, err = stripeRequest(ctx, "POST", uri+"/expire", string(secret), item.version, key+"-"+item.id, url.Values{}); err != nil {
				return err
			}
			status = "expired"
		} else if status != "expired" {
			return fmt.Errorf("unknown checkout state")
		}
		if _, err = s.app.DB.Exec(ctx, `UPDATE checkout_sessions SET status=$1,updated_at=now() WHERE id=$2 AND application_id=$3`, status, item.id, app); err != nil {
			return err
		}
	}
	return nil
}
