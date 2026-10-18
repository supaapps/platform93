package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

// Keep the subject locked until Checkout is persisted, including the provider call.
// An HTTP idempotency key alone cannot serialize different purchase requests.
func (s *Server) guardRecurringCheckout(w http.ResponseWriter, r *http.Request, subjectType, subjectID, productID, priceID string, policy map[string]any) (func(), bool) {
	noop := func() {}
	conn, err := s.app.DB.Acquire(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 503, "checkout_unavailable", "Checkout is temporarily unavailable.")
		return noop, false
	}
	key := chi.URLParam(r, "application_id") + ":" + subjectType + ":" + subjectID
	// Transaction advisory locks are released automatically even on connection loss.
	tx, err := conn.Begin(r.Context())
	if err != nil {
		conn.Release()
		kernel.WriteProblem(w, r, 503, "checkout_unavailable", "Checkout is temporarily unavailable.")
		return noop, false
	}
	release := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
		conn.Release()
	}
	_, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key)
	if err != nil {
		release()
		kernel.WriteProblem(w, r, 503, "checkout_unavailable", "Checkout is temporarily unavailable.")
		return noop, false
	}
	app := chi.URLParam(r, "application_id")
	var closed bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM billing_subject_closures WHERE application_id=$1 AND subject_type=$2 AND subject_id=$3)`, app, subjectType, subjectID).Scan(&closed); err != nil || closed {
		release()
		kernel.WriteProblem(w, r, 409, "billing_subject_closed", "This billing subject is closed to new subscriptions.")
		return noop, false
	}
	if !boolValue(policy["single_subscription"]) && !boolValue(policy["trial_once_per_subject"]) {
		return release, true
	}
	var active, open, used bool
	err = tx.QueryRow(r.Context(), `SELECT
 EXISTS(SELECT 1 FROM subscriptions s JOIN prices p ON p.id=s.price_id WHERE s.application_id=$1 AND s.subject_type=$2 AND s.subject_id=$3 AND p.product_id=$4 AND s.status IN ('active','trialing','past_due','paused','incomplete')),
 EXISTS(SELECT 1 FROM checkout_sessions c JOIN prices p ON p.id=c.price_id WHERE c.application_id=$1 AND c.subject_type=$2 AND c.subject_id=$3 AND p.product_id=$4 AND c.status IN ('pending','open') AND c.created_at>now()-interval '25 hours'),
 EXISTS(SELECT 1 FROM checkout_sessions c JOIN prices p ON p.id=c.price_id WHERE c.application_id=$1 AND c.subject_type=$2 AND c.subject_id=$3 AND p.product_id=$4 AND c.status='completed' AND COALESCE((c.policy_snapshot->>'trial_period_days')::int,0)>0)
 OR EXISTS(SELECT 1 FROM subscriptions s JOIN prices p ON p.id=s.price_id WHERE s.application_id=$1 AND s.subject_type=$2 AND s.subject_id=$3 AND p.product_id=$4 AND s.trial_end IS NOT NULL)`, app, subjectType, subjectID, productID).Scan(&active, &open, &used)
	if err != nil {
		release()
		kernel.WriteProblem(w, r, 503, "checkout_unavailable", "Checkout eligibility could not be verified.")
		return noop, false
	}
	if !active && open {
		var existingID, uri, external string
		err := tx.QueryRow(r.Context(), `SELECT c.id,c.checkout_uri,c.provider_session_id FROM checkout_sessions c WHERE c.application_id=$1 AND c.subject_type=$2 AND c.subject_id=$3 AND c.price_id=$4 AND c.status='open' AND c.checkout_uri IS NOT NULL AND c.provider_session_id IS NOT NULL AND c.created_at>now()-interval '24 hours' ORDER BY c.created_at DESC LIMIT 1`, app, subjectType, subjectID, priceID).Scan(&existingID, &uri, &external)
		if err == nil {
			release()
			kernel.WriteJSON(w, 200, map[string]any{"id": existingID, "status": "open", "checkout_uri": uri, "provider_session_id": external})
			return noop, false
		}
	}
	if active || open {
		release()
		kernel.WriteProblem(w, r, 409, "subscription_exists", "A subscription or checkout is already in progress. Manage or complete it before purchasing again.")
		return noop, false
	}
	if used && boolValue(policy["trial_once_per_subject"]) {
		delete(policy, "trial_period_days")
	}
	return release, true
}

func (s *Server) cancelMySubscription(w http.ResponseWriter, r *http.Request) {
	var subjectType, subjectID string
	err := s.app.DB.QueryRow(r.Context(), `SELECT subject_type,subject_id FROM subscriptions WHERE application_id=$1 AND id=$2`, chi.URLParam(r, "application_id"), chi.URLParam(r, "subscription_id")).Scan(&subjectType, &subjectID)
	allowed := err == nil && (subjectType == "user" && subjectID == actor(r).ID || subjectType == "workspace" && s.canManageWorkspaceBillingFor(r, subjectID))
	if !allowed {
		kernel.WriteProblem(w, r, 404, "subscription_not_found", "The subscription was not found.")
		return
	}
	s.cancelSubscription(w, r)
}
