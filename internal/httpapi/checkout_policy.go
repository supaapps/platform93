package httpapi

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

// The caller inserts its pending reservation and commits before provider I/O.
func (s *Server) guardRecurringCheckout(w http.ResponseWriter, r *http.Request, subjectType, subjectID, productID, priceID string, policy map[string]any) (pgx.Tx, bool) {
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 503, "checkout_unavailable", "Checkout is temporarily unavailable.")
		return nil, false
	}
	fail := func(status int, code, detail string) (pgx.Tx, bool) {
		_ = tx.Rollback(context.Background())
		kernel.WriteProblem(w, r, status, code, detail)
		return nil, false
	}
	app := chi.URLParam(r, "application_id")
	var locked bool
	if err = tx.QueryRow(r.Context(), `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, app+":"+subjectType+":"+subjectID).Scan(&locked); err != nil || !locked {
		return fail(409, "billing_operation_in_progress", "Another billing operation is in progress. Retry shortly.")
	}
	var available, cancelling bool
	err = tx.QueryRow(r.Context(), `SELECT
 CASE WHEN $2='user' THEN EXISTS(SELECT 1 FROM users WHERE application_id=$1 AND id=$3 AND status='active')
 ELSE EXISTS(SELECT 1 FROM workspaces WHERE application_id=$1 AND id=$3 AND deleted_at IS NULL) END,
 EXISTS(SELECT 1 FROM billing_subject_cancellations WHERE application_id=$1 AND subject_type=$2 AND subject_id=$3)`, app, subjectType, subjectID).Scan(&available, &cancelling)
	if err != nil {
		return fail(503, "checkout_unavailable", "Checkout eligibility could not be verified.")
	}
	if !available || cancelling {
		return fail(409, "billing_subject_unavailable", "The billing subject is unavailable or cancellation is pending.")
	}
	if !boolValue(policy["single_subscription"]) && !boolValue(policy["trial_once_per_subject"]) {
		return tx, true
	}
	var active, open, used bool
	err = tx.QueryRow(r.Context(), `SELECT
 EXISTS(SELECT 1 FROM subscriptions s JOIN prices p ON p.id=s.price_id WHERE s.application_id=$1 AND s.subject_type=$2 AND s.subject_id=$3 AND p.product_id=$4 AND s.status IN ('active','trialing','past_due','paused','incomplete','unpaid'))
 OR EXISTS(SELECT 1 FROM checkout_sessions c JOIN prices p ON p.id=c.price_id WHERE c.application_id=$1 AND c.subject_type=$2 AND c.subject_id=$3 AND p.product_id=$4 AND c.status='completed' AND NOT EXISTS(SELECT 1 FROM subscriptions s WHERE s.application_id=c.application_id AND s.metadata->>'platform93_checkout_id'=c.id::text)),
 EXISTS(SELECT 1 FROM checkout_sessions c JOIN prices p ON p.id=c.price_id WHERE c.application_id=$1 AND c.subject_type=$2 AND c.subject_id=$3 AND p.product_id=$4 AND c.status IN ('pending','open')),
 EXISTS(SELECT 1 FROM checkout_sessions c JOIN prices p ON p.id=c.price_id WHERE c.application_id=$1 AND c.subject_type=$2 AND c.subject_id=$3 AND p.product_id=$4 AND c.status='completed' AND COALESCE((c.policy_snapshot->>'trial_period_days')::int,0)>0)
 OR EXISTS(SELECT 1 FROM subscriptions s JOIN prices p ON p.id=s.price_id WHERE s.application_id=$1 AND s.subject_type=$2 AND s.subject_id=$3 AND p.product_id=$4 AND s.trial_end IS NOT NULL)`, app, subjectType, subjectID, productID).Scan(&active, &open, &used)
	if err != nil {
		return fail(503, "checkout_unavailable", "Checkout eligibility could not be verified.")
	}
	if open || active && boolValue(policy["single_subscription"]) {
		return fail(409, "subscription_exists", "A subscription or checkout is already in progress. Manage or complete it before purchasing again.")
	}
	if used && boolValue(policy["trial_once_per_subject"]) {
		delete(policy, "trial_period_days")
	}
	return tx, true
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
