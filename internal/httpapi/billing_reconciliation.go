package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/jobqueue"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
)

func (s *Server) createReconciliationRun(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "provider_id")
	var exists bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM provider_connections
WHERE id=$1 AND provider='stripe' AND status IN('active','error') AND (application_id=$2 OR
(application_id IS NULL AND organization_id=(SELECT organization_id FROM applications WHERE id=$2) AND inheritable) OR
(application_id IS NULL AND organization_id IS NULL AND inheritable)))`, providerID, chi.URLParam(r, "application_id")).Scan(&exists)
	if !exists {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_provider_not_found", "The billing provider was not found.")
		return
	}
	runID := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO reconciliation_runs(id,application_id,provider_connection_id,status)
VALUES($1,$2,$3,'pending')`, runID, chi.URLParam(r, "application_id"), providerID)
	}
	if err == nil {
		err = jobqueue.InsertBillingReconciliation(r.Context(), s.app.DB, tx, runID.String())
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "reconciliation_enqueue_failed", "The reconciliation run could not be queued.")
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"id": runID, "provider_id": providerID, "status": "pending"})
}

func (s *Server) listReconciliationRuns(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,provider_connection_id,status,findings,repairs,last_error,started_at,completed_at,created_at
FROM reconciliation_runs WHERE application_id=$1 ORDER BY created_at DESC,id DESC LIMIT 101`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Reconciliation runs could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, providerID, status string
		var findings, repairs []byte
		var lastError *string
		var startedAt, completedAt *time.Time
		var createdAt time.Time
		if rows.Scan(&id, &providerID, &status, &findings, &repairs, &lastError, &startedAt, &completedAt, &createdAt) == nil {
			items = append(items, reconciliationResponse(id, providerID, status, findings, repairs, lastError, startedAt, completedAt, createdAt))
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getReconciliationRun(w http.ResponseWriter, r *http.Request) {
	var id, providerID, status string
	var findings, repairs []byte
	var lastError *string
	var startedAt, completedAt *time.Time
	var createdAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,provider_connection_id,status,findings,repairs,last_error,started_at,completed_at,created_at
FROM reconciliation_runs WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "run_id"), chi.URLParam(r, "application_id")).
		Scan(&id, &providerID, &status, &findings, &repairs, &lastError, &startedAt, &completedAt, &createdAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "reconciliation_run_not_found", "The reconciliation run was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, reconciliationResponse(id, providerID, status, findings, repairs, lastError, startedAt, completedAt, createdAt))
}

func reconciliationResponse(id, providerID, status string, findings, repairs []byte, lastError *string, startedAt, completedAt *time.Time, createdAt time.Time) map[string]any {
	return map[string]any{"id": id, "provider_id": providerID, "status": status, "findings": decodeAny(findings), "repairs": decodeAny(repairs),
		"last_error": lastError, "started_at": startedAt, "completed_at": completedAt, "created_at": createdAt}
}

func RunBillingReconciliation(ctx context.Context, app *platform.App, runID string) error {
	s := &Server{app: app}
	var applicationID, connectionID, ciphertext, version string
	err := app.DB.QueryRow(ctx, `UPDATE reconciliation_runs rr SET status='running',started_at=COALESCE(started_at,now()),last_error=NULL
FROM provider_connections pc WHERE rr.id=$1 AND rr.provider_connection_id=pc.id AND rr.status IN('pending','running')
RETURNING rr.application_id,rr.provider_connection_id,pc.secret_ciphertext,pc.api_version`, runID).
		Scan(&applicationID, &connectionID, &ciphertext, &version)
	if err != nil {
		return nil
	}
	secret, err := app.Vault.Decrypt(ciphertext, "billing-provider:"+connectionID+":secret")
	if err != nil {
		return failReconciliation(ctx, app, runID, err)
	}
	types := []struct {
		name      string
		endpoint  string
		form      url.Values
		normalize func(context.Context, string, string, map[string]any) error
	}{
		{"subscriptions", "https://api.stripe.com/v1/subscriptions", url.Values{"status": {"all"}}, s.normalizeStripeSubscription},
		{"invoices", "https://api.stripe.com/v1/invoices", nil, s.normalizeStripeInvoice},
		{"payments", "https://api.stripe.com/v1/payment_intents", nil, s.normalizeStripePayment},
		{"refunds", "https://api.stripe.com/v1/refunds", nil, s.normalizeStripeRefund},
		{"disputes", "https://api.stripe.com/v1/disputes", nil, s.normalizeStripeDispute},
	}
	counts := map[string]int{}
	for _, resource := range types {
		count, listErr := reconcileStripeList(ctx, string(secret), version, resource.endpoint, resource.form, func(object map[string]any) error {
			return resource.normalize(ctx, applicationID, connectionID, object)
		})
		if listErr != nil {
			return failReconciliation(ctx, app, runID, fmt.Errorf("reconcile %s: %w", resource.name, listErr))
		}
		counts[resource.name] = count
	}
	findings, _ := json.Marshal(map[string]any{"provider_objects": counts})
	repairs, _ := json.Marshal(map[string]any{"normalized_objects": counts})
	_, err = app.DB.Exec(ctx, `UPDATE reconciliation_runs SET status='completed',findings=$1,repairs=$2,last_error=NULL,completed_at=now() WHERE id=$3`, findings, repairs, runID)
	return err
}

func failReconciliation(ctx context.Context, app *platform.App, runID string, cause error) error {
	_, _ = app.DB.Exec(ctx, `UPDATE reconciliation_runs SET status='pending',last_error=$1 WHERE id=$2`, truncate(cause.Error(), 1000), runID)
	return cause
}

func reconcileStripeList(ctx context.Context, secret, version, endpoint string, base url.Values, normalize func(map[string]any) error) (int, error) {
	form := url.Values{"limit": {"100"}}
	for key, values := range base {
		form[key] = append([]string(nil), values...)
	}
	count := 0
	for page := 0; page < 1000; page++ {
		body, err := stripeRequest(ctx, http.MethodGet, endpoint, secret, version, "", form)
		var list struct {
			Data    []map[string]any `json:"data"`
			HasMore bool             `json:"has_more"`
		}
		if err != nil {
			return count, fmt.Errorf("request Stripe list: %w", err)
		}
		if err = json.Unmarshal(body, &list); err != nil {
			return count, fmt.Errorf("decode Stripe list response: %w", err)
		}
		for _, object := range list.Data {
			if err = normalize(object); err != nil {
				return count, err
			}
			count++
		}
		if !list.HasMore {
			return count, nil
		}
		if len(list.Data) == 0 || stringValue(list.Data[len(list.Data)-1]["id"]) == "" {
			return count, fmt.Errorf("Stripe pagination did not provide a cursor")
		}
		form.Set("starting_after", stringValue(list.Data[len(list.Data)-1]["id"]))
	}
	return count, fmt.Errorf("Stripe pagination exceeded 1000 pages")
}

func decodeAny(value []byte) any {
	var result any
	if json.Unmarshal(value, &result) != nil {
		return nil
	}
	return result
}
