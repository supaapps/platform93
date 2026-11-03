package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

// Absence from a provider list is not an automatic assertion of non-purchase.
// An authorized administrator must investigate and explicitly attest the outcome.
func (s *Server) resolveCheckoutNotCreated(w http.ResponseWriter, r *http.Request) {
	if actor(r).Type != "control_user" {
		kernel.WriteProblem(w, r, 403, "control_user_required", "A Platform administrator is required.")
		return
	}
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		kernel.WriteProblem(w, r, 400, "idempotency_key_required", "Idempotency-Key is required.")
		return
	}
	var input struct {
		ConfirmNoProviderSession bool   `json:"confirm_no_provider_session"`
		Reason                   string `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &input) {
		return
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !input.ConfirmNoProviderSession || len(input.Reason) < 10 || len(input.Reason) > 512 {
		kernel.WriteProblem(w, r, 422, "resolution_confirmation_required", "Confirm that provider investigation found no session, and supply a reason of 10 to 512 characters.")
		return
	}
	app, id := chi.URLParam(r, "application_id"), chi.URLParam(r, "session_id")
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 503, "billing_unavailable", "Resolution is unavailable.")
		return
	}
	defer tx.Rollback(context.Background())
	var status string
	var external *string
	var created time.Time
	err = tx.QueryRow(r.Context(), `SELECT status,provider_session_id,created_at FROM checkout_sessions WHERE id=$1 AND application_id=$2 FOR UPDATE`, id, app).Scan(&status, &external, &created)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "checkout_session_not_found", "The checkout session was not found.")
		return
	}
	if status == "failed" {
		w.WriteHeader(204)
		return
	}
	if status != "pending" || external != nil || s.app.Now().Sub(created) < 25*time.Hour {
		kernel.WriteProblem(w, r, 409, "checkout_resolution_not_allowed", "Only an unresolved checkout older than 25 hours without a provider session ID can be resolved. Reconcile known sessions through the provider.")
		return
	}
	inserted, err := tx.Exec(r.Context(), `INSERT INTO audit_records(id,organization_id,application_id,actor_type,actor_id,action,target_type,target_id,reason,request_id,changes)
SELECT $1,a.organization_id,a.id,'control_user',$3,'billing.checkout.resolved_not_created','checkout_session',$4,$5,$6,'{"status":"failed","confirmed_no_provider_session":true}'::jsonb FROM applications a WHERE a.id=$2`, kernel.NewID(), app, actor(r).ID, id, input.Reason, kernel.RequestID(r.Context()))
	if err == nil {
		if inserted.RowsAffected() != 1 {
			err = errors.New("resolution audit was not persisted")
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE checkout_sessions SET status='failed',updated_at=now() WHERE id=$1 AND application_id=$2`, id, app)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, 503, "checkout_resolution_failed", "Resolution and its audit could not be committed.")
		return
	}
	w.WriteHeader(204)
}
