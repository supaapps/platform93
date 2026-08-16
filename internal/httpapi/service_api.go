package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func requireApplicationPermission(w http.ResponseWriter, r *http.Request, suffix string) bool {
	if actor(r).Type != "client" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "machine_client_required", "A machine client token is required for application service APIs.")
		return false
	}
	if actorHasPermission(actor(r), applicationPermission(r, suffix)) {
		return true
	}
	kernel.WriteProblem(w, r, http.StatusForbidden, "application_permission_required", "The application actor does not have the required permission.")
	return false
}

func (s *Server) serviceListUsers(w http.ResponseWriter, r *http.Request) {
	if requireApplicationPermission(w, r, "users/read") {
		s.adminListUsers(w, r)
	}
}
func (s *Server) serviceGetUser(w http.ResponseWriter, r *http.Request) {
	if requireApplicationPermission(w, r, "users/read") {
		s.adminGetUser(w, r)
	}
}
func (s *Server) serviceListWorkspaces(w http.ResponseWriter, r *http.Request) {
	if requireApplicationPermission(w, r, "workspaces/read") {
		s.listWorkspaces(w, r)
	}
}
func (s *Server) serviceGetWorkspace(w http.ResponseWriter, r *http.Request) {
	if requireApplicationPermission(w, r, "workspaces/read") {
		s.getWorkspace(w, r)
	}
}
func (s *Server) serviceWorkspaceAccess(w http.ResponseWriter, r *http.Request) {
	if requireApplicationPermission(w, r, "workspaces/read") {
		s.listWorkspaceAccess(w, r)
	}
}
func (s *Server) serviceSubjectEntitlements(w http.ResponseWriter, r *http.Request) {
	if !requireApplicationPermission(w, r, "entitlements/read") {
		return
	}
	query := r.URL.Query()
	query.Set("subject_type", chi.URLParam(r, "subject_type"))
	query.Set("subject_id", chi.URLParam(r, "subject_id"))
	r.URL.RawQuery = query.Encode()
	s.listEntitlements(w, r)
}

func (s *Server) serviceSubjectBilling(w http.ResponseWriter, r *http.Request) {
	if !requireApplicationPermission(w, r, "billing/read") {
		return
	}
	applicationID, subjectType, subjectID := chi.URLParam(r, "application_id"), chi.URLParam(r, "subject_type"), chi.URLParam(r, "subject_id")
	if subjectType != "user" && subjectType != "workspace" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_subject", "Subject type must be user or workspace.")
		return
	}
	profileID, err := s.ensureBillingProfile(r.Context(), s.app.DB, applicationID, subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_subject_not_found", "The billing subject was not found.")
		return
	}
	var name string
	var email, taxID *string
	var version int64
	_ = s.app.DB.QueryRow(r.Context(), `SELECT name,email,tax_id,version FROM billing_profiles WHERE id=$1`, profileID).Scan(&name, &email, &taxID, &version)
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,price_id,status,current_period_start,current_period_end,cancel_at,canceled_at,trial_end,cancel_at_period_end,external_reference,created_at,updated_at
FROM subscriptions WHERE application_id=$1 AND subject_type=$2 AND subject_id=$3 ORDER BY created_at DESC`, applicationID, subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Billing information could not be loaded.")
		return
	}
	defer rows.Close()
	subscriptions := []map[string]any{}
	for rows.Next() {
		var id, price, status string
		var periodStart, periodEnd, cancelAt, canceledAt, trialEnd *time.Time
		var cancel bool
		var external *string
		var created, updated time.Time
		if rows.Scan(&id, &price, &status, &periodStart, &periodEnd, &cancelAt, &canceledAt, &trialEnd, &cancel, &external, &created, &updated) == nil {
			subscriptions = append(subscriptions, map[string]any{"id": id, "price_id": price, "status": status, "current_period_start": periodStart, "current_period_end": periodEnd, "cancel_at": cancelAt, "canceled_at": canceledAt, "trial_end": trialEnd, "cancel_at_period_end": cancel, "external_reference": external, "created_at": created, "updated_at": updated})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"subject_type": subjectType, "subject_id": subjectID, "billing_profile": map[string]any{"id": profileID, "name": name, "email": email, "tax_id": taxID, "version": version}, "subscriptions": subscriptions})
}
