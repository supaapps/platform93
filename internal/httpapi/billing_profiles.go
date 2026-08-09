package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

type billingProfileQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Server) ensureBillingProfile(ctx context.Context, q billingProfileQuerier, applicationID, subjectType, subjectID string) (string, error) {
	id := kernel.NewID()
	var profileID string
	if subjectType == "user" {
		err := q.QueryRow(ctx, `INSERT INTO billing_profiles(id,application_id,subject_type,subject_id,name,email)
SELECT $1,u.application_id,'user',u.id,trim(concat_ws(' ',u.first_name,u.last_name)),u.email
FROM users u WHERE u.id=$2 AND u.application_id=$3 AND u.status='active'
ON CONFLICT (application_id,subject_type,subject_id) DO UPDATE SET updated_at=billing_profiles.updated_at
RETURNING id`, id, subjectID, applicationID).Scan(&profileID)
		return profileID, err
	}
	err := q.QueryRow(ctx, `INSERT INTO billing_profiles(id,application_id,subject_type,subject_id,name)
SELECT $1,w.application_id,'workspace',w.id,w.name FROM workspaces w
WHERE w.id=$2 AND w.application_id=$3 AND w.deleted_at IS NULL
ON CONFLICT (application_id,subject_type,subject_id) DO UPDATE SET updated_at=billing_profiles.updated_at
RETURNING id`, id, subjectID, applicationID).Scan(&profileID)
	return profileID, err
}

func (s *Server) addressSubject(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	workspaceID := chi.URLParam(r, "workspace_id")
	if workspaceID == "" {
		return "user", actor(r).ID, true
	}
	if !s.canManageWorkspaceBilling(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_billing_required", "Workspace billing permission is required.")
		return "", "", false
	}
	return "workspace", workspaceID, true
}

func (s *Server) canManageWorkspaceBilling(r *http.Request) bool {
	return s.canManageWorkspaceBillingFor(r, chi.URLParam(r, "workspace_id"))
}

func (s *Server) canManageWorkspaceBillingFor(r *http.Request, workspaceID string) bool {
	if actor(r).Type == "operator" || s.isWorkspaceOwnerOrOperator(r) {
		if actor(r).Type == "operator" {
			return true
		}
		var owner bool
		_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces
WHERE id=$1 AND application_id=$2 AND owner_user_id=$3 AND deleted_at IS NULL)`, workspaceID, chi.URLParam(r, "application_id"), actor(r).ID).Scan(&owner)
		if owner {
			return true
		}
	}
	var member bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspace_memberships
WHERE workspace_id=$1 AND application_id=$2 AND user_id=$3)`, workspaceID, chi.URLParam(r, "application_id"), actor(r).ID).Scan(&member)
	if !member {
		return false
	}
	wanted := "/applications/" + chi.URLParam(r, "application_id") + "/workspaces/" + workspaceID + "/billing/manage"
	for _, granted := range actor(r).Permissions {
		if permissionMatches(granted, wanted) {
			return true
		}
	}
	return false
}

func (s *Server) getBillingProfile(w http.ResponseWriter, r *http.Request) {
	subjectType, subjectID, ok := s.addressSubject(w, r)
	if !ok {
		return
	}
	profileID, err := s.ensureBillingProfile(r.Context(), s.app.DB, chi.URLParam(r, "application_id"), subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_profile_not_found", "The billing profile was not found.")
		return
	}
	var name string
	var email, taxID *string
	var version int64
	err = s.app.DB.QueryRow(r.Context(), `SELECT name,email,tax_id,version FROM billing_profiles WHERE id=$1`, profileID).Scan(&name, &email, &taxID, &version)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_profile_not_found", "The billing profile was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": profileID, "subject_type": subjectType, "subject_id": subjectID, "name": name, "email": email, "tax_id": taxID, "version": version})
}

func (s *Server) updateBillingProfile(w http.ResponseWriter, r *http.Request) {
	subjectType, subjectID, ok := s.addressSubject(w, r)
	if !ok {
		return
	}
	var request struct {
		Name    *string `json:"name,omitempty"`
		Email   *string `json:"email,omitempty"`
		TaxID   *string `json:"tax_id,omitempty"`
		Version int64   `json:"version"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Version < 1 || request.Name != nil && strings.TrimSpace(*request.Name) == "" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_billing_profile", "Billing profile fields and the current version must be valid.")
		return
	}
	profileID, err := s.ensureBillingProfile(r.Context(), s.app.DB, chi.URLParam(r, "application_id"), subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_profile_not_found", "The billing profile was not found.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE billing_profiles SET
name=COALESCE($1,name),email=CASE WHEN $2::text IS NULL THEN email ELSE NULLIF(trim($2),'') END,
tax_id=CASE WHEN $3::text IS NULL THEN tax_id ELSE NULLIF(trim($3),'') END,version=version+1,updated_at=now()
WHERE id=$4 AND version=$5`, request.Name, request.Email, request.TaxID, profileID, request.Version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "billing_profile_version_conflict", "The billing profile version has changed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
