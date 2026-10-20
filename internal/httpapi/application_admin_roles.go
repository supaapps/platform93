package httpapi

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) roleWithinAdministration(r *http.Request, tx pgx.Tx, current kernel.Actor, live []string, roleID string, workspace *string) error {
	var scope string
	var permissions []string
	err := tx.QueryRow(r.Context(), `SELECT scope,permissions FROM roles WHERE application_id=$1 AND id=$2 FOR SHARE`, chi.URLParam(r, "application_id"), roleID).Scan(&scope, &permissions)
	if err != nil {
		return err
	}
	if (scope == "application" && workspace != nil) || (scope == "workspace" && workspace == nil) {
		return fmt.Errorf("role scope mismatch")
	}
	if len(permissions) == 0 || len(permissions) > 200 {
		return fmt.Errorf("invalid role permissions")
	}
	for _, p := range permissions {
		canonical, e := platformauthz.CanonicalScope(chi.URLParam(r, "application_id"), workspace, p)
		if e != nil || current.Type != "control_user" && !administrationAllows(current, live, canonical) {
			return fmt.Errorf("role exceeds current authority")
		}
	}
	return nil
}

func (s *Server) manageApplicationUserRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID      string  `json:"user_id"`
		RoleID      string  `json:"role_id"`
		WorkspaceID *string `json:"workspace_id,omitempty"`
		Reason      string  `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &in) || !administrationReason(w, r, in.Reason) {
		return
	}
	if r.Method == "POST" && !requireAdministrationKey(w, r) {
		return
	}
	tx, live, ok := s.beginApplicationAdministration(w, r, "roles:assign", true)
	if !ok {
		return
	}
	defer rollback(tx, r.Context())
	app, id := chi.URLParam(r, "application_id"), chi.URLParam(r, "assignment_id")
	if r.Method == "DELETE" {
		var user *string
		if err := tx.QueryRow(r.Context(), `SELECT user_id,role_id,workspace_id FROM role_assignments WHERE application_id=$1 AND id=$2 FOR UPDATE`, app, id).Scan(&user, &in.RoleID, &in.WorkspaceID); err != nil || user == nil {
			kernel.WriteProblem(w, r, 404, "role_assignment_not_found", "The user role assignment was not found.")
			return
		}
		in.UserID = *user
	}
	if _, err := uuid.Parse(in.UserID); err != nil {
		kernel.WriteProblem(w, r, 422, "invalid_role_assignment", "A valid application user is required.")
		return
	}
	var version int64
	if err := tx.QueryRow(r.Context(), `SELECT version FROM users WHERE application_id=$1 AND id=$2 AND (status='active' OR $3::boolean) FOR UPDATE`, app, in.UserID, r.Method == "DELETE").Scan(&version); err != nil {
		kernel.WriteProblem(w, r, 404, "user_not_found", "The active user was not found.")
		return
	}
	if !administrationIfMatch(w, r, version) {
		return
	}
	if err := s.roleWithinAdministration(r, tx, actor(r), live, in.RoleID, in.WorkspaceID); err != nil {
		kernel.WriteProblem(w, r, 403, "role_assignment_forbidden", "The role is unavailable or exceeds your current permissions.")
		return
	}
	var err error
	if in.WorkspaceID != nil {
		var owner string
		err = tx.QueryRow(r.Context(), `SELECT owner_user_id FROM workspaces WHERE application_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, app, *in.WorkspaceID).Scan(&owner)
		if err != nil || owner == in.UserID {
			kernel.WriteProblem(w, r, 409, "invalid_workspace_subject", "An active workspace non-owner subject is required.")
			return
		}
		if r.Method == "POST" {
			_, err = tx.Exec(r.Context(), `INSERT INTO workspace_memberships(application_id,workspace_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, app, *in.WorkspaceID, in.UserID)
		}
	}
	if err == nil {
		if r.Method == "DELETE" {
			_, err = tx.Exec(r.Context(), `DELETE FROM role_assignments WHERE application_id=$1 AND id=$2`, app, id)
		} else {
			id = kernel.NewID().String()
			_, err = tx.Exec(r.Context(), `INSERT INTO role_assignments(id,application_id,user_id,role_id,workspace_id) VALUES($1,$2,$3,$4,$5)`, id, app, in.UserID, in.RoleID, in.WorkspaceID)
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE users SET version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2`, app, in.UserID)
	}
	if err == nil {
		err = s.auditApplicationAdministration(r, tx, "user.role_assignment."+r.Method, in.UserID, in.Reason)
	}
	if err == nil {
		parsed := uuid.MustParse(app)
		_, err = s.app.Emit(r.Context(), tx, &parsed, "user.updated", "user/"+in.UserID, actor(r), map[string]any{"user_id": in.UserID, "changed_fields": []string{"role_assignments"}})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 409, "role_assignment_conflict", "The role assignment could not be committed.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	if r.Method == "DELETE" {
		w.WriteHeader(204)
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "user_id": in.UserID, "client_id": nil, "role_id": in.RoleID, "workspace_id": in.WorkspaceID})
}

func (s *Server) listApplicationUserRoles(w http.ResponseWriter, r *http.Request) {
	tx, _, ok := s.beginApplicationAdministration(w, r, "roles:read", false)
	if !ok {
		return
	}
	defer rollback(tx, r.Context())
	user := r.URL.Query().Get("user_id")
	if _, err := uuid.Parse(user); err != nil {
		kernel.WriteProblem(w, r, 422, "user_id_required", "A valid user_id filter is required.")
		return
	}
	var version int64
	if err := tx.QueryRow(r.Context(), `SELECT version FROM users WHERE application_id=$1 AND id=$2`, chi.URLParam(r, "application_id"), user).Scan(&version); err != nil {
		kernel.WriteProblem(w, r, 404, "user_not_found", "The user was not found.")
		return
	}
	params := r.URL.Query()
	if !params.Has("limit") {
		params.Set("limit", "20")
	}
	r.URL.RawQuery = params.Encode()
	query, args, limit, valid := referenceSearch(w, r, `SELECT ra.id,ra.role_id,ro.key,ro.scope,ra.workspace_id::text,ra.created_at FROM role_assignments ra JOIN roles ro ON ro.id=ra.role_id AND ro.application_id=ra.application_id WHERE ra.application_id=$1 AND ra.user_id=$2`, []any{chi.URLParam(r, "application_id"), user}, "ra.id", "ro.key", "ro.name")
	if !valid {
		return
	}
	rows, err := tx.Query(r.Context(), query, args...)
	if err != nil {
		kernel.WriteProblem(w, r, 503, "roles_unavailable", "Role assignments could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, role, key, scope string
		var workspace *string
		var created time.Time
		if err = rows.Scan(&id, &role, &key, &scope, &workspace, &created); err != nil {
			break
		}
		items = append(items, map[string]any{"id": id, "user_id": user, "client_id": nil, "role_id": role, "role_key": key, "role_scope": scope, "workspace_id": workspace, "created_at": created})
	}
	if err != nil || rows.Err() != nil {
		kernel.WriteProblem(w, r, 503, "roles_unavailable", "Role assignments could not be loaded.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version))
	items, cursor := referencePage(items, limit, func(item map[string]any) string { return item["id"].(string) })
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": cursor, "user_version": version})
}
