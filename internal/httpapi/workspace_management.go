package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) getWorkspace(w http.ResponseWriter, r *http.Request) {
	if !s.canAccessWorkspace(r, false) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_not_found", "The workspace was not found.")
		return
	}
	var id, ownerUserID, key, name string
	var metadata []byte
	var version int64
	var createdAt, updatedAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,owner_user_id,key,name,metadata,version,created_at,updated_at FROM workspaces
WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL`, chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id")).
		Scan(&id, &ownerUserID, &key, &name, &metadata, &version, &createdAt, &updatedAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_not_found", "The workspace was not found.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version))
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "owner_user_id": ownerUserID, "key": key, "name": name, "metadata": decodeMap(metadata), "version": version, "created_at": createdAt, "updated_at": updatedAt})
}

func (s *Server) updateWorkspace(w http.ResponseWriter, r *http.Request) {
	if !s.canAccessWorkspace(r, true) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_management_required", "Workspace management permission is required.")
		return
	}
	var request struct {
		Name     *string         `json:"name,omitempty"`
		Metadata *map[string]any `json:"metadata,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Name != nil && strings.TrimSpace(*request.Name) == "" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_workspace", "A workspace name cannot be empty.")
		return
	}
	var version int64
	if err := s.app.DB.QueryRow(r.Context(), `SELECT version FROM workspaces WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL`, chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id")).Scan(&version); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_not_found", "The workspace was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	var metadata any
	if request.Metadata != nil {
		encoded, err := json.Marshal(*request.Metadata)
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_workspace", "Workspace metadata is invalid.")
			return
		}
		metadata = encoded
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE workspaces SET
name=CASE WHEN $1::text IS NULL THEN name ELSE $1 END,
metadata=CASE WHEN $2::jsonb IS NULL THEN metadata ELSE $2 END,
version=version+1,updated_at=now() WHERE id=$3 AND application_id=$4 AND version=$5 AND deleted_at IS NULL`, request.Name, metadata, chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id"), version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_version_conflict", "The workspace changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteWorkspace(w http.ResponseWriter, r *http.Request) {
	if !s.isWorkspaceOwnerOrOperator(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_owner_required", "The workspace owner or an organization administrator is required.")
		return
	}
	applicationID, workspaceID := chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id")
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The workspace could not be retired.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE workspaces SET deleted_at=now(),version=version+1,updated_at=now()
WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL`, workspaceID, applicationID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_not_found", "The active workspace was not found.")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE workspace_invitations SET revoked_at=COALESCE(revoked_at,now())
WHERE workspace_id=$1 AND application_id=$2 AND accepted_at IS NULL`, workspaceID, applicationID); err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM role_assignments WHERE workspace_id=$1 AND application_id=$2`, workspaceID, applicationID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM workspace_memberships WHERE workspace_id=$1 AND application_id=$2`, workspaceID, applicationID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "workspace_retirement_failed", "The workspace could not be retired atomically.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listWorkspaceMembers(w http.ResponseWriter, r *http.Request) {
	if !s.canAccessWorkspace(r, false) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_not_found", "The workspace was not found.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT u.id,u.email,u.first_name,u.last_name,u.status,
COALESCE(array_agg(ro.key ORDER BY ro.key) FILTER (WHERE ro.id IS NOT NULL),'{}'),
COALESCE(array_agg(ra.id::text ORDER BY ro.key) FILTER (WHERE ra.id IS NOT NULL),'{}'),m.created_at,false
FROM workspace_memberships m JOIN users u ON u.id=m.user_id
LEFT JOIN role_assignments ra ON ra.application_id=m.application_id AND ra.workspace_id=m.workspace_id AND ra.user_id=m.user_id
LEFT JOIN roles ro ON ro.id=ra.role_id
WHERE m.application_id=$1 AND m.workspace_id=$2
GROUP BY u.id,u.email,u.first_name,u.last_name,u.status,m.created_at
UNION ALL
SELECT u.id,u.email,u.first_name,u.last_name,u.status,'{}'::text[],'{}'::text[],w.created_at,true
FROM workspaces w JOIN users u ON u.id=w.owner_user_id
WHERE w.application_id=$1 AND w.id=$2 AND w.deleted_at IS NULL
ORDER BY 8,1`, chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Workspace members could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, email, firstName, lastName, status string
		var roleKeys, assignmentIDs []string
		var createdAt time.Time
		var owner bool
		if rows.Scan(&id, &email, &firstName, &lastName, &status, &roleKeys, &assignmentIDs, &createdAt, &owner) == nil {
			items = append(items, map[string]any{"id": id, "user_id": id, "email": email, "first_name": firstName, "last_name": lastName,
				"status": status, "owner": owner, "role_keys": roleKeys, "assignment_ids": assignmentIDs, "created_at": createdAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) replaceWorkspaceMemberRoles(w http.ResponseWriter, r *http.Request) {
	if !s.canAccessWorkspace(r, true) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_management_required", "Workspace management permission is required.")
		return
	}
	var request struct {
		RoleKeys []string `json:"role_keys"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.RoleKeys = uniqueStrings(request.RoleKeys)
	if len(request.RoleKeys) == 0 || len(request.RoleKeys) > 20 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_workspace_roles", "At least one workspace role is required.")
		return
	}
	applicationID, workspaceID, userID := chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id"), chi.URLParam(r, "user_id")
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Workspace membership could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	rows, err := tx.Query(r.Context(), `SELECT ro.id FROM roles ro WHERE ro.application_id=$1 AND ro.scope='workspace' AND ro.key=ANY($2)
AND EXISTS(SELECT 1 FROM workspaces WHERE id=$3 AND application_id=$1 AND deleted_at IS NULL)
AND EXISTS(SELECT 1 FROM users WHERE id=$4 AND application_id=$1 AND status='active')`, applicationID, request.RoleKeys, workspaceID, userID)
	roleIDs := []string{}
	if err == nil {
		for rows.Next() {
			var roleID string
			if rows.Scan(&roleID) == nil {
				roleIDs = append(roleIDs, roleID)
			}
		}
		rows.Close()
	}
	if err != nil || len(roleIDs) != len(request.RoleKeys) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_workspace_membership", "The workspace, user, and role keys must belong to this application.")
		return
	}
	var isOwner bool
	_ = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces WHERE id=$1 AND application_id=$2 AND owner_user_id=$3)`, workspaceID, applicationID, userID).Scan(&isOwner)
	if isOwner {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_owner_not_member", "The workspace owner cannot also be stored as a member.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO workspace_memberships(application_id,workspace_id,user_id)
VALUES($1,$2,$3) ON CONFLICT(workspace_id,user_id) DO NOTHING`, applicationID, workspaceID, userID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM role_assignments WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3`, applicationID, workspaceID, userID)
	}
	for _, roleID := range roleIDs {
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO role_assignments(id,application_id,user_id,role_id,workspace_id) VALUES($1,$2,$3,$4,$5)`, kernel.NewID(), applicationID, userID, roleID, workspaceID)
		}
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "workspace_membership_update_failed", "Workspace membership could not be updated atomically.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"user_id": userID, "workspace_id": workspaceID, "role_keys": request.RoleKeys})
}

func (s *Server) deleteWorkspaceMember(w http.ResponseWriter, r *http.Request) {
	if !s.canAccessWorkspace(r, true) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_management_required", "Workspace management permission is required.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The workspace member could not be removed.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `DELETE FROM role_assignments WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3`, chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id"), chi.URLParam(r, "user_id"))
	var removed string
	if err == nil {
		err = tx.QueryRow(r.Context(), `DELETE FROM workspace_memberships WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3 RETURNING user_id`, chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id"), chi.URLParam(r, "user_id")).Scan(&removed)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_member_not_found", "The workspace member was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) transferWorkspaceOwnership(w http.ResponseWriter, r *http.Request) {
	var request struct {
		NewOwnerUserID           string `json:"new_owner_user_id"`
		PreviousOwnerDisposition string `json:"previous_owner_disposition,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) || request.NewOwnerUserID == "" {
		return
	}
	if request.PreviousOwnerDisposition == "" {
		request.PreviousOwnerDisposition = "member"
	}
	if request.PreviousOwnerDisposition != "member" && request.PreviousOwnerDisposition != "remove" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_owner_disposition", "Previous owner disposition must be member or remove.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Workspace ownership could not be transferred.")
		return
	}
	defer rollback(tx, r.Context())
	applicationID, workspaceID := chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id")
	var previousOwnerID string
	err = tx.QueryRow(r.Context(), `SELECT owner_user_id FROM workspaces
WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL FOR UPDATE`, workspaceID, applicationID).Scan(&previousOwnerID)
	if err == nil && actor(r).Type == "user" && previousOwnerID != actor(r).ID {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_owner_required", "Only the current owner can transfer this workspace.")
		return
	}
	var newOwnerActive bool
	if err == nil {
		err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND application_id=$2 AND status='active')`, request.NewOwnerUserID, applicationID).Scan(&newOwnerActive)
	}
	if err != nil || !newOwnerActive || request.NewOwnerUserID == previousOwnerID {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_workspace_owner", "The new owner must be a different active user in this application.")
		return
	}
	_, err = tx.Exec(r.Context(), `DELETE FROM role_assignments WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3`, applicationID, workspaceID, request.NewOwnerUserID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM workspace_memberships WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3`, applicationID, workspaceID, request.NewOwnerUserID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE workspaces SET owner_user_id=$1,version=version+1,updated_at=now() WHERE id=$2 AND application_id=$3`, request.NewOwnerUserID, workspaceID, applicationID)
	}
	if err == nil && request.PreviousOwnerDisposition == "member" {
		_, err = tx.Exec(r.Context(), `INSERT INTO workspace_memberships(application_id,workspace_id,user_id) VALUES($1,$2,$3)`, applicationID, workspaceID, previousOwnerID)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO role_assignments(id,application_id,user_id,role_id,workspace_id)
SELECT $1,$2,$3,id,$4 FROM roles WHERE application_id=$2 AND key='workspace_member' AND scope='workspace'
ON CONFLICT DO NOTHING`, kernel.NewID(), applicationID, previousOwnerID, workspaceID)
		}
	}
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(r.Context(), tx, &parsedApplicationID, "workspace.owner_transferred", "workspace/"+workspaceID, actor(r),
			map[string]any{"workspace_id": workspaceID, "previous_owner_user_id": previousOwnerID, "new_owner_user_id": request.NewOwnerUserID, "previous_owner_disposition": request.PreviousOwnerDisposition})
	}
	if err != nil || parseErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_owner_transfer_failed", "Workspace ownership could not be transferred atomically.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"workspace_id": workspaceID, "owner_user_id": request.NewOwnerUserID, "previous_owner_user_id": previousOwnerID, "previous_owner_disposition": request.PreviousOwnerDisposition})
}

func (s *Server) leaveWorkspace(w http.ResponseWriter, r *http.Request) {
	if actor(r).Type != "user" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "user_required", "Only application users can leave a workspace.")
		return
	}
	if s.isWorkspaceOwnerOrOperator(r) {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_owner_cannot_leave", "Transfer workspace ownership before leaving.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The workspace could not be left.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `DELETE FROM role_assignments WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3`, chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id"), actor(r).ID)
	var removed string
	if err == nil {
		err = tx.QueryRow(r.Context(), `DELETE FROM workspace_memberships WHERE application_id=$1 AND workspace_id=$2 AND user_id=$3 RETURNING user_id`, chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id"), actor(r).ID).Scan(&removed)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_membership_not_found", "The user is not a member of this workspace.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) canAccessWorkspace(r *http.Request, manage bool) bool {
	if actor(r).Type == "operator" {
		return true
	}
	applicationID, workspaceID := chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id")
	var owner, member bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT owner_user_id=$3,
EXISTS(SELECT 1 FROM workspace_memberships WHERE application_id=$2 AND workspace_id=$1 AND user_id=$3)
FROM workspaces WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL`, workspaceID, applicationID, actor(r).ID).Scan(&owner, &member)
	if err != nil || !owner && !member {
		return false
	}
	if !manage || owner {
		return true
	}
	wanted := "/applications/" + applicationID + "/workspaces/" + workspaceID + "/manage"
	for _, scope := range actor(r).Permissions {
		if permissionMatches(scope, wanted) {
			return true
		}
	}
	return false
}

func (s *Server) isWorkspaceOwnerOrOperator(r *http.Request) bool {
	if actor(r).Type == "operator" {
		return true
	}
	var owner bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces
WHERE id=$1 AND application_id=$2 AND owner_user_id=$3 AND deleted_at IS NULL)`,
		chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id"), actor(r).ID).Scan(&owner)
	return owner
}
