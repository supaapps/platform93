package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Key         string   `json:"key"`
		Name        string   `json:"name"`
		Scope       string   `json:"scope"`
		Permissions []string `json:"permissions"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Key = strings.TrimSpace(request.Key)
	request.Name = strings.TrimSpace(request.Name)
	if request.Key == "" || request.Name == "" || (request.Scope != "application" && request.Scope != "workspace") || len(request.Permissions) == 0 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_role", "Key, name, scope, and at least one permission are required.")
		return
	}
	id := kernel.NewID()
	_, err := s.app.DB.Exec(r.Context(), `INSERT INTO roles
(id,application_id,key,name,scope,permissions) VALUES ($1,$2,$3,$4,$5,$6)`, id, chi.URLParam(r, "application_id"), request.Key, request.Name, request.Scope, request.Permissions)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "role_conflict", "A role with this key already exists.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "key": request.Key, "name": request.Name, "scope": request.Scope, "permissions": request.Permissions, "built_in": false, "version": 1})
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,key,name,scope,permissions,built_in,version,created_at
FROM roles WHERE application_id=$1 ORDER BY built_in DESC,key`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Roles could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, key, name, scope string
		var created time.Time
		var permissions []string
		var builtIn bool
		var version int64
		if rows.Scan(&id, &key, &name, &scope, &permissions, &builtIn, &version, &created) == nil {
			items = append(items, map[string]any{"id": id, "key": key, "name": name, "scope": scope, "permissions": permissions, "built_in": builtIn, "version": version, "created_at": created})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request) {
	var id, key, name, scope string
	var permissions []string
	var builtIn bool
	var version int64
	var createdAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,key,name,scope,permissions,built_in,version,created_at
FROM roles WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "role_id"), chi.URLParam(r, "application_id")).
		Scan(&id, &key, &name, &scope, &permissions, &builtIn, &version, &createdAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "role_not_found", "The role was not found.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version))
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "key": key, "name": name, "scope": scope, "permissions": permissions, "built_in": builtIn, "version": version, "created_at": createdAt})
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        *string   `json:"name,omitempty"`
		Permissions *[]string `json:"permissions,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Name != nil {
		*request.Name = strings.TrimSpace(*request.Name)
		if *request.Name == "" {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_role", "A role name cannot be empty.")
			return
		}
	}
	if request.Permissions != nil {
		values := uniqueStrings(*request.Permissions)
		for _, permission := range values {
			if strings.TrimSpace(permission) == "" || len(permission) > 160 {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_role", "Permissions must be non-empty and at most 160 characters.")
				return
			}
		}
		if len(values) == 0 || len(values) > 200 {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_role", "At least one and at most 200 permissions are required.")
			return
		}
		request.Permissions = &values
	}
	var version int64
	var builtIn bool
	if err := s.app.DB.QueryRow(r.Context(), `SELECT version,built_in FROM roles WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "role_id"), chi.URLParam(r, "application_id")).Scan(&version, &builtIn); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "role_not_found", "The role was not found.")
		return
	}
	if builtIn {
		kernel.WriteProblem(w, r, http.StatusConflict, "built_in_role_immutable", "Built-in roles cannot be modified.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE roles SET
name=CASE WHEN $1::text IS NULL THEN name ELSE $1 END,
permissions=CASE WHEN $2::text[] IS NULL THEN permissions ELSE $2 END,
version=version+1 WHERE id=$3 AND application_id=$4 AND version=$5 AND built_in=false`,
		request.Name, request.Permissions, chi.URLParam(r, "role_id"), chi.URLParam(r, "application_id"), version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "role_version_conflict", "The role changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	var builtIn, assigned bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT built_in,EXISTS(SELECT 1 FROM role_assignments WHERE role_id=roles.id)
FROM roles WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "role_id"), chi.URLParam(r, "application_id")).Scan(&builtIn, &assigned)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "role_not_found", "The role was not found.")
		return
	}
	if builtIn || assigned {
		kernel.WriteProblem(w, r, http.StatusConflict, "role_in_use", "Built-in or assigned roles cannot be deleted.")
		return
	}
	_, err = s.app.DB.Exec(r.Context(), `DELETE FROM roles WHERE id=$1 AND application_id=$2 AND built_in=false`, chi.URLParam(r, "role_id"), chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "role_delete_failed", "The role could not be deleted.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createWorkspace(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Key         string         `json:"key"`
		Name        string         `json:"name"`
		OwnerUserID string         `json:"owner_user_id,omitempty"`
		Metadata    map[string]any `json:"metadata"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Key = strings.TrimSpace(request.Key)
	request.Name = strings.TrimSpace(request.Name)
	if request.Key == "" || request.Name == "" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_workspace", "Key and name are required.")
		return
	}
	if actor(r).Type == "user" {
		request.OwnerUserID = actor(r).ID
	}
	if request.OwnerUserID == "" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "workspace_owner_required", "An active application user must own the workspace.")
		return
	}
	id := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The workspace could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	var createdID string
	err = tx.QueryRow(r.Context(), `INSERT INTO workspaces
(id,application_id,owner_user_id,key,name,metadata)
SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT 1 FROM users WHERE id=$3 AND application_id=$2 AND status='active') RETURNING id`,
		id, chi.URLParam(r, "application_id"), request.OwnerUserID, request.Key, request.Name, request.Metadata).Scan(&createdID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO billing_profiles(id,application_id,subject_type,subject_id)
VALUES($1,$2,'workspace',$3)`, kernel.NewID(), chi.URLParam(r, "application_id"), id)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_conflict", "A workspace with this key already exists.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "owner_user_id": request.OwnerUserID, "key": request.Key, "name": request.Name, "metadata": request.Metadata, "version": 1})
}

func (s *Server) listWorkspaces(w http.ResponseWriter, r *http.Request) {
	query := `SELECT w.id,w.owner_user_id,w.key,w.name,w.metadata,w.version,w.created_at,w.updated_at
FROM workspaces w WHERE w.application_id=$1 AND w.deleted_at IS NULL`
	args := []any{chi.URLParam(r, "application_id")}
	if actor(r).Type == "user" {
		query += ` AND (w.owner_user_id=$2 OR EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=w.id AND m.user_id=$2))`
		args = append(args, actor(r).ID)
	}
	query += ` ORDER BY w.created_at,w.id`
	rows, err := s.app.DB.Query(r.Context(), query, args...)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Workspaces could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, ownerUserID, key, name string
		var created, updated time.Time
		var metadata []byte
		var version int64
		if rows.Scan(&id, &ownerUserID, &key, &name, &metadata, &version, &created, &updated) == nil {
			items = append(items, map[string]any{"id": id, "owner_user_id": ownerUserID, "key": key, "name": name, "metadata": decodeMap(metadata), "version": version, "created_at": created, "updated_at": updated})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) assignRole(w http.ResponseWriter, r *http.Request) {
	var request struct {
		UserID      *string `json:"user_id"`
		ClientID    *string `json:"client_id"`
		RoleID      string  `json:"role_id"`
		WorkspaceID *string `json:"workspace_id"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if (request.UserID == nil) == (request.ClientID == nil) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_role_subject", "Exactly one user_id or client_id is required.")
		return
	}
	var valid bool
	if request.UserID != nil {
		err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users u JOIN roles ro ON ro.application_id=u.application_id
WHERE u.id=$1 AND u.status='active' AND ro.id=$2 AND u.application_id=$3 AND
((ro.scope='application' AND $4::uuid IS NULL) OR (ro.scope='workspace' AND EXISTS(SELECT 1 FROM workspaces w WHERE w.id=$4 AND w.application_id=u.application_id AND w.deleted_at IS NULL))))`,
			*request.UserID, request.RoleID, chi.URLParam(r, "application_id"), request.WorkspaceID).Scan(&valid)
		if err != nil {
			valid = false
		}
	} else {
		err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients c JOIN roles ro ON ro.application_id=c.application_id
WHERE c.id=$1 AND c.disabled_at IS NULL AND ro.id=$2 AND c.application_id=$3 AND
((ro.scope='application' AND $4::uuid IS NULL) OR (ro.scope='workspace' AND EXISTS(SELECT 1 FROM workspaces w WHERE w.id=$4 AND w.application_id=c.application_id AND w.deleted_at IS NULL))))`,
			*request.ClientID, request.RoleID, chi.URLParam(r, "application_id"), request.WorkspaceID).Scan(&valid)
		if err != nil {
			valid = false
		}
	}
	if !valid {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_role_assignment", "The subject, role, and workspace scope do not form a valid assignment.")
		return
	}
	id := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The role assignment could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	if request.WorkspaceID != nil && request.UserID != nil {
		var owner bool
		err = tx.QueryRow(r.Context(), `SELECT owner_user_id=$3 FROM workspaces
WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL FOR UPDATE`, *request.WorkspaceID, chi.URLParam(r, "application_id"), *request.UserID).Scan(&owner)
		if err != nil || owner {
			kernel.WriteProblem(w, r, http.StatusConflict, "workspace_owner_is_not_member", "A workspace owner cannot also have a workspace membership role assignment.")
			return
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO workspace_memberships(application_id,workspace_id,user_id)
VALUES($1,$2,$3) ON CONFLICT (workspace_id,user_id) DO NOTHING`, chi.URLParam(r, "application_id"), *request.WorkspaceID, *request.UserID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO role_assignments
(id,application_id,user_id,client_id,role_id,workspace_id) VALUES ($1,$2,$3,$4,$5,$6)`, id, chi.URLParam(r, "application_id"), request.UserID, request.ClientID, request.RoleID, request.WorkspaceID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "role_assignment_conflict", "The role assignment could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "user_id": request.UserID, "client_id": request.ClientID, "role_id": request.RoleID, "workspace_id": request.WorkspaceID})
}

func (s *Server) listRoleAssignments(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT ra.id,ra.user_id,ra.client_id,ra.role_id,ro.key,ro.scope,ra.workspace_id,ra.created_at
FROM role_assignments ra JOIN roles ro ON ro.id=ra.role_id AND ro.application_id=ra.application_id
WHERE ra.application_id=$1 ORDER BY ra.created_at,ra.id`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Role assignments could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, roleID, roleKey, roleScope string
		var userID, clientID, workspaceID *string
		var createdAt time.Time
		if rows.Scan(&id, &userID, &clientID, &roleID, &roleKey, &roleScope, &workspaceID, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "user_id": userID, "client_id": clientID, "role_id": roleID,
				"role_key": roleKey, "role_scope": roleScope, "workspace_id": workspaceID, "created_at": createdAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) deleteRoleAssignment(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), "DELETE FROM role_assignments WHERE id=$1 AND application_id=$2", chi.URLParam(r, "assignment_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "role_assignment_not_found", "The role assignment was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createWorkspaceInvitation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		WorkspaceID string   `json:"workspace_id"`
		Email       string   `json:"email"`
		RoleKeys    []string `json:"role_keys"`
		ExpiresIn   int64    `json:"expires_in,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.WorkspaceID == "" {
		request.WorkspaceID = chi.URLParam(r, "workspace_id")
	}
	normalized := kernel.NormalizeEmail(request.Email)
	request.RoleKeys = uniqueStrings(request.RoleKeys)
	if !strings.Contains(normalized, "@") || len(request.RoleKeys) == 0 || len(request.RoleKeys) > 20 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_workspace_invitation", "A valid email, workspace, and at least one role key are required.")
		return
	}
	if request.ExpiresIn == 0 {
		request.ExpiresIn = int64((7 * 24 * time.Hour).Seconds())
	}
	if request.ExpiresIn < 300 || request.ExpiresIn > int64((30*24*time.Hour).Seconds()) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_invitation_expiry", "Invitation expiry must be between five minutes and thirty days.")
		return
	}
	var validWorkspace bool
	var roleCount int
	applicationID := chi.URLParam(r, "application_id")
	if actor(r).Type == "user" && !s.canAccessWorkspace(r, true) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_management_required", "Workspace management permission is required.")
		return
	}
	err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL),
(SELECT count(*) FROM roles WHERE application_id=$2 AND scope='workspace' AND key=ANY($3))`,
		request.WorkspaceID, applicationID, request.RoleKeys).Scan(&validWorkspace, &roleCount)
	if err != nil || !validWorkspace || roleCount != len(request.RoleKeys) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_workspace_roles", "The workspace and role keys must exist in this application and all roles must be workspace scoped.")
		return
	}
	credential, err := secure.RandomToken("p93_invite_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_creation_failed", "The invitation credential could not be created.")
		return
	}
	invitationID := kernel.NewID()
	notificationID := kernel.NewID()
	expiresAt := s.app.Now().Add(time.Duration(request.ExpiresIn) * time.Second)
	var workspaceName string
	if err = s.app.DB.QueryRow(r.Context(), `SELECT name FROM workspaces WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL`, request.WorkspaceID, applicationID).Scan(&workspaceName); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_not_found", "The workspace was not found.")
		return
	}
	flows, _ := s.loadApplicationFlowConfig(r.Context(), applicationID)
	invitationLink := ""
	if flows.InvitationRedirectURI != "" {
		invitationLink = appendCredentialQuery(flows.InvitationRedirectURI, map[string]string{
			"application_id": applicationID, "invitation_id": invitationID.String(), "invitation_token": credential, "platform93_flow": "workspace_invitation",
		})
	}
	templateID, templateLocale, payload, renderErr := s.renderSystemNotification(r.Context(), &applicationID, workspaceInvitationTemplate, normalized, map[string]any{
		"workspace_id": request.WorkspaceID, "workspace_name": workspaceName, "role_keys": strings.Join(request.RoleKeys, ", "),
		"invitation_link": invitationLink, "invitation_token": credential, "expires_at": templateTimestamp(expiresAt),
	})
	if renderErr != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_template_unavailable", "The workspace invitation email template is unavailable or invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The invitation could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO workspace_invitations
(id,application_id,workspace_id,normalized_email,credential_digest,roles,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		invitationID, applicationID, request.WorkspaceID, normalized, s.app.Vault.Digest(credential), request.RoleKeys, expiresAt)
	if err == nil {
		var ciphertext string
		ciphertext, err = s.app.Vault.Encrypt(payload, "notification:"+notificationID.String())
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO notifications
(id,application_id,template_id,recipient,locale,payload_ciphertext,status) VALUES ($1,$2,$3,$4,$5,$6,'queued')`, notificationID, applicationID, templateID, normalized, templateLocale, ciphertext)
		}
	}
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(r.Context(), tx, &parsedApplicationID, "workspace.invitation_created", "workspace_invitation/"+invitationID.String(), actor(r),
			map[string]any{"invitation_id": invitationID, "workspace_id": request.WorkspaceID, "role_keys": request.RoleKeys})
	}
	if err != nil || parseErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_invitation_conflict", "A pending invitation already exists or could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": invitationID, "workspace_id": request.WorkspaceID, "email": normalized,
		"role_keys": request.RoleKeys, "expires_at": expiresAt, "invitation_token": credential})
}

func (s *Server) listWorkspaceInvitations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT i.id,i.workspace_id,t.key,t.name,i.normalized_email,i.roles,i.expires_at,
i.accepted_at,i.revoked_at,i.created_at FROM workspace_invitations i JOIN workspaces t ON t.id=i.workspace_id
WHERE i.application_id=$1 ORDER BY i.created_at DESC,i.id DESC`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Workspace invitations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, workspaceID, workspaceKey, workspaceName, email string
		var roles []string
		var expiresAt, createdAt time.Time
		var acceptedAt, revokedAt *time.Time
		if rows.Scan(&id, &workspaceID, &workspaceKey, &workspaceName, &email, &roles, &expiresAt, &acceptedAt, &revokedAt, &createdAt) == nil {
			items = append(items, workspaceInvitationResponse(id, workspaceID, workspaceKey, workspaceName, email, roles, expiresAt, acceptedAt, revokedAt, createdAt))
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) revokeWorkspaceInvitation(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE workspace_invitations SET revoked_at=now()
WHERE id=$1 AND application_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, chi.URLParam(r, "invitation_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_invitation_not_found", "The pending workspace invitation was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listMyWorkspaceInvitations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT i.id,i.workspace_id,t.key,t.name,i.normalized_email,i.roles,i.expires_at,
i.accepted_at,i.revoked_at,i.created_at FROM workspace_invitations i JOIN workspaces t ON t.id=i.workspace_id JOIN users u
ON u.application_id=i.application_id AND u.normalized_email=i.normalized_email
WHERE i.application_id=$1 AND u.id=$2 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>now()
ORDER BY i.created_at DESC,i.id DESC`, chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Workspace invitations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, workspaceID, workspaceKey, workspaceName, email string
		var roles []string
		var expiresAt, createdAt time.Time
		var acceptedAt, revokedAt *time.Time
		if rows.Scan(&id, &workspaceID, &workspaceKey, &workspaceName, &email, &roles, &expiresAt, &acceptedAt, &revokedAt, &createdAt) == nil {
			items = append(items, workspaceInvitationResponse(id, workspaceID, workspaceKey, workspaceName, email, roles, expiresAt, acceptedAt, revokedAt, createdAt))
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) acceptWorkspaceInvitation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		InvitationToken string `json:"invitation_token"`
	}
	if !kernel.DecodeJSON(w, r, &request) || request.InvitationToken == "" {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The invitation could not be accepted.")
		return
	}
	defer rollback(tx, r.Context())
	var workspaceID, invitedEmail string
	var roleKeys []string
	var credentialDigest []byte
	err = tx.QueryRow(r.Context(), `SELECT workspace_id,normalized_email,roles,credential_digest FROM workspace_invitations
WHERE id=$1 AND application_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`,
		chi.URLParam(r, "invitation_id"), chi.URLParam(r, "application_id")).Scan(&workspaceID, &invitedEmail, &roleKeys, &credentialDigest)
	var userEmail string
	if err == nil {
		err = tx.QueryRow(r.Context(), `SELECT normalized_email FROM users WHERE id=$1 AND application_id=$2 AND status='active'`,
			actor(r).ID, chi.URLParam(r, "application_id")).Scan(&userEmail)
	}
	if err != nil || userEmail != invitedEmail || !equalBytes(credentialDigest, s.app.Vault.Digest(request.InvitationToken)) {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_workspace_invitation", "The workspace invitation is invalid, expired, or belongs to another account.")
		return
	}
	rows, err := tx.Query(r.Context(), `SELECT id FROM roles WHERE application_id=$1 AND scope='workspace' AND key=ANY($2)`,
		chi.URLParam(r, "application_id"), roleKeys)
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
	if err != nil || len(roleIDs) != len(roleKeys) {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_invitation_roles_changed", "One or more invited roles are no longer available.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO workspace_memberships(application_id,workspace_id,user_id)
VALUES($1,$2,$3) ON CONFLICT(workspace_id,user_id) DO NOTHING`, chi.URLParam(r, "application_id"), workspaceID, actor(r).ID)
	for _, roleID := range roleIDs {
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO role_assignments(id,application_id,user_id,role_id,workspace_id)
VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, kernel.NewID(), chi.URLParam(r, "application_id"), actor(r).ID, roleID, workspaceID)
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE workspace_invitations SET accepted_at=now() WHERE id=$1`, chi.URLParam(r, "invitation_id"))
	}
	applicationID, parseErr := uuid.Parse(chi.URLParam(r, "application_id"))
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "workspace.invitation_accepted", "workspace_invitation/"+chi.URLParam(r, "invitation_id"), actor(r),
			map[string]any{"invitation_id": chi.URLParam(r, "invitation_id"), "workspace_id": workspaceID, "user_id": actor(r).ID})
	}
	if err != nil || parseErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "workspace_invitation_acceptance_failed", "The invitation acceptance could not be committed.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"workspace_id": workspaceID, "role_keys": roleKeys, "accepted": true})
}

func workspaceInvitationResponse(id, workspaceID, workspaceKey, workspaceName, email string, roles []string, expiresAt time.Time, acceptedAt, revokedAt *time.Time, createdAt time.Time) map[string]any {
	status := "pending"
	if acceptedAt != nil {
		status = "accepted"
	} else if revokedAt != nil {
		status = "revoked"
	} else if expiresAt.Before(time.Now()) {
		status = "expired"
	}
	return map[string]any{"id": id, "workspace_id": workspaceID, "workspace_key": workspaceKey, "workspace_name": workspaceName, "email": email,
		"role_keys": roles, "expires_at": expiresAt, "accepted_at": acceptedAt, "revoked_at": revokedAt, "created_at": createdAt, "status": status}
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func (s *Server) listMyWorkspaces(w http.ResponseWriter, r *http.Request) {
	s.listWorkspaces(w, r)
}

func (s *Server) checkPermissions(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Permissions []string `json:"permissions"`
		WorkspaceID *string  `json:"workspace_id"`
	}
	if !kernel.DecodeJSON(w, r, &request) || len(request.Permissions) == 0 || len(request.Permissions) > 100 {
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT ro.key,unnest(ro.permissions) FROM role_assignments ra
JOIN roles ro ON ro.id=ra.role_id WHERE ra.application_id=$1 AND ra.user_id=$2
AND (ra.workspace_id IS NULL OR ra.workspace_id=$3)`, chi.URLParam(r, "application_id"), actor(r).ID, request.WorkspaceID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Permissions could not be evaluated.")
		return
	}
	defer rows.Close()
	sources := map[string][]string{}
	for rows.Next() {
		var role, permission string
		if rows.Scan(&role, &permission) == nil {
			sources[permission] = append(sources[permission], role)
		}
	}
	results := make([]map[string]any, 0, len(request.Permissions))
	for _, wanted := range request.Permissions {
		matched := []string{}
		for granted, roles := range sources {
			if permissionMatches(granted, wanted) {
				matched = append(matched, roles...)
			}
		}
		results = append(results, map[string]any{"permission": wanted, "allowed": len(matched) > 0, "roles": matched})
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"workspace_id": request.WorkspaceID, "results": results})
}

func permissionMatches(granted, wanted string) bool {
	if granted == wanted || granted == "*" {
		return true
	}
	if !strings.HasSuffix(granted, "/*") {
		return false
	}
	base := strings.TrimSuffix(granted, "/*")
	return wanted == base || strings.HasPrefix(wanted, base+"/")
}
