package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
	"github.com/supaapps/platform93/internal/kernel"
)

type permissionGrantRequest struct {
	SubjectType string  `json:"subject_type"`
	SubjectID   string  `json:"subject_id"`
	WorkspaceID *string `json:"workspace_id,omitempty"`
	Permission  string  `json:"permission"`
	Reason      string  `json:"reason,omitempty"`
}

func (s *Server) createPermissionGrant(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "idempotency_key_required", "Permission grant creation requires an Idempotency-Key header.")
		return
	}
	var request permissionGrantRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if workspaceID := chi.URLParam(r, "workspace_id"); workspaceID != "" {
		if request.WorkspaceID != nil && *request.WorkspaceID != workspaceID {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission_grant_workspace", "The request workspace must match the route workspace.")
			return
		}
		request.WorkspaceID = &workspaceID
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.SubjectType != "user" && request.SubjectType != "client" || request.SubjectID == "" || len(request.Reason) > 500 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission_grant", "A user or client subject and an optional reason of at most 500 characters are required.")
		return
	}
	if err := platformauthz.ValidateRelativePermission(request.Permission); err != nil || strings.Split(request.Permission, ":")[0] == "roles" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission", "Permission must be a lowercase ASCII colon-delimited key; a wildcard is allowed only as the final complete segment.")
		return
	}
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	if _, err = uuid.Parse(request.SubjectID); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission_grant_subject", "The permission grant subject identifier is invalid.")
		return
	}
	if request.WorkspaceID != nil {
		if _, err = uuid.Parse(*request.WorkspaceID); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission_grant_workspace", "The permission grant workspace identifier is invalid.")
			return
		}
	}
	canonical, err := platformauthz.CanonicalScope(applicationID.String(), request.WorkspaceID, request.Permission)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission", "The permission could not be converted to a canonical application scope.")
		return
	}
	if !s.canManagePermissionGrant(r, applicationID, request.WorkspaceID, canonical) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "permission_grant_management_required", "The actor cannot grant this permission in the selected scope.")
		return
	}
	if !s.validPermissionGrantSubject(r, applicationID, request.SubjectType, request.SubjectID, request.WorkspaceID) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission_grant_subject", "The active subject is not eligible for the selected application or workspace.")
		return
	}
	id := kernel.NewID()
	current := actor(r)
	var userID, clientID *string
	if request.SubjectType == "user" {
		userID = &request.SubjectID
	} else {
		clientID = &request.SubjectID
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The permission grant could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO permission_grants
(id,application_id,user_id,client_id,workspace_id,permission,canonical_scope,reason,created_by_type,created_by_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, applicationID, userID, clientID, request.WorkspaceID, request.Permission, canonical, request.Reason, current.Type, current.ID)
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "authorization.permission_grant.created", "permission_grant/"+id.String(), current,
			map[string]any{"grant_id": id, "subject_type": request.SubjectType, "subject_id": request.SubjectID, "workspace_id": request.WorkspaceID, "permission": request.Permission, "canonical_scope": canonical})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "permission_grant_conflict", "An equivalent active permission grant already exists or the grant could not be committed.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(1))
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "application_id": applicationID, "subject_type": request.SubjectType,
		"subject_id": request.SubjectID, "workspace_id": request.WorkspaceID, "permission": request.Permission, "canonical_scope": canonical,
		"reason": request.Reason, "status": "active", "version": 1, "created_at": s.app.Now()})
}

func (s *Server) listPermissionGrants(w http.ResponseWriter, r *http.Request) {
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	workspaceID := chi.URLParam(r, "workspace_id")
	var workspace *string
	if workspaceID != "" {
		workspace = &workspaceID
	}
	if !s.canReadPermissionGrants(r, applicationID, workspace) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "permission_grant_read_required", "Permission grant read access is required.")
		return
	}
	subjectType := r.URL.Query().Get("subject_type")
	subjectID := r.URL.Query().Get("subject_id")
	status := r.URL.Query().Get("status")
	if subjectType != "" && subjectType != "user" && subjectType != "client" || status != "" && status != "active" && status != "revoked" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission_grant_filter", "Permission grant filters are invalid.")
		return
	}
	var subjectFilter any
	if subjectID != "" {
		parsedSubjectID, parseErr := uuid.Parse(subjectID)
		if parseErr != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission_grant_filter", "The permission grant subject filter must be a UUID.")
			return
		}
		subjectFilter = parsedSubjectID
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT application_id,id,user_id,client_id,workspace_id,permission,canonical_scope,reason,
created_by_type,created_by_id,revoked_by_type,revoked_by_id,revoked_reason,revoked_at,version,created_at
FROM permission_grants WHERE application_id=$1
AND ($2::uuid IS NULL OR workspace_id=$2) AND ($3='' OR ($3='user' AND user_id IS NOT NULL) OR ($3='client' AND client_id IS NOT NULL))
AND ($4::uuid IS NULL OR user_id=$4 OR client_id=$4)
AND ($5='' OR ($5='active' AND revoked_at IS NULL) OR ($5='revoked' AND revoked_at IS NOT NULL))
ORDER BY created_at DESC,id DESC`, applicationID, workspace, subjectType, subjectFilter, status)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Permission grants could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		if grant, ok := scanPermissionGrant(rows); ok {
			items = append(items, grant)
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getPermissionGrant(w http.ResponseWriter, r *http.Request) {
	grant, ok := s.loadPermissionGrant(r)
	if !ok {
		kernel.WriteProblem(w, r, http.StatusNotFound, "permission_grant_not_found", "The permission grant was not found.")
		return
	}
	applicationID, _ := uuid.Parse(chi.URLParam(r, "application_id"))
	workspaceID, _ := grant["workspace_id"].(*string)
	if routeWorkspace := chi.URLParam(r, "workspace_id"); routeWorkspace != "" && (workspaceID == nil || *workspaceID != routeWorkspace) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "permission_grant_not_found", "The permission grant was not found.")
		return
	}
	if !s.canReadPermissionGrants(r, applicationID, workspaceID) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "permission_grant_read_required", "Permission grant read access is required.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(grant["version"].(int64)))
	kernel.WriteJSON(w, http.StatusOK, grant)
}

func (s *Server) revokePermissionGrant(w http.ResponseWriter, r *http.Request) {
	grant, ok := s.loadPermissionGrant(r)
	if !ok {
		kernel.WriteProblem(w, r, http.StatusNotFound, "permission_grant_not_found", "The permission grant was not found.")
		return
	}
	applicationID, _ := uuid.Parse(chi.URLParam(r, "application_id"))
	workspaceID, _ := grant["workspace_id"].(*string)
	if routeWorkspace := chi.URLParam(r, "workspace_id"); routeWorkspace != "" && (workspaceID == nil || *workspaceID != routeWorkspace) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "permission_grant_not_found", "The permission grant was not found.")
		return
	}
	canonical := grant["canonical_scope"].(string)
	if !s.canManagePermissionGrants(r, applicationID, workspaceID) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "permission_grant_management_required", "The actor cannot revoke this permission grant.")
		return
	}
	version := grant["version"].(int64)
	if strings.TrimSpace(r.Header.Get("If-Match")) == "" {
		kernel.WriteProblem(w, r, http.StatusPreconditionRequired, "if_match_required", "Permission grant revocation requires the current ETag in If-Match.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	current := actor(r)
	reason := strings.TrimSpace(r.Header.Get("X-Audit-Reason"))
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The permission grant could not be revoked.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE permission_grants SET revoked_by_type=$1,revoked_by_id=$2,revoked_reason=$3,
revoked_at=now(),version=version+1 WHERE id=$4 AND application_id=$5 AND version=$6 AND revoked_at IS NULL`, current.Type, current.ID, reason,
		chi.URLParam(r, "grant_id"), applicationID, version)
	if err == nil && result.RowsAffected() == 1 {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "authorization.permission_grant.revoked", "permission_grant/"+chi.URLParam(r, "grant_id"), current,
			map[string]any{"grant_id": chi.URLParam(r, "grant_id"), "subject_type": grant["subject_type"], "subject_id": grant["subject_id"],
				"workspace_id": workspaceID, "permission": grant["permission"], "canonical_scope": canonical})
	} else if err == nil {
		err = http.ErrNotSupported
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "permission_grant_version_conflict", "The active permission grant changed concurrently.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) effectivePermissionAccess(w http.ResponseWriter, r *http.Request) {
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	workspaceID := r.URL.Query().Get("workspace_id")
	var workspace *string
	if workspaceID != "" {
		workspace = &workspaceID
	}
	if !s.canReadPermissionGrants(r, applicationID, workspace) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "permission_grant_read_required", "Effective access read permission is required.")
		return
	}
	subjectType, subjectID := r.URL.Query().Get("subject_type"), r.URL.Query().Get("subject_id")
	var access effectiveAccess
	if subjectType == "user" {
		access, err = s.userEffectiveAccess(r, applicationID, subjectID)
	} else if subjectType == "client" {
		var clientKey string
		err = s.app.DB.QueryRow(r.Context(), `SELECT client_id FROM clients WHERE id=$1 AND application_id=$2 AND disabled_at IS NULL`, subjectID, applicationID).Scan(&clientKey)
		if err == nil {
			access, err = s.clientEffectiveAccess(r, applicationID, clientKey)
		}
	} else {
		err = http.ErrNotSupported
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_permission_subject", "The effective-access subject is invalid or contains invalid authorization data.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"subject_type": subjectType, "subject_id": subjectID, "roles": access.Roles, "scopes": access.Scopes, "provenance": access.Provenance})
}

func (s *Server) loadPermissionGrant(r *http.Request) (map[string]any, bool) {
	return scanPermissionGrant(s.app.DB.QueryRow(r.Context(), `SELECT application_id,id,user_id,client_id,workspace_id,permission,canonical_scope,reason,
created_by_type,created_by_id,revoked_by_type,revoked_by_id,revoked_reason,revoked_at,version,created_at
FROM permission_grants WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "grant_id"), chi.URLParam(r, "application_id")))
}

func scanPermissionGrant(row scanner) (map[string]any, bool) {
	var applicationID, id, permission, canonical, reason, createdByType, createdByID string
	var userID, clientID, workspaceID, revokedByType, revokedByID, revokedReason *string
	var revokedAt *time.Time
	var version int64
	var createdAt time.Time
	if row.Scan(&applicationID, &id, &userID, &clientID, &workspaceID, &permission, &canonical, &reason, &createdByType, &createdByID,
		&revokedByType, &revokedByID, &revokedReason, &revokedAt, &version, &createdAt) != nil {
		return nil, false
	}
	subjectType, subjectID := "client", clientID
	if userID != nil {
		subjectType, subjectID = "user", userID
	}
	status := "active"
	if revokedAt != nil {
		status = "revoked"
	}
	return map[string]any{"id": id, "application_id": applicationID, "subject_type": subjectType, "subject_id": *subjectID, "workspace_id": workspaceID,
		"permission": permission, "canonical_scope": canonical, "reason": reason, "created_by": map[string]any{"type": createdByType, "id": createdByID},
		"revoked_by": nullableActor(revokedByType, revokedByID), "revoked_reason": revokedReason, "revoked_at": revokedAt,
		"status": status, "version": version, "created_at": createdAt}, true
}

func nullableActor(actorType, actorID *string) any {
	if actorType == nil || actorID == nil {
		return nil
	}
	return map[string]any{"type": *actorType, "id": *actorID}
}

func (s *Server) validPermissionGrantSubject(r *http.Request, applicationID uuid.UUID, subjectType, subjectID string, workspaceID *string) bool {
	var valid bool
	if subjectType == "user" {
		if workspaceID == nil {
			_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND application_id=$2 AND status='active')`, subjectID, applicationID).Scan(&valid)
		} else {
			_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users u JOIN workspaces w ON w.application_id=u.application_id
WHERE u.id=$1 AND u.application_id=$2 AND u.status='active' AND w.id=$3 AND w.deleted_at IS NULL
AND (w.owner_user_id=u.id OR EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=w.id AND m.user_id=u.id)))`, subjectID, applicationID, *workspaceID).Scan(&valid)
		}
	} else {
		_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients WHERE id=$1 AND application_id=$2 AND disabled_at IS NULL)`, subjectID, applicationID).Scan(&valid)
	}
	return valid
}

func (s *Server) canReadPermissionGrants(r *http.Request, applicationID uuid.UUID, workspaceID *string) bool {
	current := actor(r)
	if current.Type == "control_user" {
		return true
	}
	permission, err := platformauthz.CanonicalScope(applicationID.String(), workspaceID, "authorization:grants:read")
	if err == nil && actorHasPermission(current, permission) {
		return true
	}
	manage, err := platformauthz.CanonicalScope(applicationID.String(), workspaceID, "authorization:grants:manage")
	if err == nil && actorHasPermission(current, manage) {
		return true
	}
	return workspaceID != nil && current.Type == "user" && s.permissionGrantWorkspaceOwner(r, applicationID, current.ID, *workspaceID)
}

func (s *Server) canManagePermissionGrant(r *http.Request, applicationID uuid.UUID, workspaceID *string, grantedScope string) bool {
	if actor(r).Type == "control_user" {
		return true
	}
	return s.canManagePermissionGrants(r, applicationID, workspaceID) && actorHasPermission(actor(r), grantedScope)
}

func (s *Server) canManagePermissionGrants(r *http.Request, applicationID uuid.UUID, workspaceID *string) bool {
	current := actor(r)
	if current.Type == "control_user" {
		return true
	}
	manage, err := platformauthz.CanonicalScope(applicationID.String(), workspaceID, "authorization:grants:manage")
	manager := err == nil && actorHasPermission(current, manage)
	if workspaceID != nil && current.Type == "user" && s.permissionGrantWorkspaceOwner(r, applicationID, current.ID, *workspaceID) {
		manager = true
	}
	return manager
}

func (s *Server) permissionGrantWorkspaceOwner(r *http.Request, applicationID uuid.UUID, userID, workspaceID string) bool {
	var owner bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces
WHERE id=$1 AND application_id=$2 AND owner_user_id=$3 AND deleted_at IS NULL)`, workspaceID, applicationID, userID).Scan(&owner)
	return owner
}
