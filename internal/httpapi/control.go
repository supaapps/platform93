package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)

type createNamedRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	var request createNamedRequest
	if !kernel.DecodeJSON(w, r, &request) || !validNameSlug(request.Name, request.Slug) {
		if request.Name != "" || request.Slug != "" {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_organization", "Name and slug are invalid.")
		}
		return
	}
	id := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The organization could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), "INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", id, request.Name, request.Slug)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO organization_memberships
(organization_id,operator_id,role) VALUES ($1,$2,'owner')`, id, actor(r).ID)
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, nil, "organization.created", "organization/"+id.String(), actor(r), request)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "organization_conflict", "An organization with this slug already exists.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "name": request.Name, "slug": request.Slug, "version": 1})
}

func (s *Server) listOrganizations(w http.ResponseWriter, r *http.Request) {
	includeRetired := r.URL.Query().Get("include_retired") == "true"
	installationRole, installationAccess := s.installationRole(r)
	rows, err := s.app.DB.Query(r.Context(), `SELECT o.id,o.name,o.slug,o.version,o.created_at,o.updated_at,
COALESCE(m.role,$4),o.deleted_at FROM organizations o
LEFT JOIN organization_memberships m ON m.organization_id=o.id AND m.operator_id=$1
WHERE ($3 OR m.operator_id IS NOT NULL) AND ($2 OR o.deleted_at IS NULL) ORDER BY o.created_at,o.id`, actor(r).ID, includeRetired, installationAccess, "installation:"+installationRole)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Organizations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, slug, role string
		var created, updated time.Time
		var retiredAt *time.Time
		var version int64
		if rows.Scan(&id, &name, &slug, &version, &created, &updated, &role, &retiredAt) == nil {
			items = append(items, map[string]any{"id": id, "name": name, "slug": slug, "version": version, "role": role, "created_at": created, "updated_at": updated, "retired_at": retiredAt})
		}
	}
	var currentInstallationRole any
	if installationAccess {
		currentInstallationRole = installationRole
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil, "installation_role": currentInstallationRole})
}

func (s *Server) getOrganization(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "organization_id")
	var value map[string]any
	var name, slug, role string
	var version int64
	if actor(r).Type == "management_client" {
		err := s.app.DB.QueryRow(r.Context(), `SELECT name,slug,version FROM organizations WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&name, &slug, &version)
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
			return
		}
		w.Header().Set("ETag", kernel.ETag(version))
		kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "name": name, "slug": slug, "version": version})
		return
	}
	installationRole, installationAccess := s.installationRole(r)
	err := s.app.DB.QueryRow(r.Context(), `SELECT o.name,o.slug,o.version,COALESCE(m.role,$4) FROM organizations o
LEFT JOIN organization_memberships m ON m.organization_id=o.id AND m.operator_id=$2
WHERE o.id=$1 AND ($3 OR m.operator_id IS NOT NULL) AND o.deleted_at IS NULL`, id, actor(r).ID, installationAccess, "installation:"+installationRole).Scan(&name, &slug, &version, &role)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
		return
	}
	value = map[string]any{"id": id, "name": name, "slug": slug, "version": version, "role": role}
	w.Header().Set("ETag", kernel.ETag(version))
	kernel.WriteJSON(w, http.StatusOK, value)
}

func (s *Server) updateOrganization(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name string `json:"name"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 255 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_organization_name", "Organization name must contain between 1 and 255 characters.")
		return
	}
	var version int64
	_, allowed := s.organizationManagementRole(r, chi.URLParam(r, "organization_id"))
	err := s.app.DB.QueryRow(r.Context(), `SELECT version FROM organizations WHERE id=$1 AND deleted_at IS NULL`, chi.URLParam(r, "organization_id")).Scan(&version)
	if err != nil || !allowed {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found or cannot be changed.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE organizations SET name=$1,version=version+1,updated_at=now()
WHERE id=$2 AND version=$3`, request.Name, chi.URLParam(r, "organization_id"), version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "organization_version_conflict", "The organization changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	var request createNamedRequest
	if !kernel.DecodeJSON(w, r, &request) || !validNameSlug(request.Name, request.Slug) {
		return
	}
	organizationID := chi.URLParam(r, "organization_id")
	_, allowed := s.organizationManagementRole(r, organizationID)
	var active bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND deleted_at IS NULL)`, organizationID).Scan(&active)
	allowed = allowed && active
	if !allowed {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "The operator cannot create applications in this organization.")
		return
	}
	id := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The application could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	if err = enforceApplicationLimit(r.Context(), tx, organizationID); err != nil {
		if limit, ok := err.(organizationLimitError); ok {
			kernel.WriteProblem(w, r, http.StatusConflict, "organization_application_limit_reached", limit.Error())
			return
		}
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "organization_policy_unavailable", "The organization application limit could not be checked.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO applications (id,organization_id,name,slug)
VALUES ($1,$2,$3,$4)`, id, organizationID, request.Name, request.Slug)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO roles (id,application_id,key,name,scope,permissions,built_in)
VALUES ($1,$2,'application_admin','Application administrator','application',ARRAY[$4],true),
($3,$2,'workspace_member','Workspace member','workspace',ARRAY['read'],true),
($5,$2,'event_publisher','Event publisher','application',ARRAY['events:publish'],true)`, kernel.NewID(), id, kernel.NewID(), "/applications/"+id.String()+"/*", kernel.NewID())
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &id, "application.created", "application/"+id.String(), actor(r), request)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "application_conflict", "The application could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "organization_id": organizationID, "name": request.Name, "slug": request.Slug, "issuer": s.app.Issuer(), "audience": s.app.ApplicationAudience(id), "auth_config": map[string]any{}, "public_config": map[string]any{}, "internal_config": defaultApplicationInternalConfig(), "version": 1})
}

func (s *Server) updateApplication(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name string `json:"name"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 255 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_application_name", "Application name must contain between 1 and 255 characters.")
		return
	}
	organizationID, applicationID := chi.URLParam(r, "organization_id"), chi.URLParam(r, "application_resource_id")
	if _, allowed := s.organizationManagementRole(r, organizationID); !allowed {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found or cannot be changed.")
		return
	}
	var version int64
	err := s.app.DB.QueryRow(r.Context(), `SELECT a.version FROM applications a
JOIN organizations o ON o.id=a.organization_id
WHERE a.id=$1 AND a.organization_id=$2 AND a.deleted_at IS NULL AND o.deleted_at IS NULL`, applicationID, organizationID).Scan(&version)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found or cannot be changed.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE applications SET name=$1,version=version+1,updated_at=now()
WHERE id=$2 AND organization_id=$3 AND version=$4 AND deleted_at IS NULL`, request.Name, applicationID, organizationID, version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "application_version_conflict", "The application changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listApplications(w http.ResponseWriter, r *http.Request) {
	includeRetired := r.URL.Query().Get("include_retired") == "true"
	if !s.operatorBelongsToOrganization(r, chi.URLParam(r, "organization_id")) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,name,slug,version,created_at,deleted_at FROM applications
WHERE organization_id=$1 AND ($2 OR deleted_at IS NULL) ORDER BY created_at,id`, chi.URLParam(r, "organization_id"), includeRetired)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Applications could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, slug string
		var version int64
		var created time.Time
		var retiredAt *time.Time
		if rows.Scan(&id, &name, &slug, &version, &created, &retiredAt) == nil {
			items = append(items, map[string]any{"id": id, "organization_id": chi.URLParam(r, "organization_id"), "name": name, "slug": slug, "issuer": s.app.Issuer(), "audience": "platform93:application:" + id, "version": version, "created_at": created, "retired_at": retiredAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getApplication(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "application_id")
	var name, slug, organizationID string
	var version int64
	var authJSON, publicJSON, internalJSON []byte
	err := s.app.DB.QueryRow(r.Context(), `SELECT name,slug,organization_id,auth_config,public_config,internal_config,version FROM applications
WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&name, &slug, &organizationID, &authJSON, &publicJSON, &internalJSON, &version)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version))
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "organization_id": organizationID, "name": name, "slug": slug, "issuer": s.app.Issuer(), "audience": "platform93:application:" + id, "auth_config": decodeMap(authJSON), "public_config": decodeMap(publicJSON), "internal_config": decodeMap(internalJSON), "version": version})
}

func (s *Server) updateAuthConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if !kernel.DecodeJSON(w, r, &raw) {
		return
	}
	allowed := map[string]bool{"flows": true}
	for key := range raw {
		if !allowed[key] {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_auth_config", "The authentication configuration contains an unknown setting.")
			return
		}
	}
	var currentJSON []byte
	var version int64
	if err := s.app.DB.QueryRow(r.Context(), `SELECT auth_config,version FROM applications WHERE id=$1 AND deleted_at IS NULL`, chi.URLParam(r, "application_id")).Scan(&currentJSON, &version); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	current := decodeMap(currentJSON)
	if value, exists := raw["flows"]; exists {
		flows, flowErr := parseApplicationFlowConfig(value)
		var validationErr error
		if flowErr == nil {
			validationErr = s.validateApplicationFlowConfig(r.Context(), chi.URLParam(r, "application_id"), flows)
		}
		if flowErr != nil || validationErr != nil {
			detail := "The authentication flow configuration is invalid."
			if flowErr != nil {
				detail = flowErr.Error()
			} else if validationErr != nil {
				detail = validationErr.Error()
			}
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_auth_flow_config", detail)
			return
		}
		if flows == (applicationFlowConfig{}) {
			delete(current, "flows")
		} else {
			current["flows"] = flows
		}
	}
	value, _ := json.Marshal(current)
	result, err := s.app.DB.Exec(r.Context(), `UPDATE applications SET auth_config=$1,version=version+1,updated_at=now()
WHERE id=$2 AND version=$3 AND deleted_at IS NULL`, value, chi.URLParam(r, "application_id"), version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "application_version_conflict", "The application changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publicConfig(w http.ResponseWriter, r *http.Request) {
	var authConfig, publicConfig, internalConfig []byte
	err := s.app.DB.QueryRow(r.Context(), "SELECT auth_config,public_config,internal_config FROM applications WHERE id=$1 AND deleted_at IS NULL", chi.URLParam(r, "application_id")).Scan(&authConfig, &publicConfig, &internalConfig)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return
	}
	internal := defaultApplicationInternalConfig()
	if json.Unmarshal(internalConfig, &internal) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invalid_stored_config", "The application configuration is invalid.")
		return
	}
	auth := decodeMap(authConfig)
	auth["registration_mode"] = internal.RegistrationMode
	auth["registration_enabled"] = internal.RegistrationMode == "public"
	auth["password_enabled"] = internal.PasswordEnabled
	auth["passwordless_enabled"] = internal.PasswordlessEnabled
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"schema_version": "1.1", "api_base": s.app.PublicURL + "/v1", "issuer": s.app.Issuer(), "application_id": chi.URLParam(r, "application_id"), "public_config": decodeMap(publicConfig), "auth": auth})
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ClientID      string   `json:"client_id"`
		Name          string   `json:"name"`
		ClientType    string   `json:"client_type"`
		RedirectURIs  []string `json:"redirect_uris"`
		AllowedGrants []string `json:"allowed_grants"`
		AllowedScopes []string `json:"allowed_scopes"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.ClientType != "public" && request.ClientType != "confidential" && request.ClientType != "machine" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_client_type", "Client type must be public, confidential, or machine.")
		return
	}
	id := kernel.NewID()
	var secret string
	var digest []byte
	if request.ClientType != "public" {
		secret, _ = secure.RandomToken("p93_client_", 32)
		digest = s.app.Vault.Digest(secret)
	}
	_, err := s.app.DB.Exec(r.Context(), `INSERT INTO clients
(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes,secret_digest)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, chi.URLParam(r, "application_id"), request.ClientID, request.Name,
		request.ClientType, request.RedirectURIs, request.AllowedGrants, request.AllowedScopes, digest)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "client_conflict", "The client could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "client_id": request.ClientID, "name": request.Name, "client_type": request.ClientType, "client_secret": optionalSecret(secret)})
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes,created_at
FROM clients WHERE application_id=$1 AND disabled_at IS NULL ORDER BY created_at,id`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Clients could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, clientID, name, clientType string
		var created time.Time
		var redirects, grants, scopes []string
		if rows.Scan(&id, &clientID, &name, &clientType, &redirects, &grants, &scopes, &created) == nil {
			items = append(items, map[string]any{"id": id, "client_id": clientID, "name": name, "client_type": clientType, "redirect_uris": redirects, "allowed_grants": grants, "allowed_scopes": scopes, "created_at": created})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func validNameSlug(name, slug string) bool {
	return strings.TrimSpace(name) != "" && slugPattern.MatchString(slug)
}

type namedRows interface {
	Next() bool
	Scan(...any) error
}

func scanNamedRows(rows namedRows) []map[string]any {
	items := []map[string]any{}
	for rows.Next() {
		var id, name, slug string
		var created time.Time
		var version int64
		if rows.Scan(&id, &name, &slug, &version, &created) == nil {
			items = append(items, map[string]any{"id": id, "name": name, "slug": slug, "version": version, "created_at": created})
		}
	}
	return items
}

func optionalSecret(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func parseUUID(value string) (uuid.UUID, bool) {
	id, err := uuid.Parse(value)
	return id, err == nil
}
