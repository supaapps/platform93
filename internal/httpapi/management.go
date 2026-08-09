package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

const managementOrganizationsScope = "/management/organizations/*"

type managementOAuthClient struct {
	ID       string
	ClientID string
}

type managementOAuthClientContextKey struct{}

func managementClientFromContext(ctx context.Context) (managementOAuthClient, bool) {
	value, ok := ctx.Value(managementOAuthClientContextKey{}).(managementOAuthClient)
	return value, ok
}

func (s *Server) resolveManagementOAuthClient(r *http.Request, clientID string) (*http.Request, bool) {
	if r.FormValue("grant_type") != "client_credentials" || clientID == "" {
		return r, false
	}
	var client managementOAuthClient
	err := s.app.DB.QueryRow(r.Context(), `SELECT c.id,c.client_id FROM management_clients c
JOIN installations i ON i.management_api_enabled
WHERE c.client_id=$1 AND c.disabled_at IS NULL`, clientID).Scan(&client.ID, &client.ClientID)
	if err != nil {
		return r, false
	}
	return r.WithContext(context.WithValue(r.Context(), managementOAuthClientContextKey{}, client)), true
}

func (s *Server) issueManagementToken(w http.ResponseWriter, r *http.Request, resolved managementOAuthClient) {
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID, secret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	var id string
	var digest []byte
	var allowedScopes []string
	err := s.app.DB.QueryRow(r.Context(), `SELECT c.id,c.secret_digest,c.allowed_scopes FROM management_clients c
JOIN installations i ON i.management_api_enabled
WHERE c.id=$1 AND c.client_id=$2 AND c.disabled_at IS NULL`, resolved.ID, clientID).Scan(&id, &digest, &allowedScopes)
	if err != nil || secret == "" || !hmac.Equal(digest, s.app.Vault.Digest(secret)) {
		w.Header().Set("WWW-Authenticate", `Basic realm="platform93-management"`)
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_management_client", "The management client credentials are invalid or the management API is disabled.")
		return
	}
	requested := uniqueStrings(strings.Fields(r.FormValue("scope")))
	if len(requested) == 0 {
		requested = allowedScopes
	}
	for _, scope := range requested {
		if !scopeAllowed(scope, allowedScopes) {
			kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_management_scope", "The requested management scope is not allowed for this client.")
			return
		}
	}
	kid, privateKey, err := s.app.ActiveSigningKey(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "signing_key_unavailable", "A management access token could not be signed.")
		return
	}
	now := s.app.Now().UTC()
	token, err := identity.Sign(privateKey, kid, identity.Claims{
		Issuer: s.app.Issuer(), Subject: id, Audience: []string{s.app.ControlAudience()},
		ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(), NotBefore: now.Add(-5 * time.Second).Unix(),
		JWTID: kernel.NewID().String(), ClientID: clientID, TokenKind: "management", ActorType: "management_client",
		Scope: strings.Join(requested, " "), AMR: []string{"client_credentials"},
	})
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "token_issuance_failed", "A management access token could not be issued.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 300, "scope": strings.Join(requested, " ")})
}

func scopeAllowed(requested string, allowed []string) bool {
	current := kernel.Actor{Permissions: allowed}
	return actorHasPermission(current, requested)
}

func (s *Server) requireManagementClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "management_access_required", "A management client Bearer JWT is required.")
			return
		}
		claims, err := identity.Verify(strings.TrimSpace(authorization[7:]), func(kid string) (*rsa.PublicKey, error) {
			return s.app.ResolvePublicKey(r.Context(), kid)
		}, s.app.Issuer(), s.app.ControlAudience(), s.app.Now())
		if err != nil || claims.ActorType != "management_client" || claims.TokenKind != "management" || claims.SessionID != "" {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_management_access", "The management access token is invalid or expired.")
			return
		}
		var live bool
		err = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM management_clients c
JOIN installations i ON i.management_api_enabled WHERE c.id=$1 AND c.client_id=$2 AND c.disabled_at IS NULL)`, claims.Subject, claims.ClientID).Scan(&live)
		current := kernel.Actor{Type: "management_client", ID: claims.Subject, Permissions: strings.Fields(claims.Scope)}
		if err != nil || !live {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_management_access", "The management client is disabled or the management API is not active.")
			return
		}
		if !actorHasPermission(current, managementOrganizationsScope) {
			kernel.WriteProblem(w, r, http.StatusForbidden, "management_scope_required", "The active management client is not allowed to manage organizations.")
			return
		}
		request := r.WithContext(kernel.WithActor(r.Context(), current))
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, request)
			return
		}
		recorder := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, request)
		if recorder.status >= 200 && recorder.status < 300 {
			var organizationID any
			if value := chi.URLParam(r, "organization_id"); value != "" {
				organizationID = value
			}
			_, _ = s.app.DB.Exec(r.Context(), `INSERT INTO audit_records
(id,organization_id,actor_type,actor_id,action,target_type,reason,request_id,changes)
VALUES($1,$2,'management_client',$3,$4,'http_route',$5,$6,jsonb_build_object('method',$7::text,'path',$8::text))`,
				kernel.NewID(), organizationID, current.ID, "http."+strings.ToLower(r.Method), truncate(r.Header.Get("X-Audit-Reason"), 500), kernel.RequestID(r.Context()), r.Method, r.URL.Path)
		}
	})
}

func (s *Server) getManagementAPIStatus(w http.ResponseWriter, r *http.Request) {
	role, ok := s.installationRole(r)
	if !ok {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation role is required.")
		return
	}
	var enabled bool
	var activeClients int
	err := s.app.DB.QueryRow(r.Context(), `SELECT i.management_api_enabled,
(SELECT count(*) FROM management_clients WHERE disabled_at IS NULL) FROM installations i LIMIT 1`).Scan(&enabled, &activeClients)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "management_status_unavailable", "The management API status could not be loaded.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "can_manage": role == "owner" || role == "admin", "active_clients": activeClients, "token_endpoint": s.app.PublicURL + "/oidc/token", "api_base": s.app.PublicURL + "/v1/management"})
}

func (s *Server) updateManagementAPIStatus(w http.ResponseWriter, r *http.Request) {
	if !s.installationCanWrite(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required.")
		return
	}
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	_, err := s.app.DB.Exec(r.Context(), "UPDATE installations SET management_api_enabled=$1,updated_at=now()", request.Enabled)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "management_status_update_failed", "The management API status could not be updated.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]bool{"enabled": request.Enabled})
}

func (s *Server) listManagementClients(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.installationRole(r); !ok {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation role is required.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,client_id,name,allowed_scopes,disabled_at,version,created_at,updated_at
FROM management_clients ORDER BY created_at,id`)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "management_clients_unavailable", "Management clients could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, clientID, name string
		var scopes []string
		var disabledAt *time.Time
		var version int64
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &clientID, &name, &scopes, &disabledAt, &version, &createdAt, &updatedAt) == nil {
			items = append(items, map[string]any{"id": id, "client_id": clientID, "name": name, "allowed_scopes": scopes, "disabled_at": disabledAt, "version": version, "created_at": createdAt, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) createManagementClient(w http.ResponseWriter, r *http.Request) {
	if !s.installationCanWrite(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required.")
		return
	}
	var request struct {
		ClientID string   `json:"client_id"`
		Name     string   `json:"name"`
		Scopes   []string `json:"allowed_scopes,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.ClientID, request.Name = strings.TrimSpace(request.ClientID), strings.TrimSpace(request.Name)
	if len(request.Scopes) == 0 {
		request.Scopes = []string{managementOrganizationsScope}
	}
	if request.ClientID == "" || request.Name == "" || len(request.ClientID) > 160 || len(request.Name) > 200 || !validManagementScopes(request.Scopes) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_management_client", "A client ID, name, and supported management scope are required.")
		return
	}
	secret, err := secure.RandomToken("p93_mgmt_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The management client secret could not be generated.")
		return
	}
	id := kernel.NewID()
	result, err := s.app.DB.Exec(r.Context(), `INSERT INTO management_clients(id,client_id,name,secret_digest,allowed_scopes)
SELECT $1,$2,$3,$4,$5 WHERE NOT EXISTS(SELECT 1 FROM clients WHERE client_id=$2)`, id, request.ClientID, request.Name, s.app.Vault.Digest(secret), uniqueStrings(request.Scopes))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "management_client_conflict", "The management client ID already exists.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "client_id": request.ClientID, "name": request.Name, "allowed_scopes": request.Scopes, "client_secret": secret, "secret_returned_once": true, "version": 1})
}

func (s *Server) rotateManagementClientSecret(w http.ResponseWriter, r *http.Request) {
	if !s.installationCanWrite(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required.")
		return
	}
	secret, _ := secure.RandomToken("p93_mgmt_", 32)
	if secret == "" {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The management client secret could not be generated.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE management_clients SET secret_digest=$1,version=version+1,updated_at=now()
WHERE id=$2 AND disabled_at IS NULL`, s.app.Vault.Digest(secret), chi.URLParam(r, "management_client_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "management_client_not_found", "An active management client was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"client_secret": secret, "secret_returned_once": true})
}

func (s *Server) disableManagementClient(w http.ResponseWriter, r *http.Request) {
	if !s.installationCanWrite(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE management_clients SET disabled_at=now(),version=version+1,updated_at=now()
WHERE id=$1 AND disabled_at IS NULL`, chi.URLParam(r, "management_client_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "management_client_not_found", "An active management client was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) installationCanWrite(r *http.Request) bool {
	role, ok := s.installationRole(r)
	return ok && (role == "owner" || role == "admin")
}

func validManagementScopes(scopes []string) bool {
	if len(scopes) != 1 {
		return false
	}
	return scopes[0] == managementOrganizationsScope
}

func (s *Server) managementCreateOrganization(w http.ResponseWriter, r *http.Request) {
	var request createNamedRequest
	if !kernel.DecodeJSON(w, r, &request) || !validNameSlug(request.Name, request.Slug) {
		if request.Name != "" || request.Slug != "" {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_organization", "Name and slug are invalid.")
		}
		return
	}
	id := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), "INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3)", id, request.Name, request.Slug)
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, nil, "organization.created", "organization/"+id.String(), actor(r), request)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "organization_conflict", "An organization with this slug already exists or could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "name": request.Name, "slug": request.Slug, "version": 1})
}

func (s *Server) managementListOrganizations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,name,slug,version,created_at,updated_at,deleted_at FROM organizations
WHERE ($1 OR deleted_at IS NULL) ORDER BY created_at,id`, r.URL.Query().Get("include_retired") == "true")
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Organizations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, slug string
		var version int64
		var createdAt, updatedAt time.Time
		var retiredAt *time.Time
		if rows.Scan(&id, &name, &slug, &version, &createdAt, &updatedAt, &retiredAt) == nil {
			items = append(items, map[string]any{"id": id, "name": name, "slug": slug, "version": version, "created_at": createdAt, "updated_at": updatedAt, "retired_at": retiredAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}
