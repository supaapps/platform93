package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
	"github.com/supaapps/platform93/internal/kernel"
)

type ResourceCapability struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Context     string   `json:"context"`
	Permissions []string `json:"permissions"`
}

type OAuthResource struct {
	ID                  uuid.UUID            `json:"id"`
	ApplicationID       uuid.UUID            `json:"application_id"`
	URI                 string               `json:"uri"`
	Name                string               `json:"name"`
	Enabled             bool                 `json:"enabled"`
	AllowClientMetadata bool                 `json:"allow_client_metadata"`
	ClientIDs           []string             `json:"client_ids"`
	Capabilities        []ResourceCapability `json:"capabilities"`
	Version             int64                `json:"version"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           time.Time            `json:"updated_at"`
}

type OAuthConnection struct {
	ID              uuid.UUID   `json:"id"`
	ApplicationID   uuid.UUID   `json:"application_id"`
	ResourceID      uuid.UUID   `json:"resource_id"`
	ResourceVersion int64       `json:"resource_version"`
	UserID          uuid.UUID   `json:"user_id"`
	ClientID        string      `json:"client_id"`
	SessionID       uuid.UUID   `json:"session_id"`
	Capabilities    []string    `json:"capabilities"`
	PersonalAccess  bool        `json:"personal_access"`
	WorkspaceIDs    []uuid.UUID `json:"workspace_ids"`
	ExpiresAt       time.Time   `json:"expires_at"`
	RevokedAt       *time.Time  `json:"revoked_at"`
	Version         int64       `json:"version"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

const oauthResourceColumns = `id,application_id,uri,name,enabled,allow_client_metadata,client_ids,capabilities,version,created_at,updated_at`
const oauthConnectionColumns = `id,application_id,resource_id,resource_version,user_id,client_id,session_id,capabilities,personal_access,workspace_ids,expires_at,revoked_at,version,created_at,updated_at`

func scanOAuthResource(row scanner) (OAuthResource, error) {
	var v OAuthResource
	var capabilities []byte
	err := row.Scan(&v.ID, &v.ApplicationID, &v.URI, &v.Name, &v.Enabled, &v.AllowClientMetadata, &v.ClientIDs, &capabilities, &v.Version, &v.CreatedAt, &v.UpdatedAt)
	if err == nil {
		err = json.Unmarshal(capabilities, &v.Capabilities)
	}
	return v, err
}

func scanOAuthConnection(row scanner) (OAuthConnection, error) {
	var v OAuthConnection
	err := row.Scan(&v.ID, &v.ApplicationID, &v.ResourceID, &v.ResourceVersion, &v.UserID, &v.ClientID, &v.SessionID, &v.Capabilities, &v.PersonalAccess, &v.WorkspaceIDs, &v.ExpiresAt, &v.RevokedAt, &v.Version, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func (s *Server) loadOAuthResource(ctx context.Context, appID, resourceID string) (OAuthResource, error) {
	return scanOAuthResource(s.app.DB.QueryRow(ctx, `SELECT `+oauthResourceColumns+` FROM oauth_resources WHERE application_id=$1 AND id=$2`, appID, resourceID))
}

func (s *Server) loadOAuthConnection(ctx context.Context, appID, id string) (OAuthConnection, error) {
	return scanOAuthConnection(s.app.DB.QueryRow(ctx, `SELECT `+oauthConnectionColumns+` FROM oauth_connections WHERE application_id=$1 AND id=$2`, appID, id))
}

// Resource identifiers are normalized before the global uniqueness check.
func canonicalOAuthResourceURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u == nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", fmt.Errorf("resource URI must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.ContainsAny(raw, "\\ \t\r\n") {
		return "", fmt.Errorf("resource URI host is invalid")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return "", fmt.Errorf("local resource URI is not allowed")
		}
		host = ip.String()
	} else {
		if strings.Trim(host, "0123456789.") == "" {
			return "", fmt.Errorf("noncanonical IP address is not allowed")
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", fmt.Errorf("invalid host")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", fmt.Errorf("invalid host")
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid port")
		}
		port = strconv.Itoa(n)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" && port != "443" {
		host += ":" + port
	}
	u.Host = host
	if strings.ContainsAny(u.Path, "\\\x00\r\n\t") {
		return "", fmt.Errorf("invalid resource path")
	}
	for _, c := range u.Path {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("invalid resource path")
		}
	}
	if u.Path != "" {
		trailing := strings.HasSuffix(u.Path, "/")
		u.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
		if trailing && u.Path != "/" {
			u.Path += "/"
		}
	}
	if u.Path == "/" {
		u.Path = ""
	}
	u.RawPath = ""
	return u.String(), nil
}

func validateOAuthResource(v *OAuthResource) error {
	uri, err := canonicalOAuthResourceURI(v.URI)
	if err != nil {
		return err
	}
	v.URI = uri
	v.Name = strings.TrimSpace(v.Name)
	if len(v.Name) == 0 || len(v.Name) > 160 || len(v.ClientIDs) > 32 || len(v.Capabilities) == 0 || len(v.Capabilities) > 32 {
		return fmt.Errorf("name, client IDs, or capabilities exceed resource limits")
	}
	if v.ClientIDs == nil {
		v.ClientIDs = []string{}
	}
	seen := map[string]bool{}
	for _, id := range v.ClientIDs {
		if id == "" || len(id) > 2048 || id != strings.TrimSpace(id) || seen[id] || strings.ContainsAny(id, "\r\n\t ") {
			return fmt.Errorf("client IDs must be distinct nonempty external identifiers")
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, c := range v.Capabilities {
		first := strings.Split(c.Key, ":")[0]
		if platformauthz.ValidateRelativePermission(c.Key) != nil || strings.Contains(c.Key, "*") || first == "roles" || first == "workspaces" || seen[c.Key] || strings.TrimSpace(c.Name) == "" || len(c.Name) > 160 || (c.Context != "personal" && c.Context != "workspace") || c.Permissions == nil || len(c.Permissions) > 200 {
			return fmt.Errorf("invalid capability definition")
		}
		seen[c.Key] = true
		permissions := map[string]bool{}
		for _, p := range c.Permissions {
			if platformauthz.ValidateRelativePermission(p) != nil || strings.Contains(p, "*") || permissions[p] {
				return fmt.Errorf("capability permissions must be distinct explicit relative permissions")
			}
			permissions[p] = true
		}
	}
	return nil
}

func resourceIfMatch(w http.ResponseWriter, r *http.Request, version int64) bool {
	if strings.TrimSpace(r.Header.Get("If-Match")) == "" {
		kernel.WriteProblem(w, r, 428, "if_match_required", "The current version ETag is required.")
		return false
	}
	if strings.TrimSpace(r.Header.Get("If-Match")) != kernel.ETag(version) {
		kernel.WriteProblem(w, r, 412, "version_conflict", "The resource changed after it was loaded.")
		return false
	}
	return true
}

func (s *Server) emitResourceMutation(r *http.Request, tx pgx.Tx, appID uuid.UUID, event, kind string, id uuid.UUID, data map[string]any) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	current := actor(r)
	_, err = tx.Exec(r.Context(), `INSERT INTO audit_records(id,organization_id,application_id,actor_type,actor_id,action,target_type,target_id,request_id,changes)
SELECT $1,organization_id,id,$3,$4,$5,$6,$7,$8,$9 FROM applications WHERE id=$2`, kernel.NewID(), appID, current.Type, current.ID, event, kind, id.String(), kernel.RequestID(r.Context()), encoded)
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &appID, event, kind+"/"+id.String(), current, data)
	}
	return err
}

func (s *Server) createOAuthResource(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		kernel.WriteProblem(w, r, 400, "idempotency_key_required", "Resource creation requires an Idempotency-Key.")
		return
	}
	var request struct {
		URI                 string               `json:"uri"`
		Name                string               `json:"name"`
		Enabled             *bool                `json:"enabled"`
		AllowClientMetadata bool                 `json:"allow_client_metadata"`
		ClientIDs           []string             `json:"client_ids"`
		Capabilities        []ResourceCapability `json:"capabilities"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	appID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, 400, "invalid_application_id", "Invalid application identifier.")
		return
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	v := OAuthResource{ID: kernel.NewID(), ApplicationID: appID, URI: request.URI, Name: request.Name, Enabled: enabled, AllowClientMetadata: request.AllowClientMetadata, ClientIDs: request.ClientIDs, Capabilities: request.Capabilities}
	if err = validateOAuthResource(&v); err != nil {
		kernel.WriteProblem(w, r, 422, "invalid_oauth_resource", "A valid resource definition is required.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		resourceDatabaseProblem(w, r)
		return
	}
	defer rollback(tx, r.Context())
	if !s.validateResourceClients(w, r, tx, appID, v.ClientIDs, v.AllowClientMetadata) {
		return
	}
	capabilities, _ := json.Marshal(v.Capabilities)
	v, err = scanOAuthResource(tx.QueryRow(r.Context(), `INSERT INTO oauth_resources(id,application_id,uri,name,enabled,allow_client_metadata,client_ids,capabilities) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+oauthResourceColumns, v.ID, appID, v.URI, v.Name, v.Enabled, v.AllowClientMetadata, v.ClientIDs, capabilities))
	if err == nil {
		err = s.emitResourceMutation(r, tx, appID, "resource.created", "resource", v.ID, map[string]any{"resource_id": v.ID, "version": v.Version})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		resourceMutationProblem(w, r, err)
		return
	}
	w.Header().Set("ETag", kernel.ETag(v.Version))
	kernel.WriteJSON(w, 201, v)
}

func (s *Server) validateResourceClients(w http.ResponseWriter, r *http.Request, tx pgx.Tx, appID uuid.UUID, ids []string, allowMetadata bool) bool {
	registered := make([]string, 0, len(ids))
	for _, id := range ids {
		if allowMetadata && strings.HasPrefix(id, "https://") {
			if _, err := canonicalOAuthResourceURI(id); err != nil {
				kernel.WriteProblem(w, r, 422, "invalid_resource_clients", "Metadata client IDs must be valid HTTPS URLs.")
				return false
			}
			continue
		}
		registered = append(registered, id)
	}
	var count int
	err := tx.QueryRow(r.Context(), `SELECT count(*) FROM clients WHERE application_id=$1 AND client_id=ANY($2) AND disabled_at IS NULL AND NOT resource_only`, appID, registered).Scan(&count)
	if err != nil {
		resourceDatabaseProblem(w, r)
		return false
	}
	if count != len(registered) {
		kernel.WriteProblem(w, r, 422, "invalid_resource_clients", "Client IDs must identify registered active clients in this application.")
		return false
	}
	return true
}

func (s *Server) getOAuthResource(w http.ResponseWriter, r *http.Request) {
	if !resourceRouteIDs(w, r, "application_id", "resource_id") {
		return
	}
	v, err := s.loadOAuthResource(r.Context(), chi.URLParam(r, "application_id"), chi.URLParam(r, "resource_id"))
	if resourceLoadProblem(w, r, err, "resource") {
		return
	}
	w.Header().Set("ETag", kernel.ETag(v.Version))
	kernel.WriteJSON(w, 200, v)
}

func (s *Server) listOAuthResources(w http.ResponseWriter, r *http.Request) {
	if !resourceRouteIDs(w, r, "application_id") {
		return
	}
	cursor, ok := resourcePageCursor(w, r)
	if !ok {
		return
	}
	limit := pageLimit(r)
	rows, err := s.app.DB.Query(r.Context(), `SELECT `+oauthResourceColumns+` FROM oauth_resources WHERE application_id=$1 AND (created_at,id)<($2,$3::uuid) ORDER BY created_at DESC,id DESC LIMIT $4`, chi.URLParam(r, "application_id"), cursor.Time, cursor.ID, limit+1)
	if err != nil {
		resourceDatabaseProblem(w, r)
		return
	}
	defer rows.Close()
	items := []OAuthResource{}
	var next *string
	for rows.Next() {
		v, e := scanOAuthResource(rows)
		if e != nil {
			resourceDatabaseProblem(w, r)
			return
		}
		if len(items) == limit {
			c := encodeTimeCursor(items[limit-1].CreatedAt, items[limit-1].ID.String())
			next = &c
			break
		}
		items = append(items, v)
	}
	if rows.Err() != nil {
		resourceDatabaseProblem(w, r)
		return
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) updateOAuthResource(w http.ResponseWriter, r *http.Request) {
	if !resourceRouteIDs(w, r, "application_id", "resource_id") {
		return
	}
	var request struct {
		URI                 *string               `json:"uri"`
		Name                *string               `json:"name"`
		Enabled             *bool                 `json:"enabled"`
		AllowClientMetadata *bool                 `json:"allow_client_metadata"`
		ClientIDs           *[]string             `json:"client_ids"`
		Capabilities        *[]ResourceCapability `json:"capabilities"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	v, err := s.loadOAuthResource(r.Context(), chi.URLParam(r, "application_id"), chi.URLParam(r, "resource_id"))
	if resourceLoadProblem(w, r, err, "resource") {
		return
	}
	if !resourceIfMatch(w, r, v.Version) {
		return
	}
	if request.URI != nil {
		v.URI = *request.URI
	}
	if request.Name != nil {
		v.Name = *request.Name
	}
	if request.Enabled != nil {
		v.Enabled = *request.Enabled
	}
	if request.AllowClientMetadata != nil {
		v.AllowClientMetadata = *request.AllowClientMetadata
	}
	if request.ClientIDs != nil {
		v.ClientIDs = *request.ClientIDs
	}
	if request.Capabilities != nil {
		v.Capabilities = *request.Capabilities
	}
	if validateOAuthResource(&v) != nil {
		kernel.WriteProblem(w, r, 422, "invalid_oauth_resource", "The resource definition is invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		resourceDatabaseProblem(w, r)
		return
	}
	defer rollback(tx, r.Context())
	if !s.validateResourceClients(w, r, tx, v.ApplicationID, v.ClientIDs, v.AllowClientMetadata) {
		return
	}
	capabilities, _ := json.Marshal(v.Capabilities)
	v, err = scanOAuthResource(tx.QueryRow(r.Context(), `UPDATE oauth_resources SET uri=$1,name=$2,enabled=$3,allow_client_metadata=$4,client_ids=$5,capabilities=$6,version=version+1,updated_at=now() WHERE application_id=$7 AND id=$8 AND version=$9 RETURNING `+oauthResourceColumns, v.URI, v.Name, v.Enabled, v.AllowClientMetadata, v.ClientIDs, capabilities, v.ApplicationID, v.ID, v.Version))
	if err != nil {
		resourceUpdateProblem(w, r, err)
		return
	}
	if err == nil {
		err = s.emitResourceMutation(r, tx, v.ApplicationID, "resource.updated", "resource", v.ID, map[string]any{"resource_id": v.ID, "version": v.Version})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		resourceMutationProblem(w, r, err)
		return
	}
	w.Header().Set("ETag", kernel.ETag(v.Version))
	kernel.WriteJSON(w, 200, v)
}

func resourceDatabaseProblem(w http.ResponseWriter, r *http.Request) {
	kernel.WriteProblem(w, r, 500, "database_error", "Resource authorization data could not be loaded or committed.")
}

func resourceMutationProblem(w http.ResponseWriter, r *http.Request, err error) {
	if uniqueConstraint(err, "oauth_resources_uri_key") {
		kernel.WriteProblem(w, r, http.StatusConflict, "resource_conflict", "The resource URI is already registered.")
		return
	}
	resourceDatabaseProblem(w, r)
}

func resourceUpdateProblem(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		kernel.WriteProblem(w, r, http.StatusPreconditionFailed, "resource_version_conflict", "The resource changed concurrently.")
		return
	}
	resourceMutationProblem(w, r, err)
}

func resourceRouteIDs(w http.ResponseWriter, r *http.Request, names ...string) bool {
	for _, name := range names {
		if _, err := uuid.Parse(chi.URLParam(r, name)); err != nil {
			kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_"+name, "The route identifier must be a UUID.")
			return false
		}
	}
	return true
}
func resourceLoadProblem(w http.ResponseWriter, r *http.Request, err error, kind string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, pgx.ErrNoRows) {
		kernel.WriteProblem(w, r, 404, kind+"_not_found", "The requested "+kind+" was not found.")
	} else {
		resourceDatabaseProblem(w, r)
	}
	return true
}
func resourcePageCursor(w http.ResponseWriter, r *http.Request) (timeCursor, bool) {
	c, err := decodeTimeCursor(r.URL.Query().Get("cursor"))
	if err == nil {
		_, err = uuid.Parse(c.ID)
	}
	if err != nil {
		kernel.WriteProblem(w, r, 400, "invalid_cursor", "The pagination cursor is invalid.")
		return c, false
	}
	return c, true
}

func (s *Server) listResourceConnections(w http.ResponseWriter, r *http.Request) {
	s.writeResourceConnections(w, r, false)
}
func (s *Server) listMyConnections(w http.ResponseWriter, r *http.Request) {
	s.writeResourceConnections(w, r, true)
}
func (s *Server) getResourceConnection(w http.ResponseWriter, r *http.Request) {
	s.writeResourceConnection(w, r, false, false)
}
func (s *Server) getMyConnection(w http.ResponseWriter, r *http.Request) {
	s.writeResourceConnection(w, r, true, false)
}
func (s *Server) revokeResourceConnection(w http.ResponseWriter, r *http.Request) {
	s.writeResourceConnection(w, r, false, true)
}
func (s *Server) revokeMyConnection(w http.ResponseWriter, r *http.Request) {
	s.writeResourceConnection(w, r, true, true)
}

func resourceSelfActor(w http.ResponseWriter, r *http.Request) bool {
	if actor(r).Type != "user" || actor(r).ID == "" {
		kernel.WriteProblem(w, r, 403, "user_required", "An application user is required.")
		return false
	}
	if actor(r).DelegatedBy != "" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "delegated_session_forbidden", "Delegated sessions cannot manage external connections.")
		return false
	}
	return true
}

func (s *Server) writeResourceConnections(w http.ResponseWriter, r *http.Request, self bool) {
	if self && !resourceSelfActor(w, r) {
		return
	}
	if !resourceRouteIDs(w, r, "application_id") {
		return
	}
	if !self && !resourceRouteIDs(w, r, "resource_id") {
		return
	}
	var userID, resourceID *string
	if self {
		id := actor(r).ID
		userID = &id
	} else {
		id := chi.URLParam(r, "resource_id")
		resourceID = &id
		_, err := s.loadOAuthResource(r.Context(), chi.URLParam(r, "application_id"), id)
		if resourceLoadProblem(w, r, err, "resource") {
			return
		}
	}
	cursor, ok := resourcePageCursor(w, r)
	if !ok {
		return
	}
	limit := pageLimit(r)
	rows, err := s.app.DB.Query(r.Context(), `SELECT `+oauthConnectionColumns+` FROM oauth_connections WHERE application_id=$1 AND ($2::uuid IS NULL OR resource_id=$2) AND ($3::uuid IS NULL OR user_id=$3) AND (created_at,id)<($4,$5::uuid) ORDER BY created_at DESC,id DESC LIMIT $6`, chi.URLParam(r, "application_id"), resourceID, userID, cursor.Time, cursor.ID, limit+1)
	if err != nil {
		resourceDatabaseProblem(w, r)
		return
	}
	defer rows.Close()
	items := []OAuthConnection{}
	var next *string
	for rows.Next() {
		v, e := scanOAuthConnection(rows)
		if e != nil {
			resourceDatabaseProblem(w, r)
			return
		}
		if len(items) == limit {
			c := encodeTimeCursor(items[limit-1].CreatedAt, items[limit-1].ID.String())
			next = &c
			break
		}
		items = append(items, v)
	}
	if rows.Err() != nil {
		resourceDatabaseProblem(w, r)
		return
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) writeResourceConnection(w http.ResponseWriter, r *http.Request, self, revoke bool) {
	if self && !resourceSelfActor(w, r) {
		return
	}
	if !resourceRouteIDs(w, r, "application_id", "connection_id") {
		return
	}
	if !self && !resourceRouteIDs(w, r, "resource_id") {
		return
	}
	v, err := s.loadOAuthConnection(r.Context(), chi.URLParam(r, "application_id"), chi.URLParam(r, "connection_id"))
	if resourceLoadProblem(w, r, err, "connection") {
		return
	}
	if self && v.UserID.String() != actor(r).ID || !self && v.ResourceID.String() != chi.URLParam(r, "resource_id") {
		kernel.WriteProblem(w, r, 404, "connection_not_found", "The connection was not found.")
		return
	}
	if !revoke {
		w.Header().Set("ETag", kernel.ETag(v.Version))
		kernel.WriteJSON(w, 200, v)
		return
	}
	if !resourceIfMatch(w, r, v.Version) {
		return
	}
	if v.RevokedAt != nil {
		w.Header().Set("ETag", kernel.ETag(v.Version))
		w.WriteHeader(204)
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		resourceDatabaseProblem(w, r)
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE oauth_connections SET revoked_at=now(),version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2 AND version=$3 AND revoked_at IS NULL`, v.ApplicationID, v.ID, v.Version)
	if err == nil && result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusPreconditionFailed, "connection_version_conflict", "The connection changed concurrently.")
		return
	}
	if err == nil {
		err = s.emitResourceMutation(r, tx, v.ApplicationID, "connection.revoked", "connection", v.ID, map[string]any{"connection_id": v.ID, "resource_id": v.ResourceID, "version": v.Version + 1})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		resourceDatabaseProblem(w, r)
		return
	}
	w.Header().Set("ETag", kernel.ETag(v.Version+1))
	w.WriteHeader(204)
}
