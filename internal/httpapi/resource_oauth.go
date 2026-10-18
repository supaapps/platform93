package httpapi

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/oauthserver"
	"github.com/supaapps/platform93/internal/outbound"
)

type resourceOAuthContextKey struct{}

func resourceFromRequest(r *http.Request) *OAuthResource {
	resource, _ := r.Context().Value(resourceOAuthContextKey{}).(*OAuthResource)
	return resource
}

func resourceCapabilityScope(applicationID, key string) string {
	scope, _ := platformauthz.CanonicalScope(applicationID, nil, key)
	return scope
}

// Resource resolution precedes client resolution: a published client identity may
// connect to multiple applications, but each registered resource has one owner.
func (s *Server) resolveResourceOAuth(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	values, present := r.Form["resource"]
	if !present {
		return r, true
	}
	if len(values) != 1 || values[0] == "" {
		kernel.WriteProblem(w, r, 400, "invalid_target", "Exactly one registered resource is required.")
		return r, false
	}
	var appID, id string
	err := s.app.DB.QueryRow(r.Context(), `SELECT application_id,id FROM oauth_resources WHERE uri=$1 AND enabled`, values[0]).Scan(&appID, &id)
	if err != nil {
		kernel.WriteProblem(w, r, 400, "invalid_target", "The requested resource is unavailable.")
		return r, false
	}
	resource, err := s.loadOAuthResource(r.Context(), appID, id)
	config, configErr := loadApplicationInternalConfig(r.Context(), s.app.DB, appID)
	if err != nil || configErr != nil || !config.ResourceAuthorizationEnabled {
		kernel.WriteProblem(w, r, 400, "invalid_target", "Resource authorization is unavailable for this application.")
		return r, false
	}
	clientID := r.Form.Get("client_id")
	if basic, _, ok := r.BasicAuth(); ok {
		clientID = basic
	}
	if !stringSliceContains(resource.ClientIDs, clientID) {
		kernel.WriteProblem(w, r, 400, "invalid_client", "The client is not permitted for this resource.")
		return r, false
	}
	if strings.HasPrefix(clientID, "https://") {
		if !resource.AllowClientMetadata || s.ensureResourceMetadataClient(r.Context(), &resource, clientID, r.Method == http.MethodGet && r.URL.Path == "/oidc/authorize") != nil {
			kernel.WriteProblem(w, r, 400, "invalid_client", "The published client identity is unavailable or not permitted.")
			return r, false
		}
	}
	chi.RouteContext(r.Context()).URLParams.Add("application_id", appID)
	return r.WithContext(context.WithValue(r.Context(), resourceOAuthContextKey{}, &resource)), true
}

type resourceClientMetadata struct {
	ClientID                string          `json:"client_id"`
	ClientName              string          `json:"client_name"`
	RedirectURIs            []string        `json:"redirect_uris"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	ClientSecret            json.RawMessage `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   json.RawMessage `json:"client_secret_expires_at,omitempty"`
}

func validateResourceClientMetadata(expected string, metadata resourceClientMetadata) error {
	u, err := url.Parse(expected)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || metadata.ClientID != expected || strings.TrimSpace(metadata.ClientName) == "" || len(metadata.ClientName) > 200 || len(metadata.RedirectURIs) < 1 || len(metadata.RedirectURIs) > 16 || metadata.TokenEndpointAuthMethod != "none" || len(metadata.ClientSecret) > 0 || len(metadata.ClientSecretExpiresAt) > 0 {
		return errors.New("invalid published client metadata")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return errors.New("invalid metadata identity path")
		}
	}
	for _, value := range metadata.GrantTypes {
		if value != "authorization_code" && value != "refresh_token" {
			return errors.New("unsupported metadata grant")
		}
	}
	for _, value := range metadata.ResponseTypes {
		if value != "code" {
			return errors.New("unsupported metadata response")
		}
	}
	for _, value := range metadata.RedirectURIs {
		redirect, parseErr := url.Parse(value)
		if parseErr != nil || len(value) > 2048 || redirect.User != nil || redirect.Fragment != "" || redirect.Hostname() == "" || redirect.Scheme != "https" && !(redirect.Scheme == "http" && (redirect.Hostname() == "127.0.0.1" || redirect.Hostname() == "[::1]" || redirect.Hostname() == "::1")) {
			return errors.New("invalid metadata redirect")
		}
	}
	return nil
}

func (s *Server) ensureResourceMetadataClient(ctx context.Context, resource *OAuthResource, clientID string, refresh bool) error {
	if refresh {
		var fresh bool
		err := s.app.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_resource_clients b JOIN clients c ON c.id=b.client_database_id WHERE b.resource_id=$1 AND b.client_id=$2 AND c.disabled_at IS NULL AND c.updated_at>now()-interval '5 minutes')`, resource.ID, clientID).Scan(&fresh)
		if err != nil {
			return err
		}
		if fresh {
			return nil
		}
	}
	if !refresh {
		var available bool
		err := s.app.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_resource_clients b JOIN clients c ON c.id=b.client_database_id WHERE b.resource_id=$1 AND b.application_id=$2 AND b.client_id=$3 AND c.disabled_at IS NULL)`, resource.ID, resource.ApplicationID, clientID).Scan(&available)
		if err != nil || !available {
			return errors.New("published client is not enrolled")
		}
		return nil
	}
	if err := outbound.ValidateHTTPS(ctx, clientID); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := outbound.NewSafeHTTPClient(5 * time.Second).Do(request)
	if err != nil {
		return errors.New("client metadata fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("client metadata fetch rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return errors.New("client metadata exceeds limit")
	}
	var metadata resourceClientMetadata
	if json.Unmarshal(raw, &metadata) != nil {
		return errors.New("invalid client metadata JSON")
	}
	if err = validateResourceClientMetadata(clientID, metadata); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	grants := metadata.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "resource-client:"+resource.ID.String()+":"+clientID); err != nil {
		return err
	}
	var databaseID string
	err = tx.QueryRow(ctx, `SELECT client_database_id FROM oauth_resource_clients WHERE resource_id=$1 AND client_id=$2`, resource.ID, clientID).Scan(&databaseID)
	if errors.Is(err, pgx.ErrNoRows) {
		databaseID = kernel.NewID().String()
		_, err = tx.Exec(ctx, `INSERT INTO clients(id,application_id,client_id,name,client_type,redirect_uris,allowed_grants,allowed_scopes,pkce_required,authorization_ui,resource_only) VALUES($1,$2,$3,$4,'public',$5,$6,ARRAY['openid','profile','email','offline_access'],true,'hosted',true)`, databaseID, resource.ApplicationID, "p93_resource_"+databaseID, metadata.ClientName, metadata.RedirectURIs, grants)
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO oauth_resource_clients(application_id,resource_id,client_id,client_database_id,metadata_digest) VALUES($1,$2,$3,$4,$5)`, resource.ApplicationID, resource.ID, clientID, databaseID, digest[:])
		}
	} else if err == nil {
		result, updateErr := tx.Exec(ctx, `UPDATE clients SET name=$1,redirect_uris=$2,allowed_grants=$5,updated_at=now() WHERE id=$3 AND application_id=$4 AND resource_only AND disabled_at IS NULL`, metadata.ClientName, metadata.RedirectURIs, databaseID, resource.ApplicationID, grants)
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = errors.New("published client disabled")
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE oauth_resource_clients SET metadata_digest=$3 WHERE resource_id=$1 AND client_id=$2`, resource.ID, clientID, digest[:])
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) resourceClientDatabaseID(ctx context.Context, resource *OAuthResource, clientID string) (string, error) {
	var id string
	err := s.app.DB.QueryRow(ctx, `SELECT c.id FROM clients c WHERE c.application_id=$1 AND c.client_id=$2 AND NOT c.resource_only AND c.disabled_at IS NULL
UNION ALL SELECT c.id FROM oauth_resource_clients b JOIN clients c ON c.id=b.client_database_id WHERE b.application_id=$1 AND b.resource_id=$3 AND b.client_id=$2 AND c.disabled_at IS NULL LIMIT 1`, resource.ApplicationID, clientID, resource.ID).Scan(&id)
	return id, err
}

func (s *Server) configureResourceProvider(r *http.Request, provider *oauthserver.Provider) {
	resource := resourceFromRequest(r)
	if resource == nil {
		return
	}
	provider.Store.ResourceURI = resource.URI
	for _, capability := range resource.Capabilities {
		provider.Store.ResourceScopes = append(provider.Store.ResourceScopes, resourceCapabilityScope(resource.ApplicationID.String(), capability.Key))
	}
}

func (s *Server) resourceUserMay(r *http.Request, applicationID, userID, workspaceID string, permissions []string) bool {
	if workspaceID != "" {
		var available bool
		err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces w WHERE w.application_id=$1 AND w.id=$2 AND w.deleted_at IS NULL AND (w.owner_user_id=$3 OR EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=w.id AND m.user_id=$3 AND m.application_id=$1)))`, applicationID, workspaceID, userID).Scan(&available)
		if err != nil || !available {
			return false
		}
	}
	appID, err := uuid.Parse(applicationID)
	if err != nil {
		return false
	}
	effective, err := s.userEffectiveAccess(r, appID, userID)
	if err != nil {
		return false
	}
	current := kernel.Actor{Permissions: effective.Scopes}
	var workspace *string
	if workspaceID != "" {
		workspace = &workspaceID
	}
	for _, permission := range permissions {
		wanted, err := platformauthz.CanonicalScope(applicationID, workspace, permission)
		if err != nil || !actorHasPermission(current, wanted) {
			return false
		}
	}
	return true
}

func (s *Server) hostedResourceConsent(r *http.Request, interaction *hostedInteraction, userID string) (map[string]any, error) {
	var resourceID string
	if err := s.app.DB.QueryRow(r.Context(), `SELECT id FROM oauth_resources WHERE application_id=$1 AND uri=$2 AND enabled`, interaction.ApplicationID, interaction.Params.Get("resource")).Scan(&resourceID); err != nil {
		return nil, err
	}
	resource, err := s.loadOAuthResource(r.Context(), interaction.ApplicationID, resourceID)
	if err != nil {
		return nil, err
	}
	config, err := loadApplicationInternalConfig(r.Context(), s.app.DB, interaction.ApplicationID)
	if err != nil || !config.ResourceAuthorizationEnabled || !stringSliceContains(resource.ClientIDs, interaction.ClientID) {
		return nil, errors.New("resource disabled")
	}
	capabilities := []map[string]any{}
	personal := false
	for _, capability := range resource.Capabilities {
		if !stringSliceContains(strings.Fields(interaction.Params.Get("scope")), resourceCapabilityScope(interaction.ApplicationID, capability.Key)) {
			continue
		}
		capabilities = append(capabilities, map[string]any{"key": capability.Key, "name": capability.Name, "context": capability.Context})
		if capability.Context == "personal" {
			personal = true
		}
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT w.id,w.name,w.key FROM workspaces w WHERE w.application_id=$1 AND w.deleted_at IS NULL AND (w.owner_user_id=$2 OR EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.application_id=$1 AND m.workspace_id=w.id AND m.user_id=$2)) ORDER BY w.name,w.id`, interaction.ApplicationID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	workspaces := []map[string]string{}
	for rows.Next() {
		var id, name, key string
		if err = rows.Scan(&id, &name, &key); err != nil {
			return nil, err
		}
		workspaces = append(workspaces, map[string]string{"id": id, "name": name, "key": key})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if resource.Version != interaction.Private.ResourceVersion {
		return nil, errors.New("resource consent changed; restart authorization")
	}
	return map[string]any{"resource": map[string]any{"id": resource.ID, "uri": resource.URI, "name": resource.Name, "version": resource.Version}, "capabilities": capabilities, "workspaces": workspaces, "personal_access_available": personal}, nil
}

func (s *Server) resourceConnectionLive(r *http.Request, connectionID, appID, resourceURI, userID, sessionID, clientID string) (OAuthConnection, OAuthResource, bool) {
	connection, err := s.loadOAuthConnection(r.Context(), appID, connectionID)
	if err != nil || connection.UserID.String() != userID || connection.SessionID.String() != sessionID || connection.ClientID != clientID || connection.RevokedAt != nil || !connection.ExpiresAt.After(s.app.Now()) {
		return OAuthConnection{}, OAuthResource{}, false
	}
	resource, err := s.loadOAuthResource(r.Context(), appID, connection.ResourceID.String())
	if err != nil || !resource.Enabled || resource.URI != resourceURI || resource.Version != connection.ResourceVersion || !stringSliceContains(resource.ClientIDs, clientID) {
		return OAuthConnection{}, OAuthResource{}, false
	}
	config, err := loadApplicationInternalConfig(r.Context(), s.app.DB, appID)
	if err != nil || !config.ResourceAuthorizationEnabled {
		return OAuthConnection{}, OAuthResource{}, false
	}
	var live bool
	err = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_sessions ss JOIN users u ON u.id=ss.user_id AND u.application_id=ss.application_id WHERE ss.id=$1 AND ss.application_id=$2 AND ss.user_id=$3 AND ss.revoked_at IS NULL AND ss.expires_at>now() AND ss.delegation_id IS NULL AND u.status='active')`, sessionID, appID, userID).Scan(&live)
	if err != nil || !live {
		return OAuthConnection{}, OAuthResource{}, false
	}
	if _, err = s.resourceClientDatabaseID(r.Context(), &resource, clientID); err != nil {
		return OAuthConnection{}, OAuthResource{}, false
	}
	return connection, resource, true
}

func setResourceScopes(request fosite.Requester, scopes []string) {
	sort.Strings(scopes)
	switch value := request.(type) {
	case *fosite.AuthorizeRequest:
		value.GrantedScope = nil
		value.GrantedAudience = nil
	case *fosite.AccessRequest:
		value.GrantedScope = nil
		value.GrantedAudience = nil
	}
	for _, scope := range scopes {
		request.GrantScope(scope)
	}
}

func (s *Server) authorizeResource(w http.ResponseWriter, r *http.Request, provider *oauthserver.Provider, request fosite.AuthorizeRequester) {
	resource := resourceFromRequest(r)
	current := actor(r)
	fail := func(err error) { provider.OAuth.WriteAuthorizeError(r.Context(), w, request, err) }
	if resource == nil || current.Type != "user" || current.DelegatedBy != "" || current.ApplicationID != resource.ApplicationID.String() {
		fail(fosite.ErrAccessDenied)
		return
	}
	approvedVersion, versionErr := strconv.ParseInt(r.FormValue("resource_version"), 10, 64)
	if versionErr != nil || approvedVersion != resource.Version {
		fail(fosite.ErrAccessDenied.WithHint("Resource consent changed; restart authorization."))
		return
	}
	var capabilities, workspaces []string
	if json.Unmarshal([]byte(r.FormValue("approved_capabilities")), &capabilities) != nil || len(capabilities) == 0 || len(capabilities) > 32 {
		fail(fosite.ErrInvalidScope)
		return
	}
	if raw := r.FormValue("workspace_ids"); raw != "" && json.Unmarshal([]byte(raw), &workspaces) != nil {
		fail(fosite.ErrInvalidRequest)
		return
	}
	if len(workspaces) > 100 {
		fail(fosite.ErrInvalidRequest)
		return
	}
	personal := r.FormValue("personal_access") == "true"
	if !personal && len(workspaces) == 0 {
		fail(fosite.ErrAccessDenied)
		return
	}
	seen := map[string]bool{}
	for _, id := range workspaces {
		if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id || seen[id] {
			fail(fosite.ErrInvalidRequest)
			return
		}
		seen[id] = true
	}
	requested := request.GetRequestedScopes()
	granted := []string{}
	for _, scope := range requested {
		if scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access" {
			granted = append(granted, scope)
		}
	}
	seen = map[string]bool{}
	workspaceCapability := false
	for _, key := range capabilities {
		if seen[key] {
			fail(fosite.ErrInvalidScope)
			return
		}
		seen[key] = true
		matched := false
		for _, capability := range resource.Capabilities {
			if capability.Key != key {
				continue
			}
			canonical := resourceCapabilityScope(resource.ApplicationID.String(), key)
			if !requested.Has(canonical) {
				fail(fosite.ErrInvalidScope)
				return
			}
			if capability.Context == "personal" {
				if !personal || !s.resourceUserMay(r, resource.ApplicationID.String(), current.ID, "", capability.Permissions) {
					fail(fosite.ErrAccessDenied)
					return
				}
			} else {
				workspaceCapability = true
				if len(workspaces) == 0 {
					fail(fosite.ErrAccessDenied)
					return
				}
				for _, workspace := range workspaces {
					if !s.resourceUserMay(r, resource.ApplicationID.String(), current.ID, workspace, capability.Permissions) {
						fail(fosite.ErrAccessDenied)
						return
					}
				}
			}
			granted = append(granted, canonical)
			matched = true
		}
		if !matched {
			fail(fosite.ErrInvalidScope)
			return
		}
	}
	if len(workspaces) > 0 && !workspaceCapability {
		fail(fosite.ErrInvalidRequest.WithHint("Workspace selection requires an approved workspace capability."))
		return
	}
	if personal {
		hasPersonal := false
		for _, cap := range resource.Capabilities {
			if cap.Context == "personal" && seen[cap.Key] {
				hasPersonal = true
			}
		}
		if !hasPersonal {
			fail(fosite.ErrInvalidRequest)
			return
		}
	}
	if workspaces == nil {
		workspaces = []string{}
	}
	txContext, err := provider.Store.BeginTX(r.Context())
	if err != nil {
		fail(fosite.ErrServerError)
		return
	}
	defer provider.Store.Rollback(txContext)
	tx, _ := provider.Store.Transaction(txContext)
	var version int64
	err = tx.QueryRow(txContext, `SELECT version FROM oauth_resources WHERE id=$1 AND application_id=$2 AND enabled FOR SHARE`, resource.ID, resource.ApplicationID).Scan(&version)
	if err != nil || version != resource.Version {
		fail(fosite.ErrAccessDenied)
		return
	}
	var authenticatedAt, expiresAt time.Time
	var amr []string
	err = tx.QueryRow(txContext, `SELECT ss.authenticated_at,ss.amr,LEAST(ss.expires_at,now()+interval '30 days') FROM user_sessions ss JOIN users u ON u.id=ss.user_id AND u.application_id=ss.application_id WHERE ss.id=$1 AND ss.user_id=$2 AND ss.application_id=$3 AND ss.revoked_at IS NULL AND ss.expires_at>now() AND ss.delegation_id IS NULL AND u.status='active' FOR SHARE OF ss,u`, current.SessionID, current.ID, resource.ApplicationID).Scan(&authenticatedAt, &amr, &expiresAt)
	if err != nil {
		fail(fosite.ErrLoginRequired)
		return
	}
	connectionID := kernel.NewID().String()
	_, err = tx.Exec(txContext, `INSERT INTO oauth_connections(id,application_id,resource_id,resource_version,user_id,client_id,session_id,capabilities,personal_access,workspace_ids,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, connectionID, resource.ApplicationID, resource.ID, resource.Version, current.ID, request.GetClient().GetID(), current.SessionID, capabilities, personal, workspaces, expiresAt)
	if err == nil {
		appID := resource.ApplicationID
		_, err = s.app.Emit(txContext, tx, &appID, "connection.approved", "connection/"+connectionID, current, map[string]any{"connection_id": connectionID, "resource_id": resource.ID, "version": 1})
	}
	if err == nil {
		_, err = tx.Exec(txContext, `INSERT INTO audit_records(id,application_id,actor_type,actor_id,action,target_type,target_id,request_id,changes) VALUES($1,$2,'user',$3,'connection.approved','connection',$4,$5,'{}')`, kernel.NewID(), resource.ApplicationID, current.ID, connectionID, kernel.RequestID(r.Context()))
	}
	if err != nil {
		fail(fosite.ErrServerError)
		return
	}
	session := oauthserver.NewSession(current.ID, "", provider.KID, s.app.Now().UTC())
	setResourceScopes(request, granted)
	request.GrantAudience(resource.URI)
	session.AccessClaims.Extra = map[string]any{"application_id": resource.ApplicationID, "actor_type": "user", "token_kind": "resource_access", "sid": current.SessionID, "client_id": request.GetClient().GetID(), "connection_id": connectionID, "roles": emptyRoleClaims(), "scope": strings.Join(granted, " "), "amr": amr}
	session.IDClaims.Extra = map[string]any{"application_id": resource.ApplicationID, "actor_type": "user", "sid": current.SessionID, "roles": emptyRoleClaims()}
	session.IDClaims.AuthTime = authenticatedAt
	session.IDClaims.AuthenticationMethodsReferences = amr
	request.SetSession(session)
	response, err := provider.OAuth.NewAuthorizeResponse(txContext, request, session)
	if err != nil {
		fail(err)
		return
	}
	if err = provider.Store.Commit(txContext); err != nil {
		fail(fosite.ErrServerError)
		return
	}
	response.AddParameter("iss", s.app.Issuer())
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		destination := *request.GetRedirectURI()
		query := destination.Query()
		for key, values := range response.GetParameters() {
			for _, value := range values {
				query.Add(key, value)
			}
		}
		destination.RawQuery = query.Encode()
		kernel.WriteJSON(w, 200, map[string]any{"redirect_to": destination.String()})
		return
	}
	provider.OAuth.WriteAuthorizeResponse(r.Context(), w, request, response)
}

func (s *Server) prepareResourceToken(r *http.Request, request fosite.AccessRequester) error {
	session, ok := request.GetSession().(*oauthserver.Session)
	if !ok || session.AccessClaims == nil {
		return fosite.ErrInvalidGrant
	}
	kind, _ := session.AccessClaims.Extra["token_kind"].(string)
	resource := resourceFromRequest(r)
	if kind != "resource_access" {
		if resource != nil {
			return fosite.ErrInvalidGrant
		}
		return nil
	}
	if resource == nil || !request.GetGrantTypes().ExactOne("authorization_code") && !request.GetGrantTypes().ExactOne("refresh_token") {
		return fosite.ErrInvalidGrant
	}
	connectionID, _ := session.AccessClaims.Extra["connection_id"].(string)
	sessionID, _ := session.AccessClaims.Extra["sid"].(string)
	connection, _, live := s.resourceConnectionLive(r, connectionID, resource.ApplicationID.String(), resource.URI, session.Subject, sessionID, request.GetClient().GetID())
	if !live {
		return fosite.ErrInvalidGrant
	}
	granted := []string{}
	persistedScope, _ := session.AccessClaims.Extra["scope"].(string)
	if persistedScope == "" || platformauthz.ValidateScopeClaim(persistedScope, resource.ApplicationID.String()) != nil {
		return fosite.ErrInvalidScope
	}
	ceiling := strings.Split(persistedScope, " ")
	requestedSubset := r.PostForm.Get("scope")
	var subset map[string]bool
	if request.GetGrantTypes().ExactOne("refresh_token") && requestedSubset != "" {
		if platformauthz.ValidateScopeClaim(requestedSubset, resource.ApplicationID.String()) != nil {
			return fosite.ErrInvalidScope
		}
		subset = map[string]bool{}
		for _, scope := range strings.Split(requestedSubset, " ") {
			if !stringSliceContains(ceiling, scope) {
				return fosite.ErrInvalidScope
			}
			subset[scope] = true
		}
	}
	for _, scope := range ceiling {
		if subset != nil && !subset[scope] {
			continue
		}
		if scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access" {
			granted = append(granted, scope)
			continue
		}
		for _, capability := range connection.Capabilities {
			if scope == resourceCapabilityScope(resource.ApplicationID.String(), capability) {
				granted = append(granted, scope)
				break
			}
		}
	}
	if len(granted) == 0 {
		return fosite.ErrInvalidScope
	}
	setResourceScopes(request, granted)
	request.GrantAudience(resource.URI)
	session.AccessClaims.Extra["scope"] = strings.Join(granted, " ")
	session.AccessClaims.Extra["roles"] = emptyRoleClaims()
	request.SetSession(session)
	return nil
}

type resourceAccessCheckRequest struct {
	Token       string  `json:"token"`
	Resource    string  `json:"resource"`
	Capability  string  `json:"capability"`
	WorkspaceID *string `json:"workspace_id,omitempty"`
}

func (s *Server) checkResourceAccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !requireApplicationPermission(w, r, "resource_access/check") {
		return
	}
	var input resourceAccessCheckRequest
	if !kernel.DecodeJSON(w, r, &input) {
		return
	}
	deny := func(reason string) { kernel.WriteJSON(w, 200, map[string]any{"allowed": false, "reason": reason}) }
	if len(input.Token) > 16384 || len(input.Resource) > 2048 || platformauthz.ValidateRelativePermission(input.Capability) != nil || strings.Contains(input.Capability, "*") {
		deny("invalid_request")
		return
	}
	appID := chi.URLParam(r, "application_id")
	claims, err := identity.Verify(input.Token, func(kid string) (*rsa.PublicKey, error) { return s.app.ResolvePublicKey(r.Context(), kid) }, s.app.Issuer(), input.Resource, s.app.Now())
	if err != nil || len(claims.Audience) != 1 || claims.ApplicationID != appID || claims.TokenKind != "resource_access" || claims.ActorType != "user" || claims.Actor != nil || len(claims.Roles.Application) != 0 || len(claims.Roles.Workspaces) != 0 {
		deny("invalid_token")
		return
	}
	var tokenActive bool
	parts := strings.Split(input.Token, ".")
	err = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM oauth_sessions WHERE application_id=$1 AND kind='access' AND signature_digest=$2 AND active AND expires_at>now())`, appID, s.app.Vault.Digest(parts[2])).Scan(&tokenActive)
	if err != nil || !tokenActive {
		deny("invalid_token")
		return
	}
	connection, resource, live := s.resourceConnectionLive(r, claims.ConnectionID, appID, input.Resource, claims.Subject, claims.SessionID, claims.ClientID)
	if !live {
		deny("connection_unavailable")
		return
	}
	if !stringSliceContains(connection.Capabilities, input.Capability) || !stringSliceContains(strings.Split(claims.Scope, " "), resourceCapabilityScope(appID, input.Capability)) {
		deny("capability_not_granted")
		return
	}
	workspaceID := ""
	if input.WorkspaceID != nil {
		workspaceID = *input.WorkspaceID
		if parsed, e := uuid.Parse(workspaceID); e != nil || parsed.String() != workspaceID || !containsWorkspaceID(connection.WorkspaceIDs, parsed) {
			deny("workspace_not_granted")
			return
		}
	}
	for _, capability := range resource.Capabilities {
		if capability.Key != input.Capability {
			continue
		}
		if capability.Context == "personal" && (workspaceID != "" || !connection.PersonalAccess) || capability.Context == "workspace" && workspaceID == "" {
			deny("context_not_granted")
			return
		}
		if !s.resourceUserMay(r, appID, claims.Subject, workspaceID, capability.Permissions) {
			deny("permission_denied")
			return
		}
		result := map[string]any{"allowed": true, "reason": "allowed", "user_id": claims.Subject, "connection_id": connection.ID}
		if workspaceID != "" {
			result["workspace_id"] = workspaceID
		}
		kernel.WriteJSON(w, 200, result)
		return
	}
	deny("capability_unavailable")
}

func containsWorkspaceID(values []uuid.UUID, wanted uuid.UUID) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// Resource responses include issuer identification even when authorization is denied.
type oauthIssuerWriter struct {
	http.ResponseWriter
	issuer string
}

func (w oauthIssuerWriter) WriteHeader(status int) {
	if location := w.Header().Get("Location"); location != "" {
		if destination, err := url.Parse(location); err == nil {
			query := destination.Query()
			if query.Has("code") || query.Has("error") {
				query.Set("iss", w.issuer)
				destination.RawQuery = query.Encode()
				w.Header().Set("Location", destination.String())
			}
		}
	}
	w.ResponseWriter.WriteHeader(status)
}
