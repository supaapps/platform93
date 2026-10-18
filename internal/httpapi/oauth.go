package httpapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/oauthserver"
)

func (s *Server) resolveOAuthApplication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if _, present := r.Form["resource"]; present {
			resolved, ok := s.resolveResourceOAuth(w, r)
			if ok {
				next.ServeHTTP(w, resolved)
			}
			return
		}
		clientID := strings.TrimSpace(r.FormValue("client_id"))
		if basicClientID, _, ok := r.BasicAuth(); ok && basicClientID != "" {
			clientID = basicClientID
		}
		application := ""
		if clientID != "" {
			_ = s.app.DB.QueryRow(r.Context(), `SELECT application_id FROM clients
WHERE client_id=$1 AND disabled_at IS NULL AND NOT resource_only`, clientID).Scan(&application)
		}
		if application == "" {
			if managementRequest, ok := s.resolveManagementOAuthClient(r, clientID); ok {
				next.ServeHTTP(w, managementRequest)
				return
			}
		}
		if application == "" {
			token := strings.TrimSpace(r.FormValue("token"))
			if token == "" {
				token = fosite.AccessTokenFromRequest(r)
			}
			application = unverifiedApplicationID(token)
		}
		if _, err := uuid.Parse(application); err != nil {
			kernel.WriteProblem(w, r, http.StatusBadRequest, "oauth_application_unresolved", "The OAuth application could not be resolved from the client or token.")
			return
		}
		chi.RouteContext(r.Context()).URLParams.Add("application_id", application)
		next.ServeHTTP(w, r)
	})
}

func unverifiedApplicationID(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		ApplicationID string `json:"application_id"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.ApplicationID
}

func (s *Server) oauthAuthorizeInteraction(w http.ResponseWriter, r *http.Request) {
	w = oauthIssuerWriter{ResponseWriter: w, issuer: s.app.Issuer()}
	provider, ok := s.oauthProvider(w, r)
	if !ok {
		return
	}
	request, err := provider.OAuth.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, err)
		return
	}
	if s.startHostedAuthorization(w, r, provider, request) {
		return
	}
	if resource := resourceFromRequest(r); resource != nil {
		kernel.WriteJSON(w, http.StatusOK, map[string]any{"interaction": "consent", "client_id": request.GetClient().GetID(), "requested_scopes": request.GetRequestedScopes(), "redirect_uri": request.GetRedirectURI().String(), "state": request.GetState(), "submit_method": "POST", "resource": map[string]any{"id": resource.ID, "uri": resource.URI, "name": resource.Name, "version": resource.Version}})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	kernel.WriteJSON(w, http.StatusOK, map[string]any{
		"interaction":      "consent",
		"client_id":        request.GetClient().GetID(),
		"requested_scopes": request.GetRequestedScopes(),
		"redirect_uri":     request.GetRedirectURI().String(),
		"state":            request.GetState(),
		"submit_method":    "POST",
	})
}

func (s *Server) oauthAuthorizeDecision(w http.ResponseWriter, r *http.Request) {
	w = oauthIssuerWriter{ResponseWriter: w, issuer: s.app.Issuer()}
	provider, ok := s.oauthProvider(w, r)
	if !ok {
		return
	}
	request, err := provider.OAuth.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, err)
		return
	}
	if strings.EqualFold(r.FormValue("decision"), "deny") {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrAccessDenied)
		return
	}
	if resourceFromRequest(r) != nil {
		s.authorizeResource(w, r, provider, request)
		return
	}
	consentScopes := append([]string(nil), request.GetRequestedScopes()...)
	for _, scope := range consentScopes {
		request.GrantScope(scope)
	}
	applicationID, _ := uuid.Parse(chi.URLParam(r, "application_id"))
	request.GrantAudience(s.app.ApplicationAudience(applicationID))

	current := actor(r)
	// Delegation is deliberately short-lived and non-renewable. It must not be
	// converted into an ordinary OAuth grant or recorded as the user's consent.
	if current.DelegatedBy != "" || current.Type != "user" {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrAccessDenied)
		return
	}
	var email, firstName, lastName, locale string
	var emailVerified, orgVerified bool
	var authenticatedAt time.Time
	var amr []string
	err = s.app.DB.QueryRow(r.Context(), `SELECT email,first_name,last_name,locale,email_verified_at IS NOT NULL,is_org_verified
FROM users WHERE id=$1 AND application_id=$2 AND status='active'`, current.ID, chi.URLParam(r, "application_id")).
		Scan(&email, &firstName, &lastName, &locale, &emailVerified, &orgVerified)
	if err != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrLoginRequired)
		return
	}
	err = s.app.DB.QueryRow(r.Context(), `SELECT authenticated_at,amr FROM user_sessions
WHERE id=$1 AND application_id=$2 AND user_id=$3 AND revoked_at IS NULL AND expires_at>now() AND delegation_id IS NULL`, current.SessionID, chi.URLParam(r, "application_id"), current.ID).
		Scan(&authenticatedAt, &amr)
	if err != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrLoginRequired)
		return
	}
	session := oauthserver.NewSession(current.ID, email, provider.KID, s.app.Now().UTC())
	customClaims, claimsErr := s.customClaimsForUser(r.Context(), chi.URLParam(r, "application_id"), current.ID)
	if claimsErr != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrServerError)
		return
	}
	effective, accessErr := s.userEffectiveAccess(r, applicationID, current.ID)
	if accessErr != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrServerError)
		return
	}
	session.AccessClaims.Extra = map[string]any{
		"application_id": chi.URLParam(r, "application_id"), "client_id": request.GetClient().GetID(),
		"token_kind": "access", "email": email, "email_verified": emailVerified,
		"is_org_verified": orgVerified, "locale": locale, "actor_type": "user", "scope": strings.Join(current.Permissions, " "),
		"sid": current.SessionID, "amr": amr, "custom_claims": customClaims, "roles": effective.Roles,
	}
	session.IDClaims.Extra = map[string]any{
		"application_id": chi.URLParam(r, "application_id"), "actor_type": "user", "sid": current.SessionID,
		"custom_claims": customClaims, "roles": effective.Roles,
	}
	if stringSliceContains(consentScopes, "email") {
		session.IDClaims.Extra["email"] = email
		session.IDClaims.Extra["email_verified"] = emailVerified
	}
	if stringSliceContains(consentScopes, "profile") {
		session.IDClaims.Extra["given_name"] = firstName
		session.IDClaims.Extra["family_name"] = lastName
		session.IDClaims.Extra["name"] = strings.TrimSpace(firstName + " " + lastName)
		session.IDClaims.Extra["locale"] = locale
		session.IDClaims.Extra["is_org_verified"] = orgVerified
	}
	session.IDClaims.AuthTime = authenticatedAt
	session.IDClaims.AuthenticationMethodsReferences = amr
	request.SetSession(session)
	for _, scope := range current.Permissions {
		request.GrantScope(scope)
	}

	var clientDatabaseID uuid.UUID
	err = s.app.DB.QueryRow(r.Context(), `SELECT id FROM clients WHERE application_id=$1 AND client_id=$2`,
		chi.URLParam(r, "application_id"), request.GetClient().GetID()).Scan(&clientDatabaseID)
	if err != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrInvalidClient)
		return
	}
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO oauth_consents(application_id,user_id,client_id,scopes)
VALUES ($1,$2,$3,$4) ON CONFLICT (application_id,user_id,client_id) DO UPDATE
SET scopes=(SELECT ARRAY(SELECT DISTINCT unnest(oauth_consents.scopes || EXCLUDED.scopes))),updated_at=now(),revoked_at=NULL`,
		chi.URLParam(r, "application_id"), current.ID, clientDatabaseID, consentScopes)
	if err != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrServerError)
		return
	}
	response, err := provider.OAuth.NewAuthorizeResponse(r.Context(), request, session)
	if err != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, err)
		return
	}
	response.AddParameter("iss", s.app.Issuer())
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		redirectTo := *request.GetRedirectURI()
		query := redirectTo.Query()
		for key, values := range response.GetParameters() {
			for _, value := range values {
				query.Add(key, value)
			}
		}
		redirectTo.RawQuery = query.Encode()
		w.Header().Set("Cache-Control", "no-store")
		kernel.WriteJSON(w, http.StatusOK, map[string]any{"redirect_to": redirectTo.String()})
		return
	}
	provider.OAuth.WriteAuthorizeResponse(r.Context(), w, request, response)
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_oauth_request", "The token request could not be parsed.")
		return
	}
	clientID := r.FormValue("client_id")
	if basicClientID, _, ok := r.BasicAuth(); ok && basicClientID != "" {
		clientID = basicClientID
	}
	if managementClient, ok := managementClientFromContext(r.Context()); ok {
		s.issueManagementToken(w, r, managementClient)
		return
	}
	provider, ok := s.oauthProvider(w, r)
	if !ok {
		return
	}
	session := oauthserver.NewSession("", "", provider.KID, s.app.Now().UTC())
	request, err := provider.OAuth.NewAccessRequest(r.Context(), r, session)
	if err != nil {
		if !s.allowOAuthTokenAttempt(w, r, clientID, "", false) {
			return
		}
		provider.OAuth.WriteAccessError(r.Context(), w, request, err)
		return
	}
	resourceSession, _ := request.GetSession().(*oauthserver.Session)
	if resourceSession == nil || resourceSession.AccessClaims == nil || resourceSession.AccessClaims.Extra["token_kind"] != "resource_access" {
		for _, scope := range request.GetRequestedScopes() {
			request.GrantScope(scope)
		}
	}
	applicationID, _ := uuid.Parse(chi.URLParam(r, "application_id"))
	if err := s.prepareResourceToken(r, request); err != nil {
		provider.OAuth.WriteAccessError(r.Context(), w, request, err)
		return
	}
	storedResource, _ := request.GetSession().(*oauthserver.Session)
	isResource := storedResource != nil && storedResource.AccessClaims != nil && storedResource.AccessClaims.Extra["token_kind"] == "resource_access"
	if !isResource {
		request.GrantAudience(s.app.ApplicationAudience(applicationID))
	}
	if isResource {
		// Resource grants retain their consent ceiling instead of inheriting all roles.
	} else if request.GetGrantTypes().ExactOne("client_credentials") {
		clientID := request.GetClient().GetID()
		effective, accessErr := s.clientEffectiveAccess(r, applicationID, clientID)
		if accessErr != nil {
			provider.OAuth.WriteAccessError(r.Context(), w, request, fosite.ErrInvalidGrant)
			return
		}
		replaceApplicationScopes(request, effective.Scopes)
		session.Subject = clientID
		session.AccessClaims.Subject = clientID
		session.AccessClaims.Extra = map[string]any{
			"application_id": chi.URLParam(r, "application_id"), "client_id": clientID,
			"token_kind": "machine", "actor_type": "client", "amr": []string{"client_credentials"}, "roles": effective.Roles,
			"scope": strings.Join(effective.Scopes, " "),
		}
		request.SetSession(session)
	} else if request.GetGrantTypes().ExactOne("refresh_token") || request.GetGrantTypes().ExactOne("authorization_code") {
		storedSession, sessionOK := request.GetSession().(*oauthserver.Session)
		if !sessionOK || storedSession.Subject == "" {
			provider.OAuth.WriteAccessError(r.Context(), w, request, fosite.ErrInvalidGrant)
			return
		}
		if !s.oauthSubjectLive(r, request) {
			provider.OAuth.WriteAccessError(r.Context(), w, request, fosite.ErrInvalidGrant)
			return
		}
		effective, accessErr := s.userEffectiveAccess(r, applicationID, storedSession.Subject)
		if accessErr != nil {
			provider.OAuth.WriteAccessError(r.Context(), w, request, fosite.ErrInvalidGrant)
			return
		}
		replaceApplicationScopes(request, effective.Scopes)
		customClaims, claimsErr := s.customClaimsForUser(r.Context(), applicationID.String(), storedSession.Subject)
		if claimsErr != nil {
			provider.OAuth.WriteAccessError(r.Context(), w, request, fosite.ErrInvalidGrant)
			return
		}
		if storedSession.AccessClaims.Extra == nil {
			storedSession.AccessClaims.Extra = map[string]any{}
		}
		storedSession.AccessClaims.Extra["custom_claims"] = customClaims
		storedSession.AccessClaims.Extra["roles"] = effective.Roles
		storedSession.AccessClaims.Extra["scope"] = strings.Join(effective.Scopes, " ")
		if storedSession.IDClaims.Extra == nil {
			storedSession.IDClaims.Extra = map[string]any{}
		}
		storedSession.IDClaims.Extra["custom_claims"] = customClaims
		storedSession.IDClaims.Extra["roles"] = effective.Roles
		request.SetSession(storedSession)
	}
	if !s.allowOAuthTokenAttempt(w, r, clientID, request.GetSession().GetSubject(), true) {
		return
	}
	response, err := provider.OAuth.NewAccessResponse(r.Context(), request)
	if err != nil {
		provider.OAuth.WriteAccessError(r.Context(), w, request, err)
		return
	}
	provider.OAuth.WriteAccessResponse(r.Context(), w, request, response)
}

func (s *Server) allowOAuthTokenAttempt(w http.ResponseWriter, r *http.Request, clientID, subject string, authenticated bool) bool {
	// Classify only after Fosite validates credentials/the grant. Public client IDs
	// and failed attempts must never consume a valid caller's issuance budget,
	// including callers sharing the same NAT or reverse proxy.
	flow := "oauth_token_authenticated"
	if !authenticated {
		flow = "oauth_token_invalid"
		// Forwarding headers are deliberately not trusted for abuse accounting.
		subject, _ = requestIPAddress(r).(string)
	}
	// The generic limiter normalizes email-like subjects to lowercase; OAuth
	// identifiers are case-sensitive, so preserve them in a lowercase digest.
	key := hex.EncodeToString(s.app.Vault.Digest(clientID + "\x00" + subject))
	return s.allowAuthAttempt(w, r, flow, key, 30, 10*time.Minute)
}

func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.oauthProvider(w, r)
	if !ok {
		return
	}
	err := provider.OAuth.NewRevocationRequest(r.Context(), r)
	provider.OAuth.WriteRevocationResponse(r.Context(), w, err)
}

func (s *Server) oauthIntrospect(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.oauthProvider(w, r)
	if !ok {
		return
	}
	response, err := provider.OAuth.NewIntrospectionRequest(r.Context(), r, &oauthserver.Session{})
	if err != nil {
		provider.OAuth.WriteIntrospectionError(r.Context(), w, err)
		return
	}
	if response.IsActive() && !s.oauthSubjectLive(r, response.GetAccessRequester()) {
		w.Header().Set("Cache-Control", "no-store")
		kernel.WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	provider.OAuth.WriteIntrospectionResponse(r.Context(), w, response)
}

func (s *Server) oauthUserinfo(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.oauthProvider(w, r)
	if !ok {
		return
	}
	token := fosite.AccessTokenFromRequest(r)
	_, request, err := provider.OAuth.IntrospectToken(r.Context(), token, fosite.AccessToken, &oauthserver.Session{})
	if err != nil || request.GetSession().GetSubject() == "" || !s.oauthSubjectLive(r, request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_token", "The access token is invalid or inactive.")
		return
	}
	if session, ok := request.GetSession().(*oauthserver.Session); ok && session.AccessClaims.Extra["token_kind"] == "resource_access" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_token", "Resource credentials cannot access application UserInfo.")
		return
	}
	subject := request.GetSession().GetSubject()
	var email, firstName, lastName, locale, status string
	var verified, orgVerified bool
	err = s.app.DB.QueryRow(r.Context(), `SELECT email,first_name,last_name,locale,email_verified_at IS NOT NULL,is_org_verified,status
FROM users WHERE id=$1 AND application_id=$2`, subject, chi.URLParam(r, "application_id")).
		Scan(&email, &firstName, &lastName, &locale, &verified, &orgVerified, &status)
	if err != nil || status != "active" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "inactive_subject", "The token subject is no longer active.")
		return
	}
	result := map[string]any{"sub": subject, "is_org_verified": orgVerified}
	applicationID, applicationErr := uuid.Parse(chi.URLParam(r, "application_id"))
	if applicationErr != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_token", "The token application is invalid.")
		return
	}
	if effective, accessErr := s.userEffectiveAccess(r, applicationID, subject); accessErr == nil {
		result["roles"] = effective.Roles
		result["scope"] = strings.Join(effective.Scopes, " ")
	} else {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_authorization_data", "The subject authorization data is invalid.")
		return
	}
	if customClaims, claimsErr := s.customClaimsForUser(r.Context(), chi.URLParam(r, "application_id"), subject); claimsErr == nil && len(customClaims) > 0 {
		result["custom_claims"] = customClaims
	}
	if request.GetGrantedScopes().Has("email") {
		result["email"] = email
		result["email_verified"] = verified
	}
	if request.GetGrantedScopes().Has("profile") {
		result["given_name"] = firstName
		result["family_name"] = lastName
		result["name"] = strings.TrimSpace(firstName + " " + lastName)
		result["locale"] = locale
	}
	w.Header().Set("Cache-Control", "no-store")
	kernel.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) oauthSubjectLive(r *http.Request, request fosite.Requester) bool {
	session, ok := request.GetSession().(*oauthserver.Session)
	if !ok || session.AccessClaims == nil {
		return false
	}
	tokenKind, _ := session.AccessClaims.Extra["token_kind"].(string)
	if tokenKind == "resource_access" {
		connection, _ := session.AccessClaims.Extra["connection_id"].(string)
		sid, _ := session.AccessClaims.Extra["sid"].(string)
		var uri string
		if len(request.GetGrantedAudience()) == 1 {
			uri = request.GetGrantedAudience()[0]
		}
		_, _, live := s.resourceConnectionLive(r, connection, chi.URLParam(r, "application_id"), uri, session.Subject, sid, request.GetClient().GetID())
		return live
	}
	if tokenKind == "machine" {
		var live bool
		err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients
WHERE client_id=$1 AND application_id=$2 AND disabled_at IS NULL)`, session.Subject, chi.URLParam(r, "application_id")).Scan(&live)
		return err == nil && live
	}
	sessionID, _ := session.AccessClaims.Extra["sid"].(string)
	if sessionID == "" || session.Subject == "" || session.AccessClaims.Extra["act"] != nil {
		return false
	}
	var live bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_sessions s JOIN users u ON u.id=s.user_id
JOIN oauth_consents c ON c.application_id=s.application_id AND c.user_id=s.user_id
JOIN clients cl ON cl.id=c.client_id AND cl.application_id=c.application_id
WHERE s.id=$1 AND s.user_id=$2 AND s.application_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now()
AND u.application_id=s.application_id AND u.status='active' AND s.delegation_id IS NULL
AND c.revoked_at IS NULL AND cl.client_id=$4 AND cl.disabled_at IS NULL)`,
		sessionID, session.Subject, chi.URLParam(r, "application_id"), request.GetClient().GetID()).Scan(&live)
	return err == nil && live
}

func replaceApplicationScopes(request fosite.Requester, effective []string) {
	preserved := make([]string, 0, len(request.GetGrantedScopes()))
	for _, scope := range request.GetGrantedScopes() {
		if scope == "openid" || scope == "email" || scope == "profile" || scope == "offline_access" {
			preserved = append(preserved, scope)
		}
	}
	granted := append(preserved, effective...)
	switch typed := request.(type) {
	case *fosite.AccessRequest:
		typed.GrantedScope = nil
		for _, scope := range granted {
			typed.GrantScope(scope)
		}
	case *fosite.AuthorizeRequest:
		typed.GrantedScope = nil
		for _, scope := range granted {
			typed.GrantScope(scope)
		}
	}
}

func (s *Server) oauthProvider(w http.ResponseWriter, r *http.Request) (*oauthserver.Provider, bool) {
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return nil, false
	}
	clientID := r.FormValue("client_id")
	if basicID, _, ok := r.BasicAuth(); ok {
		clientID = basicID
	}
	resourceURI := ""
	if resource := resourceFromRequest(r); resource != nil {
		resourceURI = resource.URI
	}
	provider, err := oauthserver.NewProviderForClient(r.Context(), s.app, applicationID, clientID, resourceURI)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "oauth_provider_unavailable", "The OAuth provider is unavailable for this application.")
		return nil, false
	}
	s.configureResourceProvider(r, provider)
	return provider, true
}
