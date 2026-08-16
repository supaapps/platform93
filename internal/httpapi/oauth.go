package httpapi

import (
	"encoding/base64"
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
		clientID := strings.TrimSpace(r.FormValue("client_id"))
		if basicClientID, _, ok := r.BasicAuth(); ok && basicClientID != "" {
			clientID = basicClientID
		}
		application := ""
		if clientID != "" {
			_ = s.app.DB.QueryRow(r.Context(), `SELECT application_id FROM clients
WHERE client_id=$1 AND disabled_at IS NULL`, clientID).Scan(&application)
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
	provider, ok := s.oauthProvider(w, r)
	if !ok {
		return
	}
	request, err := provider.OAuth.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, err)
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
	consentScopes := append([]string(nil), request.GetRequestedScopes()...)
	for _, scope := range consentScopes {
		request.GrantScope(scope)
	}
	applicationID, _ := uuid.Parse(chi.URLParam(r, "application_id"))
	request.GrantAudience(s.app.ApplicationAudience(applicationID))

	current := actor(r)
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
WHERE id=$1 AND application_id=$2 AND user_id=$3 AND revoked_at IS NULL`, current.SessionID, chi.URLParam(r, "application_id"), current.ID).
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
	if current.DelegatedBy != "" {
		effective.Roles = emptyRoleClaims()
	}
	session.AccessClaims.Extra = map[string]any{
		"application_id": chi.URLParam(r, "application_id"), "client_id": request.GetClient().GetID(),
		"token_kind": "access", "email": email, "email_verified": emailVerified,
		"is_org_verified": orgVerified, "locale": locale, "actor_type": "user", "scope": strings.Join(current.Permissions, " "),
		"sid": current.SessionID, "amr": amr, "custom_claims": customClaims, "roles": effective.Roles,
	}
	session.IDClaims.Extra = map[string]any{
		"application_id": chi.URLParam(r, "application_id"), "email": email, "email_verified": emailVerified,
		"is_org_verified": orgVerified, "locale": locale, "actor_type": "user", "given_name": firstName, "family_name": lastName, "sid": current.SessionID,
		"custom_claims": customClaims, "roles": effective.Roles,
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
	if !s.allowAuthAttempt(w, r, "oauth_token", clientID, 30, 10*time.Minute) {
		return
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
		provider.OAuth.WriteAccessError(r.Context(), w, request, err)
		return
	}
	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}
	applicationID, _ := uuid.Parse(chi.URLParam(r, "application_id"))
	request.GrantAudience(s.app.ApplicationAudience(applicationID))
	if request.GetGrantTypes().ExactOne("client_credentials") {
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
		}
		request.SetSession(session)
	} else if request.GetGrantTypes().ExactOne("refresh_token") || request.GetGrantTypes().ExactOne("authorization_code") {
		storedSession, sessionOK := request.GetSession().(*oauthserver.Session)
		if !sessionOK || storedSession.Subject == "" {
			provider.OAuth.WriteAccessError(r.Context(), w, request, fosite.ErrInvalidGrant)
			return
		}
		var active bool
		err = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users
WHERE id=$1 AND application_id=$2 AND status='active')`, storedSession.Subject, applicationID).Scan(&active)
		if err != nil || !active {
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
		if storedSession.IDClaims.Extra == nil {
			storedSession.IDClaims.Extra = map[string]any{}
		}
		storedSession.IDClaims.Extra["custom_claims"] = customClaims
		storedSession.IDClaims.Extra["roles"] = effective.Roles
		request.SetSession(storedSession)
	}
	response, err := provider.OAuth.NewAccessResponse(r.Context(), request)
	if err != nil {
		provider.OAuth.WriteAccessError(r.Context(), w, request, err)
		return
	}
	provider.OAuth.WriteAccessResponse(r.Context(), w, request, response)
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
	if tokenKind == "machine" {
		var live bool
		err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients
WHERE client_id=$1 AND application_id=$2 AND disabled_at IS NULL)`, session.Subject, chi.URLParam(r, "application_id")).Scan(&live)
		return err == nil && live
	}
	sessionID, _ := session.AccessClaims.Extra["sid"].(string)
	if sessionID == "" || session.Subject == "" {
		return false
	}
	var live bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_sessions s JOIN users u ON u.id=s.user_id
WHERE s.id=$1 AND s.user_id=$2 AND s.application_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active')`,
		sessionID, session.Subject, chi.URLParam(r, "application_id")).Scan(&live)
	return err == nil && live
}

func replaceApplicationScopes(request fosite.Requester, effective []string) {
	preserved := make([]string, 0, len(request.GetGrantedScopes()))
	for _, scope := range request.GetGrantedScopes() {
		if !strings.HasPrefix(scope, "/applications/") {
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
	provider, err := oauthserver.NewProvider(r.Context(), s.app, applicationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "oauth_provider_unavailable", "The OAuth provider is unavailable for this application.")
		return nil, false
	}
	return provider, true
}
