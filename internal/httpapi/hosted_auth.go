package httpapi

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/oauthserver"
	"golang.org/x/oauth2"
)

type hostedContextKey struct{}
type hostedPrivateState struct {
	Verifier              string   `json:"verifier"`
	CSRF                  string   `json:"csrf"`
	MFAChallenge          string   `json:"mfa_challenge,omitempty"`
	MFAMethods            []string `json:"mfa_methods,omitempty"`
	EmailChallenge        string   `json:"email_challenge,omitempty"`
	Enrollment            string   `json:"enrollment,omitempty"`
	Provider              string   `json:"provider,omitempty"`
	InvitationID          string   `json:"invitation_id,omitempty"`
	InvitationToken       string   `json:"invitation_token,omitempty"`
	InvitationMethod      string   `json:"invitation_method,omitempty"`
	RecoveryChallenge     string   `json:"recovery_challenge,omitempty"`
	VerificationChallenge string   `json:"verification_challenge,omitempty"`
	WebAuthnCeremony      string   `json:"webauthn_ceremony,omitempty"`
	ForceLogin            bool     `json:"force_login,omitempty"`
}
type hostedInteraction struct {
	ID            string
	ApplicationID string
	ClientID      string
	ClientName    string
	Params        url.Values
	Private       hostedPrivateState
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LockToken     string
}
type hostedActionRequest struct {
	Action       string          `json:"action"`
	Email        string          `json:"email,omitempty"`
	Password     string          `json:"password,omitempty"`
	FirstName    string          `json:"first_name,omitempty"`
	LastName     string          `json:"last_name,omitempty"`
	Code         string          `json:"code,omitempty"`
	RecoveryCode string          `json:"recovery_code,omitempty"`
	Provider     string          `json:"provider,omitempty"`
	Intent       string          `json:"intent,omitempty"`
	InvitationID string          `json:"invitation_id,omitempty"`
	LinkToken    string          `json:"link_token,omitempty"`
	Credential   json.RawMessage `json:"credential,omitempty"`
}

// Internal adapters capture existing authentication results without returning bearer
// credentials to the hosted browser or making an HTTP request to ourselves.
type hostedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (s *Server) hostedAuthorizationErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "text/html") || strings.Contains(r.Header.Get("Accept"), "application/json") {
			next.ServeHTTP(w, r)
			return
		}
		response := &hostedResponse{header: make(http.Header)}
		next.ServeHTTP(response, r)
		for name, values := range response.header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		if response.status >= 400 {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(response.status)
			_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign-in unavailable</title></head><body><main><h1>Sign-in unavailable</h1><p>The client or sign-in request is invalid or unavailable. Return to your application and start sign-in again.</p></main></body></html>`)
			return
		}
		status := response.status
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		_, _ = w.Write(response.body.Bytes())
	})
}

func (w *hostedResponse) Header() http.Header { return w.header }
func (w *hostedResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *hostedResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(b)
}
func (s *Server) hostedInvoke(r *http.Request, applicationID string, body any, handler http.HandlerFunc) *hostedResponse {
	encoded, _ := json.Marshal(body)
	clone := r.Clone(r.Context())
	clone.Method = http.MethodPost
	clone.Body = io.NopCloser(bytes.NewReader(encoded))
	clone.ContentLength = int64(len(encoded))
	clone.Header = r.Header.Clone()
	clone.Header.Del("Authorization")
	clone.Header.Set("Content-Type", "application/json")
	clone.Form = nil
	clone.PostForm = nil
	rc := chi.NewRouteContext()
	rc.URLParams.Add("application_id", applicationID)
	rc.URLParams.Add("provider", chi.URLParam(r, "provider"))
	clone = clone.WithContext(context.WithValue(clone.Context(), chi.RouteCtxKey, rc))
	response := &hostedResponse{header: make(http.Header)}
	handler(response, clone)
	return response
}
func hostedProviderRedirectAllowed(r *http.Request, redirect string) bool {
	expected, _ := r.Context().Value(hostedContextKey{}).(string)
	return expected != "" && expected == redirect
}

func (s *Server) hostedCookieName() string {
	if strings.HasPrefix(s.app.PublicURL, "https://") {
		return "__Host-p93_hosted_browser"
	}
	return "p93_hosted_browser"
}
func (s *Server) hostedBrowser(w http.ResponseWriter, r *http.Request, create bool) string {
	if c, e := r.Cookie(s.hostedCookieName()); e == nil && invitationPKCEVerifierPattern.MatchString(c.Value) {
		return c.Value
	}
	if !create {
		return ""
	}
	value := oauth2.GenerateVerifier()
	http.SetCookie(w, &http.Cookie{Name: s.hostedCookieName(), Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.app.PublicURL, "https://"), SameSite: http.SameSiteLaxMode})
	return value
}
func hostedPrompts(params url.Values) (map[string]bool, error) {
	p := map[string]bool{}
	for _, v := range strings.Fields(params.Get("prompt")) {
		switch v {
		case "none", "login", "consent", "select_account":
			p[v] = true
		default:
			return nil, errors.New("Unsupported authentication prompt.")
		}
	}
	if p["none"] && len(p) > 1 {
		return nil, errors.New("The none prompt cannot be combined with other prompts.")
	}
	if value := params.Get("max_age"); value != "" {
		n, e := strconv.ParseUint(value, 10, 32)
		if e != nil || n > 86400*365 {
			return nil, errors.New("max_age must be a nonnegative bounded number of seconds.")
		}
	}
	return p, nil
}

func (s *Server) startHostedAuthorization(w http.ResponseWriter, r *http.Request, provider *oauthserver.Provider, request fosite.AuthorizeRequester) bool {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return false
	}
	var id, name, ui string
	var required bool
	e := s.app.DB.QueryRow(r.Context(), `SELECT id,name,authorization_ui,pkce_required FROM clients WHERE application_id=$1 AND client_id=$2 AND disabled_at IS NULL`, chi.URLParam(r, "application_id"), request.GetClient().GetID()).Scan(&id, &name, &ui, &required)
	if e != nil || ui != "hosted" {
		return false
	}
	prompts, e := hostedPrompts(r.URL.Query())
	if e != nil {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrInvalidRequest)
		return true
	}
	challenge, method := r.URL.Query().Get("code_challenge"), r.URL.Query().Get("code_challenge_method")
	if (required || request.GetClient().IsPublic()) && challenge == "" || challenge != "" && (!invitationPKCEChallengePattern.MatchString(challenge) || method != "S256") || challenge == "" && method != "" {
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrInvalidRequest.WithHint("A valid S256 PKCE challenge is required."))
		return true
	}
	browser := s.hostedBrowser(w, r, true)
	if !s.allowAuthAttempt(w, r, "hosted-authorization", browser, 30, 5*time.Minute) {
		return true
	}
	interaction := hostedInteraction{ID: kernel.NewID().String(), ApplicationID: chi.URLParam(r, "application_id"), ClientID: request.GetClient().GetID(), ClientName: name, Params: url.Values{}, CreatedAt: s.app.Now(), ExpiresAt: s.app.Now().Add(15 * time.Minute)}
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "prompt", "max_age", "login_hint", "ui_locales"} {
		if value := r.URL.Query().Get(key); value != "" {
			interaction.Params.Set(key, value)
		}
	}
	interaction.Private = hostedPrivateState{Verifier: oauth2.GenerateVerifier(), CSRF: oauth2.GenerateVerifier(), ForceLogin: prompts["login"] || prompts["select_account"]}
	raw, _ := json.Marshal(interaction.Private)
	cipher, e := s.app.Vault.Encrypt(raw, "hosted-interaction:"+interaction.ID)
	params, _ := json.Marshal(interaction.Params)
	if e == nil {
		_, e = s.app.DB.Exec(r.Context(), `INSERT INTO hosted_auth_interactions(id,application_id,client_id,browser_digest,csrf_digest,authorization_parameters,pkce_required,private_state_ciphertext,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, interaction.ID, interaction.ApplicationID, id, s.app.Vault.Digest(browser), s.app.Vault.Digest(interaction.Private.CSRF), params, required, cipher, interaction.ExpiresAt)
	}
	if e != nil {
		kernel.WriteProblem(w, r, 500, "hosted_auth_unavailable", "The hosted sign-in request could not be created.")
		return true
	}
	current, profile, live := s.hostedActor(r, &interaction, browser)
	verificationRequired := live && stringSliceContains(strings.Fields(interaction.Params.Get("scope")), "email") && profile["email_verified"] != true
	if prompts["none"] && !live {
		s.consumeHostedInteraction(r, interaction.ID)
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrLoginRequired)
		return true
	}
	consent := live && s.hostedConsentKnown(r, &interaction, current.ID)
	if prompts["none"] && verificationRequired {
		s.consumeHostedInteraction(r, interaction.ID)
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrInteractionRequired)
		return true
	}
	if prompts["none"] && !consent {
		s.consumeHostedInteraction(r, interaction.ID)
		provider.OAuth.WriteAuthorizeError(r.Context(), w, request, fosite.ErrConsentRequired)
		return true
	}
	if live && consent && !verificationRequired && !prompts["consent"] && !prompts["select_account"] {
		s.completeHostedAuthorization(w, r, &interaction, current, false)
		return true
	}
	http.Redirect(w, r, "/auth/?interaction="+interaction.ID, http.StatusSeeOther)
	return true
}

func (s *Server) loadHostedInteraction(w http.ResponseWriter, r *http.Request, lock bool) (*hostedInteraction, string, bool) {
	browser := s.hostedBrowser(w, r, false)
	id := chi.URLParam(r, "interaction_id")
	if _, e := uuid.Parse(id); e != nil || browser == "" {
		kernel.WriteProblem(w, r, 401, "hosted_interaction_unavailable", "This sign-in request is unavailable. Restart sign-in from your application.")
		return nil, "", false
	}
	i := &hostedInteraction{ID: id}
	var params []byte
	var cipher string
	query := `SELECT h.application_id,c.client_id,c.name,h.authorization_parameters,h.private_state_ciphertext,h.created_at,h.expires_at
 FROM hosted_auth_interactions h JOIN clients c ON c.id=h.client_id JOIN applications a ON a.id=h.application_id
 WHERE h.id=$1 AND h.browser_digest=$2 AND h.consumed_at IS NULL AND h.expires_at>now() AND c.disabled_at IS NULL AND c.authorization_ui='hosted' AND a.deleted_at IS NULL`
	e := s.app.DB.QueryRow(r.Context(), query, id, s.app.Vault.Digest(browser)).Scan(&i.ApplicationID, &i.ClientID, &i.ClientName, &params, &cipher, &i.CreatedAt, &i.ExpiresAt)
	if e == nil {
		e = json.Unmarshal(params, &i.Params)
	}
	var raw []byte
	if e == nil {
		raw, e = s.app.Vault.Decrypt(cipher, "hosted-interaction:"+id)
	}
	if e == nil {
		e = json.Unmarshal(raw, &i.Private)
	}
	if e != nil {
		kernel.WriteProblem(w, r, 401, "hosted_interaction_unavailable", "This sign-in request expired or is unavailable. Restart sign-in from your application.")
		return nil, "", false
	}
	if lock {
		if !allowedControlOrigin(r.Header.Get("Origin"), s.app.PublicURL) || !equalBytes(s.app.Vault.Digest(r.Header.Get("X-CSRF-Token")), s.app.Vault.Digest(i.Private.CSRF)) {
			kernel.WriteProblem(w, r, 403, "hosted_csrf_failed", "The browser request could not be verified.")
			return nil, "", false
		}
		i.LockToken = kernel.NewID().String()
		result, e := s.app.DB.Exec(r.Context(), `UPDATE hosted_auth_interactions SET locked_until=now()+interval '2 minutes',lock_token=$3 WHERE id=$1 AND private_state_ciphertext=$2 AND consumed_at IS NULL AND expires_at>now() AND (locked_until IS NULL OR locked_until<now())`, id, cipher, i.LockToken)
		if e != nil || result.RowsAffected() != 1 {
			kernel.WriteProblem(w, r, 409, "hosted_interaction_busy", "Another action is running. Please wait before retrying.")
			return nil, "", false
		}
	}
	return i, browser, true
}
func (s *Server) releaseHostedInteraction(r *http.Request, i *hostedInteraction) {
	_, _ = s.app.DB.Exec(r.Context(), `UPDATE hosted_auth_interactions SET locked_until=NULL,lock_token=NULL WHERE id=$1 AND lock_token=$2`, i.ID, i.LockToken)
}
func (s *Server) saveHostedState(r *http.Request, i *hostedInteraction) error {
	raw, _ := json.Marshal(i.Private)
	cipher, e := s.app.Vault.Encrypt(raw, "hosted-interaction:"+i.ID)
	if e == nil {
		result, err := s.app.DB.Exec(r.Context(), `UPDATE hosted_auth_interactions SET private_state_ciphertext=$2 WHERE id=$1 AND consumed_at IS NULL AND lock_token=$3 AND locked_until>now()`, i.ID, cipher, i.LockToken)
		e = err
		if e == nil && result.RowsAffected() != 1 {
			e = errors.New("hosted interaction lease expired")
		}
	}
	return e
}
func (s *Server) consumeHostedInteraction(r *http.Request, id string, tokens ...string) bool {
	var token any
	if len(tokens) > 0 {
		token = nullableActorID(tokens[0])
	}
	result, e := s.app.DB.Exec(r.Context(), `UPDATE hosted_auth_interactions SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL AND (($2::uuid IS NULL AND (locked_until IS NULL OR locked_until<now())) OR (lock_token=$2::uuid AND locked_until>now()))`, id, token)
	return e == nil && result.RowsAffected() == 1
}

func (s *Server) hostedActor(r *http.Request, i *hostedInteraction, browser string) (kernel.Actor, map[string]any, bool) {
	current := kernel.Actor{Type: "user", ApplicationID: i.ApplicationID}
	var email, name string
	var verified bool
	var authAt, created time.Time
	e := s.app.DB.QueryRow(r.Context(), `SELECT u.id,ss.id,u.email,trim(u.first_name||' '||u.last_name),ss.authenticated_at,hs.created_at,u.email_verified_at IS NOT NULL
 FROM hosted_auth_sessions hs JOIN user_sessions ss ON ss.id=hs.session_id JOIN users u ON u.id=ss.user_id
 WHERE hs.application_id=$1 AND hs.browser_digest=$2 AND hs.expires_at>now() AND ss.application_id=$1 AND ss.revoked_at IS NULL AND ss.expires_at>now() AND ss.delegation_id IS NULL AND u.application_id=$1 AND u.status='active'`, i.ApplicationID, s.app.Vault.Digest(browser)).Scan(&current.ID, &current.SessionID, &email, &name, &authAt, &created, &verified)
	if e != nil || i.Private.MFAChallenge != "" || i.Private.ForceLogin && created.Before(i.CreatedAt) {
		return current, nil, false
	}
	if v := i.Params.Get("max_age"); v != "" {
		n, _ := strconv.ParseUint(v, 10, 32)
		if s.app.Now().Sub(authAt) > time.Duration(n)*time.Second && created.Before(i.CreatedAt) {
			return current, nil, false
		}
	}
	parsed, _ := uuid.Parse(i.ApplicationID)
	request := hostedApplicationRequest(r, i.ApplicationID)
	access, e := s.userEffectiveAccess(request, parsed, current.ID)
	if e != nil {
		return current, nil, false
	}
	current.Permissions = access.Scopes
	return current, map[string]any{"name": name, "email": email, "email_verified": verified}, true
}
func hostedApplicationRequest(r *http.Request, appID string) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("application_id", appID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}
func (s *Server) hostedConsentKnown(r *http.Request, i *hostedInteraction, userID string) bool {
	var known bool
	e := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM oauth_consents oc JOIN clients c ON c.id=oc.client_id WHERE oc.application_id=$1 AND oc.user_id=$2 AND c.client_id=$3 AND oc.revoked_at IS NULL AND $4::text[]<@oc.scopes)`, i.ApplicationID, userID, i.ClientID, strings.Fields(i.Params.Get("scope"))).Scan(&known)
	return e == nil && known
}

func (s *Server) getHostedInteraction(w http.ResponseWriter, r *http.Request) {
	i, browser, ok := s.loadHostedInteraction(w, r, false)
	if !ok {
		return
	}
	s.writeHostedView(w, r, i, browser, nil)
}
func (s *Server) writeHostedView(w http.ResponseWriter, r *http.Request, i *hostedInteraction, browser string, notice any) {
	b, e := s.effectiveHostedBranding(r.Context(), i.ApplicationID)
	if e != nil {
		kernel.WriteProblem(w, r, 500, "hosted_branding_unavailable", "Sign-in settings could not be loaded.")
		return
	}
	config, e := loadApplicationInternalConfig(r.Context(), s.app.DB, i.ApplicationID)
	if e != nil {
		kernel.WriteProblem(w, r, 404, "application_unavailable", "The application is unavailable.")
		return
	}
	providers := []string{}
	for _, p := range []string{"google", "apple", "microsoft", "facebook", "linkedin"} {
		if _, e := s.loadEffectiveAuthProvider(r.Context(), i.ApplicationID, p); e == nil {
			providers = append(providers, p)
		}
	}
	current, profile, live := s.hostedActor(r, i, browser)
	stage := "login"
	if i.Private.RecoveryChallenge != "" {
		stage = "recovery"
	}
	if i.Private.EmailChallenge != "" {
		stage = "email_code"
	}
	if i.Private.Enrollment != "" {
		stage = "external_email"
	}
	if i.Private.MFAChallenge != "" {
		stage = "mfa"
	}
	if live {
		stage = "consent"
	}
	if !live && i.Private.InvitationID != "" && i.Private.MFAChallenge == "" {
		stage = "invitation"
		providers = []string{}
		if i.Private.InvitationMethod != "email" {
			providers = append(providers, i.Private.InvitationMethod)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	view := map[string]any{"interaction_id": i.ID, "csrf_token": i.Private.CSRF, "application_id": i.ApplicationID, "client_name": i.ClientName, "branding": b, "stage": stage, "consent_required": live && (!s.hostedConsentKnown(r, i, current.ID) || strings.Contains(i.Params.Get("prompt"), "consent")), "requested_scopes": strings.Fields(i.Params.Get("scope")), "providers": providers, "password_enabled": config.PasswordEnabled, "passwordless_enabled": config.PasswordlessEnabled, "registration_enabled": config.RegistrationMode == "public", "expires_at": i.ExpiresAt, "ui_locales": i.Params.Get("ui_locales"), "notice": notice}
	if profile != nil {
		view["user"] = profile
	}
	view["mfa_methods"] = append([]string{}, i.Private.MFAMethods...)
	view["verification_pending"] = i.Private.VerificationChallenge != ""
	kernel.WriteJSON(w, 200, view)
}

func (s *Server) hostedAction(w http.ResponseWriter, r *http.Request) {
	i, browser, ok := s.loadHostedInteraction(w, r, true)
	if !ok {
		return
	}
	defer s.releaseHostedInteraction(r, i)
	var input hostedActionRequest
	if !kernel.DecodeJSON(w, r, &input) {
		return
	}
	current, _, live := s.hostedActor(r, i, browser)
	if input.Action == "approve" || input.Action == "deny" {
		if !live && input.Action == "approve" {
			kernel.WriteProblem(w, r, 401, "hosted_login_required", "Sign in before approving access.")
			return
		}
		s.completeHostedAuthorization(w, r, i, current, input.Action == "deny")
		return
	}
	if input.Action == "restart" {
		if i.Private.InvitationID != "" {
			var accepted bool
			if err := s.app.DB.QueryRow(r.Context(), `SELECT accepted_at IS NOT NULL FROM application_invitations WHERE id=$1 AND application_id=$2`, i.Private.InvitationID, i.ApplicationID).Scan(&accepted); err != nil {
				kernel.WriteProblem(w, r, 401, "hosted_invitation_unavailable", "The invitation is unavailable. Start sign-in from your application.")
				return
			}
			if accepted {
				_, start, err := s.hostedInvitationClient(r.Context(), i.ApplicationID, i.Params.Get("hosted_client_id"), i.Params.Get("redirect_uri"))
				if err != nil || !s.consumeHostedInteraction(r, i.ID, i.LockToken) {
					kernel.WriteProblem(w, r, 409, "hosted_invitation_unavailable", "The invitation could not be restarted. Start sign-in from your application.")
					return
				}
				kernel.WriteJSON(w, 200, map[string]any{"redirect_url": start})
				return
			}
		}
		i.Private = hostedPrivateState{Verifier: oauth2.GenerateVerifier(), CSRF: i.Private.CSRF, ForceLogin: true, InvitationID: i.Private.InvitationID, InvitationToken: i.Private.InvitationToken, InvitationMethod: i.Private.InvitationMethod}
		if e := s.saveHostedState(r, i); e != nil {
			kernel.WriteProblem(w, r, 500, "hosted_state_failed", "Sign-in could not be restarted.")
			return
		}
		s.writeHostedView(w, r, i, browser, nil)
		return
	}
	if input.Action == "switch_account" || input.Action == "logout" {
		tx, err := s.app.DB.Begin(r.Context())
		if err == nil {
			defer tx.Rollback(r.Context())
			_, err = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=now() WHERE id IN(SELECT session_id FROM hosted_auth_sessions WHERE application_id=$1 AND browser_digest=$2)`, i.ApplicationID, s.app.Vault.Digest(browser))
			if err == nil {
				_, err = tx.Exec(r.Context(), `DELETE FROM hosted_auth_sessions WHERE application_id=$1 AND browser_digest=$2`, i.ApplicationID, s.app.Vault.Digest(browser))
			}
			if err == nil {
				err = tx.Commit(r.Context())
			}
		}
		if err != nil {
			kernel.WriteProblem(w, r, 500, "hosted_logout_failed", "The application session could not be signed out. Please retry.")
			return
		}
		i.Private = hostedPrivateState{Verifier: oauth2.GenerateVerifier(), CSRF: i.Private.CSRF, ForceLogin: true, InvitationID: i.Private.InvitationID, InvitationToken: i.Private.InvitationToken, InvitationMethod: i.Private.InvitationMethod}
		if e := s.saveHostedState(r, i); e != nil {
			kernel.WriteProblem(w, r, 500, "hosted_state_failed", "The sign-in state could not be updated.")
			return
		}
		s.writeHostedView(w, r, i, browser, nil)
		return
	}
	body := map[string]any{}
	var handler http.HandlerFunc
	callback := strings.TrimRight(s.app.PublicURL, "/") + "/auth/return/" + i.ID
	r = r.WithContext(context.WithValue(r.Context(), hostedContextKey{}, callback))
	switch input.Action {
	case "password":
		body = map[string]any{"email": input.Email, "password": input.Password}
		handler = s.passwordSignIn
	case "signup":
		body = map[string]any{"email": input.Email, "password": input.Password, "first_name": input.FirstName, "last_name": input.LastName}
		handler = s.passwordSignUp
	case "email_start":
		intent := input.Intent
		if intent == "" {
			intent = "automatic"
		}
		body = map[string]any{"email": input.Email, "intent": intent, "delivery": "both", "redirect_uri": callback}
		handler = s.emailStart
	case "email_verify":
		body = map[string]any{"challenge_id": i.Private.EmailChallenge, "code": input.Code}
		handler = s.emailVerify
	case "mfa":
		body = map[string]any{"challenge_id": i.Private.MFAChallenge, "code": input.Code, "recovery_code": input.RecoveryCode}
		handler = s.verifyMFA
	case "webauthn_options":
		body = map[string]any{"challenge_id": i.Private.MFAChallenge, "origin": s.app.PublicURL}
		handler = s.beginWebAuthnAuthentication
	case "webauthn_verify":
		body = map[string]any{"ceremony_id": i.Private.WebAuthnCeremony, "credential": input.Credential}
		handler = s.finishWebAuthnAuthentication
	case "reset_start":
		body = map[string]any{"email": input.Email}
		handler = s.passwordResetStart
	case "reset_verify":
		body = map[string]any{"challenge_id": i.Private.RecoveryChallenge, "code": input.Code, "password": input.Password}
		handler = s.passwordResetVerify
	case "provider":
		if !stringSliceContains([]string{"google", "apple", "microsoft", "facebook", "linkedin"}, input.Provider) {
			kernel.WriteProblem(w, r, 422, "invalid_provider", "Select an available authentication provider.")
			return
		}
		rc := chi.NewRouteContext()
		rc.URLParams.Add("provider", input.Provider)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
		digest := sha256.Sum256([]byte(i.Private.Verifier))
		i.Private.Provider = input.Provider
		body = map[string]any{"flow": "automatic", "redirect_uri": callback, "code_challenge": base64.RawURLEncoding.EncodeToString(digest[:])}
		handler = s.startSocialAuth
		if input.Provider == "google" {
			handler = s.startGoogleAuth
		}
		if input.Provider == "apple" {
			handler = s.startAppleAuth
		}
		if i.Private.InvitationID != "" {
			if input.Provider != i.Private.InvitationMethod {
				kernel.WriteProblem(w, r, 422, "invitation_provider_required", "Use the invitation's selected sign-in provider.")
				return
			}
			body = map[string]any{"invitation_id": i.Private.InvitationID, "link_token": i.Private.InvitationToken, "code_challenge": base64.RawURLEncoding.EncodeToString(digest[:])}
			handler = s.startApplicationInvitationProvider
		}
	case "external_email_start":
		body = map[string]any{"enrollment": i.Private.Enrollment, "email": input.Email, "delivery": "code", "code_verifier": i.Private.Verifier}
		handler = s.startExternalEmailEnrollment
	case "external_email_verify":
		body = map[string]any{"enrollment": i.Private.Enrollment, "code": input.Code}
		handler = s.verifyExternalEmailEnrollment
	case "invitation":
		digest := sha256.Sum256([]byte(i.Private.Verifier))
		body = map[string]any{"code_challenge": base64.RawURLEncoding.EncodeToString(digest[:])}
		if i.Private.InvitationID != "" {
			body["invitation_id"], body["link_token"] = i.Private.InvitationID, i.Private.InvitationToken
		} else if input.InvitationID != "" {
			body["invitation_id"] = input.InvitationID
			body["link_token"] = input.LinkToken
		} else {
			body["email"] = input.Email
			body["code"] = input.Code
		}
		handler = s.exchangeInvitation
	case "verify_email_start":
		if !live {
			kernel.WriteProblem(w, r, 401, "hosted_login_required", "Sign in first.")
			return
		}
		r = r.WithContext(kernel.WithActor(r.Context(), current))
		handler = s.emailVerificationStart
	case "verify_email":
		if !live {
			kernel.WriteProblem(w, r, 401, "hosted_login_required", "Sign in first.")
			return
		}
		r = r.WithContext(kernel.WithActor(r.Context(), current))
		body = map[string]any{"challenge_id": i.Private.VerificationChallenge, "code": input.Code}
		handler = s.emailVerificationVerify
	default:
		kernel.WriteProblem(w, r, 422, "invalid_hosted_action", "This sign-in action is unavailable.")
		return
	}
	response := s.hostedInvoke(r, i.ApplicationID, body, handler)
	var result map[string]any
	_ = json.Unmarshal(response.body.Bytes(), &result)
	if input.Action == "invitation" && response.status < 400 {
		if code, ok := result["authorization_code"].(string); ok {
			response = s.hostedInvoke(r, i.ApplicationID, map[string]any{"authorization_code": code, "code_verifier": i.Private.Verifier}, s.redeemInvitationAuthorizationCode)
			_ = json.Unmarshal(response.body.Bytes(), &result)
		}
	}
	if response.status >= 400 {
		w.Header().Set("Content-Type", "application/problem+json")
		if retry := response.header.Get("Retry-After"); retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(response.status)
		_, _ = w.Write(response.body.Bytes())
		return
	}
	if input.Action == "webauthn_options" {
		i.Private.WebAuthnCeremony, _ = result["ceremony_id"].(string)
		if e := s.saveHostedState(r, i); e != nil {
			kernel.WriteProblem(w, r, 500, "hosted_state_failed", "The passkey request could not be saved.")
			return
		}
		kernel.WriteJSON(w, 200, result)
		return
	}
	if input.Action == "email_start" {
		i.Private.EmailChallenge, _ = result["challenge_id"].(string)
	}
	if input.Action == "reset_start" {
		i.Private.RecoveryChallenge, _ = result["challenge_id"].(string)
	}
	if input.Action == "reset_verify" {
		i.Private.RecoveryChallenge = ""
	}
	if input.Action == "verify_email_start" {
		i.Private.VerificationChallenge, _ = result["challenge_id"].(string)
	}
	if input.Action == "verify_email" {
		i.Private.VerificationChallenge = ""
	}
	if input.Action == "provider" {
		if e := s.saveHostedState(r, i); e != nil {
			kernel.WriteProblem(w, r, 500, "hosted_state_failed", "Sign-in state could not be saved.")
			return
		}
		kernel.WriteJSON(w, 200, map[string]any{"redirect_url": result["authorize_url"]})
		return
	}
	if e := s.acceptHostedAuthentication(r, i, browser, result); e != nil {
		kernel.WriteProblem(w, r, 500, "hosted_session_failed", "The sign-in session could not be established.")
		return
	}
	if e := s.saveHostedState(r, i); e != nil {
		kernel.WriteProblem(w, r, 500, "hosted_state_failed", "Sign-in state could not be saved.")
		return
	}
	s.writeHostedView(w, r, i, browser, nil)
}

func (s *Server) acceptHostedAuthentication(r *http.Request, i *hostedInteraction, browser string, result map[string]any) error {
	if required, _ := result["mfa_required"].(bool); required {
		i.Private.MFAChallenge, _ = result["challenge_id"].(string)
		i.Private.MFAMethods = nil
		if methods, ok := result["methods"].([]any); ok {
			for _, method := range methods {
				if value, ok := method.(string); ok {
					i.Private.MFAMethods = append(i.Private.MFAMethods, value)
				}
			}
		}
		return nil
	}
	token, _ := result["access_token"].(string)
	if token == "" {
		return nil
	}
	appID, _ := uuid.Parse(i.ApplicationID)
	claims, e := identity.Verify(token, func(kid string) (*rsa.PublicKey, error) { return s.app.ResolvePublicKey(r.Context(), kid) }, s.app.Issuer(), s.app.ApplicationAudience(appID), s.app.Now())
	if e != nil || claims.ActorType != "user" || claims.TokenKind != "access" || claims.ApplicationID != i.ApplicationID {
		return errors.New("invalid hosted authentication result")
	}
	bindingID := kernel.NewID().String()
	raw, _ := json.Marshal(result)
	cipher, e := s.app.Vault.Encrypt(raw, "hosted-session:"+bindingID)
	if e != nil {
		return e
	}
	resultWrite, e := s.app.DB.Exec(r.Context(), `INSERT INTO hosted_auth_sessions(id,application_id,session_id,browser_digest,credential_ciphertext,expires_at) SELECT $1,$2,id,$4,$5,expires_at FROM user_sessions WHERE id=$3 AND application_id=$2 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM hosted_auth_interactions WHERE id=$6 AND lock_token=$7 AND locked_until>now() AND consumed_at IS NULL)
 ON CONFLICT(application_id,browser_digest) DO UPDATE SET id=EXCLUDED.id,session_id=EXCLUDED.session_id,credential_ciphertext=EXCLUDED.credential_ciphertext,expires_at=EXCLUDED.expires_at,created_at=now()`, bindingID, i.ApplicationID, claims.SessionID, s.app.Vault.Digest(browser), cipher, i.ID, i.LockToken)
	if e == nil && resultWrite.RowsAffected() != 1 {
		e = errors.New("hosted session is unavailable")
	}
	if e == nil {
		i.Private.MFAChallenge = ""
		i.Private.EmailChallenge = ""
		i.Private.Enrollment = ""
		i.Private.ForceLogin = false
	}
	return e
}

func (s *Server) completeHostedAuthorization(w http.ResponseWriter, r *http.Request, i *hostedInteraction, current kernel.Actor, deny bool) {
	if !deny && stringSliceContains(strings.Fields(i.Params.Get("scope")), "email") {
		var verified bool
		if err := s.app.DB.QueryRow(r.Context(), `SELECT email_verified_at IS NOT NULL FROM users WHERE id=$1 AND application_id=$2 AND status='active'`, current.ID, i.ApplicationID).Scan(&verified); err != nil || !verified {
			kernel.WriteProblem(w, r, 403, "hosted_email_verification_required", "Verify your email before sharing it with this application.")
			return
		}
	}
	if i.Private.InvitationID != "" {
		var accepted bool
		if !deny {
			_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM application_invitations i JOIN users u ON u.application_id=i.application_id AND u.normalized_email=i.normalized_email WHERE i.id=$1 AND i.application_id=$2 AND u.id=$3 AND i.accepted_at IS NOT NULL)`, i.Private.InvitationID, i.ApplicationID, current.ID).Scan(&accepted)
		}
		_, start, err := s.hostedInvitationClient(r.Context(), i.ApplicationID, i.Params.Get("hosted_client_id"), i.Params.Get("redirect_uri"))
		if err != nil || (!deny && !accepted) {
			kernel.WriteProblem(w, r, 401, "hosted_invitation_unavailable", "The invitation could not be completed.")
			return
		}
		if !s.consumeHostedInteraction(r, i.ID, i.LockToken) {
			kernel.WriteProblem(w, r, 409, "hosted_interaction_consumed", "This request was already completed.")
			return
		}
		kernel.WriteJSON(w, 200, map[string]any{"redirect_url": start})
		return
	}
	request := hostedApplicationRequest(r, i.ApplicationID)
	clone := request.Clone(kernel.WithActor(request.Context(), current))
	clone.Method = http.MethodPost
	clone.URL = &url.URL{Path: "/oidc/authorize"}
	parameters := url.Values{}
	for key, values := range i.Params {
		parameters[key] = append([]string(nil), values...)
	}
	if deny {
		parameters.Set("decision", "deny")
	}
	encoded := parameters.Encode()
	clone.Body = io.NopCloser(strings.NewReader(encoded))
	clone.ContentLength = int64(len(encoded))
	clone.Form = nil
	clone.PostForm = nil
	clone.Header = r.Header.Clone()
	clone.Header.Set("Accept", "application/json")
	clone.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := &hostedResponse{header: make(http.Header)}
	if !s.consumeHostedInteraction(r, i.ID, i.LockToken) {
		kernel.WriteProblem(w, r, 409, "hosted_interaction_consumed", "This sign-in request was already completed.")
		return
	}
	s.oauthAuthorizeDecision(response, clone)
	var result struct {
		RedirectURI string `json:"redirect_to"`
	}
	_ = json.Unmarshal(response.body.Bytes(), &result)
	destination := result.RedirectURI
	if destination == "" {
		destination = response.header.Get("Location")
	}
	if destination == "" {
		kernel.WriteProblem(w, r, 400, "hosted_authorization_failed", "Authorization could not be completed. Restart sign-in from your application.")
		return
	}
	if r.Method == http.MethodGet {
		http.Redirect(w, r, destination, http.StatusSeeOther)
	} else {
		kernel.WriteJSON(w, 200, map[string]any{"redirect_url": destination})
	}
}

func (s *Server) hostedReturn(w http.ResponseWriter, r *http.Request) {
	i, browser, ok := s.loadHostedInteraction(w, r, false)
	if !ok {
		return
	}
	// A return URL never consumes a credential on GET. The hosted page confirms it
	// with a same-origin CSRF-protected POST, avoiding mail scanners and login CSRF.
	query := r.URL.Query()
	allowed := url.Values{"interaction": {i.ID}}
	for _, key := range []string{"challenge_id", "link_token", "external_auth_provider", "external_auth_exchange", "external_auth_error", "external_auth_email_enrollment", "platform93_flow"} {
		if v := query.Get(key); v != "" {
			allowed.Set(key, v)
		}
	}
	_ = browser
	http.Redirect(w, r, "/auth/?"+allowed.Encode(), http.StatusSeeOther)
}

func (s *Server) hostedReturnExchange(w http.ResponseWriter, r *http.Request) {
	i, browser, ok := s.loadHostedInteraction(w, r, true)
	if !ok {
		return
	}
	defer s.releaseHostedInteraction(r, i)
	var input struct {
		ChallengeID string `json:"challenge_id,omitempty"`
		LinkToken   string `json:"link_token,omitempty"`
		Provider    string `json:"provider,omitempty"`
		Code        string `json:"code,omitempty"`
		Enrollment  string `json:"enrollment,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &input) {
		return
	}
	if input.Enrollment != "" {
		if i.Private.Provider == "" || input.Provider != "" && input.Provider != i.Private.Provider {
			kernel.WriteProblem(w, r, 401, "hosted_provider_mismatch", "This provider does not belong to the current sign-in request.")
			return
		}
		i.Private.Enrollment = input.Enrollment
		if e := s.saveHostedState(r, i); e != nil {
			kernel.WriteProblem(w, r, 500, "hosted_state_failed", "Sign-in state could not be saved.")
			return
		}
		s.writeHostedView(w, r, i, browser, nil)
		return
	}
	var handler http.HandlerFunc
	body := map[string]any{}
	if input.ChallengeID != "" {
		if input.ChallengeID != i.Private.EmailChallenge {
			kernel.WriteProblem(w, r, 401, "hosted_challenge_mismatch", "This link does not belong to the current sign-in request.")
			return
		}
		body = map[string]any{"challenge_id": input.ChallengeID, "link_token": input.LinkToken}
		handler = s.emailVerify
	} else {
		if input.Provider != "" && input.Provider != i.Private.Provider {
			kernel.WriteProblem(w, r, 401, "hosted_provider_mismatch", "This provider does not belong to the current sign-in request.")
			return
		}
		input.Provider = i.Private.Provider
		if !stringSliceContains([]string{"google", "apple", "microsoft", "facebook", "linkedin"}, input.Provider) {
			kernel.WriteProblem(w, r, 422, "invalid_provider", "The provider return is invalid.")
			return
		}
		body = map[string]any{"exchange": input.Code, "code_verifier": i.Private.Verifier}
		handler = s.exchangeSocialAuth
		if input.Provider == "google" {
			handler = s.exchangeGoogleAuth
		}
		if input.Provider == "apple" {
			handler = s.exchangeAppleAuth
		}
		rc := chi.NewRouteContext()
		rc.URLParams.Add("provider", input.Provider)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
	}
	response := s.hostedInvoke(r, i.ApplicationID, body, handler)
	var result map[string]any
	_ = json.Unmarshal(response.body.Bytes(), &result)
	if response.status >= 400 {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(response.status)
		_, _ = w.Write(response.body.Bytes())
		return
	}
	if e := s.acceptHostedAuthentication(r, i, browser, result); e != nil {
		kernel.WriteProblem(w, r, 500, "hosted_session_failed", "Sign-in could not be completed.")
		return
	}
	if e := s.saveHostedState(r, i); e != nil {
		kernel.WriteProblem(w, r, 500, "hosted_state_failed", "Sign-in state could not be saved.")
		return
	}
	s.writeHostedView(w, r, i, browser, nil)
}
