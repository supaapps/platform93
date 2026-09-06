package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type controlExternalIdentity struct {
	Subject   string
	Email     string
	FirstName string
	LastName  string
}

func (s *Server) startControlProviderLogin(w http.ResponseWriter, r *http.Request) {
	s.startControlExternalAuth(w, r, chi.URLParam(r, "provider"), "login", "", "")
}

func (s *Server) startControlProviderLink(w http.ResponseWriter, r *http.Request) {
	var recent bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT authenticated_at>now()-interval '10 minutes' FROM control_user_sessions
WHERE id=$1 AND control_user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, actor(r).SessionID, actor(r).ID).Scan(&recent)
	if !recent {
		kernel.WriteProblem(w, r, http.StatusConflict, "recent_authentication_required", "Sign in again before linking an external identity.")
		return
	}
	s.startControlExternalAuth(w, r, chi.URLParam(r, "provider"), "link", actor(r).ID, "")
}

func (s *Server) startControlInvitationProvider(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	var request struct {
		InvitationToken string `json:"invitation_token"`
	}
	if !kernel.DecodeJSON(w, r, &request) || request.InvitationToken == "" {
		return
	}
	var invitationID string
	err := s.app.DB.QueryRow(r.Context(), `SELECT id FROM control_user_invitations
WHERE credential_digest=$1 AND onboarding_method=$2 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`,
		s.app.Vault.Digest(request.InvitationToken), provider).Scan(&invitationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_control_user_invitation", "The Platform user invitation is invalid or expired.")
		return
	}
	s.startControlExternalAuth(w, r, provider, "invitation", "", invitationID)
}

func (s *Server) startControlExternalAuth(w http.ResponseWriter, r *http.Request, provider, flow, requestedBy, invitationID string) {
	if !validExternalAuthProvider(provider) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "control_auth_provider_not_found", "The Platform authentication provider is unavailable.")
		return
	}
	if !s.allowAuthAttempt(w, r, "control_external_"+provider, requestedBy+invitationID, 12, 10*time.Minute) {
		return
	}
	config, err := s.loadControlAuthProvider(r, provider)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "control_auth_provider_unavailable", "The Platform authentication provider is unavailable.")
		return
	}
	state, _ := secure.RandomToken("p93_control_"+provider+"_state_", 32)
	nonce, _ := secure.RandomToken("", 32)
	verifier := oauth2.GenerateVerifier()
	challengeID := kernel.NewID()
	verifierValue := providerVerifierValue(provider, verifier)
	ciphertext, err := s.app.Vault.Encrypt([]byte(verifierValue), "control-external-auth:"+challengeID.String())
	var requestedByValue, invitationValue any
	if requestedBy != "" {
		requestedByValue = requestedBy
	}
	if invitationID != "" {
		invitationValue = invitationID
	}
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO control_user_external_auth_challenges
(id,auth_provider_config_id,provider,flow,requested_by_control_user_id,invitation_id,state_digest,nonce_digest,verifier_ciphertext,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, challengeID, config.ID, provider, flow, requestedByValue, invitationValue,
			s.app.Vault.Digest(state), s.app.Vault.Digest(nonce), ciphertext, s.app.Now().Add(10*time.Minute))
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "control_external_auth_start_failed", "The Platform authentication flow could not be started.")
		return
	}
	var authorizeURL string
	if provider == "google" {
		oauthConfig := oauth2.Config{ClientID: config.ClientID, ClientSecret: config.Credentials["client_secret"], Endpoint: google.Endpoint,
			RedirectURL: s.externalAuthCallbackURI("google"), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
		authorizeURL = oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("prompt", "select_account"))
	} else if provider == "apple" {
		query := url.Values{"client_id": {config.ClientID}, "redirect_uri": {s.externalAuthCallbackURI("apple")}, "response_type": {"code"},
			"response_mode": {"form_post"}, "scope": {"name email"}, "state": {state}, "nonce": {nonce}}
		authorizeURL = "https://appleid.apple.com/auth/authorize?" + query.Encode()
	} else {
		authorizeURL, err = providerAuthorizationURL(config, s.externalAuthCallbackURI(provider), state, nonce, verifier, "")
		if err != nil {
			s.consumeControlExternalChallenge(r, challengeID.String())
			kernel.WriteProblem(w, r, http.StatusInternalServerError, "control_external_auth_start_failed", "The provider authorization request could not be created.")
			return
		}
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"provider": provider, "authorize_url": authorizeURL, "expires_in": 600})
}

func (s *Server) loadControlAuthProvider(r *http.Request, provider string) (externalAuthProviderConfig, error) {
	var value externalAuthProviderConfig
	var ciphertext string
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,provider,client_id,config_ciphertext,inheritable,control_login_enabled
FROM auth_provider_configs WHERE provider=$1 AND application_id IS NULL AND organization_id IS NULL
AND disabled_at IS NULL AND control_login_enabled`, provider).Scan(&value.ID, &value.Provider, &value.ClientID, &ciphertext, &value.Inheritable, &value.ControlLoginEnabled)
	if err != nil {
		return value, err
	}
	plaintext, err := s.app.Vault.Decrypt(ciphertext, "auth-provider:"+value.ID)
	if err != nil || json.Unmarshal(plaintext, &value.Credentials) != nil {
		return value, fmt.Errorf("control provider unavailable")
	}
	value.Scope = "installation"
	return value, nil
}

func (s *Server) routeControlExternalCallback(w http.ResponseWriter, r *http.Request, provider, state string) bool {
	var exists bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM control_user_external_auth_challenges
WHERE provider=$1 AND state_digest=$2 AND consumed_at IS NULL AND expires_at>now())`, provider, s.app.Vault.Digest(state)).Scan(&exists)
	if !exists {
		return false
	}
	s.controlExternalCallback(w, r, provider, state)
	return true
}

func (s *Server) controlExternalCallback(w http.ResponseWriter, r *http.Request, provider, state string) {
	var challengeID, providerConfigID, flow, verifierCiphertext string
	var requestedBy, invitationID *string
	var nonceDigest []byte
	err := s.app.DB.QueryRow(r.Context(), `UPDATE control_user_external_auth_challenges SET locked_until=now()+interval '2 minutes'
WHERE provider=$1 AND state_digest=$2 AND consumed_at IS NULL AND expires_at>now() AND (locked_until IS NULL OR locked_until<now())
RETURNING id,auth_provider_config_id,flow,requested_by_control_user_id,invitation_id,nonce_digest,verifier_ciphertext`, provider, s.app.Vault.Digest(state)).
		Scan(&challengeID, &providerConfigID, &flow, &requestedBy, &invitationID, &nonceDigest, &verifierCiphertext)
	if err != nil {
		s.redirectControlExternal(w, r, provider, "invalid_state")
		return
	}
	if r.Form.Get("error") != "" || r.URL.Query().Get("error") != "" {
		s.consumeControlExternalChallenge(r, challengeID)
		s.redirectControlExternal(w, r, provider, "provider_denied")
		return
	}
	config, configErr := s.loadControlAuthProvider(r, provider)
	if configErr != nil || config.ID != providerConfigID {
		s.consumeControlExternalChallenge(r, challengeID)
		s.redirectControlExternal(w, r, provider, "provider_unavailable")
		return
	}
	verifier, decryptErr := s.app.Vault.Decrypt(verifierCiphertext, "control-external-auth:"+challengeID)
	var external controlExternalIdentity
	if decryptErr == nil && provider == "google" {
		external, err = s.verifyControlGoogle(r, config, string(verifier), nonceDigest)
	} else if decryptErr == nil && provider == "apple" {
		external, err = s.verifyControlApple(r, config, nonceDigest)
	} else if decryptErr == nil {
		var identity externalProviderIdentity
		identity, err = exchangeExternalProviderIdentity(r.Context(), config, s.externalAuthCallbackURI(provider), r.Form.Get("code"), string(verifier), nonceDigest, s.app.Vault.Digest)
		external = controlExternalIdentity{Subject: identity.Subject, Email: kernel.NormalizeEmail(identity.Email), FirstName: identity.FirstName, LastName: identity.LastName}
		if err == nil && flow == "invitation" && invitationID != nil && !identity.TrustedEmail {
			err = s.app.DB.QueryRow(r.Context(), `SELECT normalized_email FROM control_user_invitations WHERE id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`, *invitationID).Scan(&external.Email)
		}
	} else {
		err = decryptErr
	}
	if err != nil {
		s.consumeControlExternalChallenge(r, challengeID)
		s.redirectControlExternal(w, r, provider, "provider_identity_invalid")
		return
	}
	if flow == "link" && requestedBy != nil {
		err = s.linkControlExternalIdentity(r, challengeID, *requestedBy, config, external)
		if err == nil {
			s.redirectControlExternal(w, r, provider, "")
			return
		}
	} else {
		var invitation string
		if invitationID != nil {
			invitation = *invitationID
		}
		err = s.completeControlExternalSignIn(w, r, challengeID, flow, invitation, config, external)
		if err == nil {
			return
		}
	}
	s.consumeControlExternalChallenge(r, challengeID)
	s.redirectControlExternal(w, r, provider, "account_unavailable")
}

func (s *Server) verifyControlGoogle(r *http.Request, config externalAuthProviderConfig, verifier string, nonceDigest []byte) (controlExternalIdentity, error) {
	oauthConfig := oauth2.Config{ClientID: config.ClientID, ClientSecret: config.Credentials["client_secret"], Endpoint: google.Endpoint,
		RedirectURL: s.externalAuthCallbackURI("google"), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	token, err := oauthConfig.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return controlExternalIdentity{}, err
	}
	raw, _ := token.Extra("id_token").(string)
	verified, err := oidc.NewVerifier("https://accounts.google.com", oidc.NewRemoteKeySet(r.Context(), "https://www.googleapis.com/oauth2/v3/certs"), &oidc.Config{ClientID: config.ClientID}).Verify(r.Context(), raw)
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		FirstName     string `json:"given_name"`
		LastName      string `json:"family_name"`
		Nonce         string `json:"nonce"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err == nil {
		err = verified.Claims(&claims)
	}
	if err != nil || claims.Subject == "" || !claims.EmailVerified || !equalBytes(nonceDigest, s.app.Vault.Digest(claims.Nonce)) {
		return controlExternalIdentity{}, fmt.Errorf("invalid google identity")
	}
	return controlExternalIdentity{Subject: claims.Subject, Email: kernel.NormalizeEmail(claims.Email), FirstName: claims.FirstName, LastName: claims.LastName}, nil
}

func (s *Server) verifyControlApple(r *http.Request, config externalAuthProviderConfig, nonceDigest []byte) (controlExternalIdentity, error) {
	secret, err := createAppleClientSecret(config, s.app.Now())
	if err != nil {
		return controlExternalIdentity{}, err
	}
	form := url.Values{"client_id": {config.ClientID}, "client_secret": {secret}, "code": {r.Form.Get("code")}, "grant_type": {"authorization_code"}, "redirect_uri": {s.externalAuthCallbackURI("apple")}}
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://appleid.apple.com/auth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return controlExternalIdentity{}, err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	var tokenResponse struct {
		IDToken string `json:"id_token"`
	}
	if response.StatusCode/100 != 2 || json.Unmarshal(body, &tokenResponse) != nil {
		return controlExternalIdentity{}, fmt.Errorf("apple exchange failed")
	}
	verified, err := oidc.NewVerifier("https://appleid.apple.com", oidc.NewRemoteKeySet(r.Context(), "https://appleid.apple.com/auth/keys"), &oidc.Config{ClientID: config.ClientID}).Verify(r.Context(), tokenResponse.IDToken)
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		Nonce         string `json:"nonce"`
		EmailVerified any    `json:"email_verified"`
	}
	if err == nil {
		err = verified.Claims(&claims)
	}
	firstName, lastName := appleCallbackName(r.Form.Get("user"))
	if err != nil || claims.Subject == "" || !appleEmailVerified(claims.EmailVerified) || !equalBytes(nonceDigest, s.app.Vault.Digest(claims.Nonce)) {
		return controlExternalIdentity{}, fmt.Errorf("invalid apple identity")
	}
	return controlExternalIdentity{Subject: claims.Subject, Email: kernel.NormalizeEmail(claims.Email), FirstName: firstName, LastName: lastName}, nil
}

func (s *Server) linkControlExternalIdentity(r *http.Request, challengeID, controlUserID string, config externalAuthProviderConfig, external controlExternalIdentity) error {
	metadata, _ := json.Marshal(map[string]any{"email": external.Email, "first_name": external.FirstName, "last_name": external.LastName})
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return err
	}
	defer rollback(tx, r.Context())
	identityID := kernel.NewID()
	_, err = tx.Exec(r.Context(), `INSERT INTO control_user_identities
(id,control_user_id,auth_provider_config_id,provider,provider_subject,metadata,last_used_at) VALUES($1,$2,$3,$4,$5,$6,now())`,
		identityID, controlUserID, config.ID, config.Provider, external.Subject, metadata)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_external_auth_challenges SET consumed_at=now(),locked_until=NULL WHERE id=$1`, challengeID)
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.identity_linked", "control_user/"+controlUserID,
			map[string]any{"control_user_id": controlUserID, "provider": config.Provider})
	}
	if err == nil {
		err = insertControlAuthAudit(r.Context(), tx, r, controlUserID, "control_user.identity_linked", "control_user_identity", identityID.String(),
			map[string]any{"provider": config.Provider})
	}
	if err != nil {
		return err
	}
	return tx.Commit(r.Context())
}

func (s *Server) completeControlExternalSignIn(w http.ResponseWriter, r *http.Request, challengeID, flow, invitationID string, config externalAuthProviderConfig, external controlExternalIdentity) error {
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return err
	}
	defer rollback(tx, r.Context())
	var controlUserID string
	if flow == "login" {
		err = tx.QueryRow(r.Context(), `SELECT u.id FROM control_user_identities i JOIN control_users u ON u.id=i.control_user_id
WHERE i.auth_provider_config_id=$1 AND i.provider_subject=$2 AND u.status='active' FOR UPDATE OF i`, config.ID, external.Subject).Scan(&controlUserID)
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE control_user_identities SET last_used_at=now() WHERE auth_provider_config_id=$1 AND provider_subject=$2`, config.ID, external.Subject)
		}
	} else if flow == "invitation" {
		var email, role string
		var organizationID *string
		var identityCreated bool
		err = tx.QueryRow(r.Context(), `SELECT normalized_email,role,organization_id FROM control_user_invitations
WHERE id=$1 AND onboarding_method=$2 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, invitationID, config.Provider).
			Scan(&email, &role, &organizationID)
		if err == nil && email != external.Email {
			err = fmt.Errorf("invitation email mismatch")
		}
		displayName := strings.TrimSpace(external.FirstName + " " + external.LastName)
		if displayName == "" {
			displayName = strings.Split(email, "@")[0]
		}
		var controlUserStatus string
		if err == nil {
			err = tx.QueryRow(r.Context(), `INSERT INTO control_users(id,email,normalized_email,display_name)
VALUES($1,$2,$2,$3) ON CONFLICT(normalized_email) DO UPDATE SET display_name=CASE WHEN control_users.display_name='' THEN EXCLUDED.display_name ELSE control_users.display_name END
RETURNING id,status`, kernel.NewID(), email, truncate(displayName, 200)).Scan(&controlUserID, &controlUserStatus)
		}
		if err == nil && controlUserStatus != "active" {
			err = fmt.Errorf("control user unavailable")
		}
		metadata, _ := json.Marshal(map[string]any{"email": external.Email, "first_name": external.FirstName, "last_name": external.LastName})
		if err == nil {
			err = tx.QueryRow(r.Context(), `INSERT INTO control_user_identities
(id,control_user_id,auth_provider_config_id,provider,provider_subject,metadata,last_used_at) VALUES($1,$2,$3,$4,$5,$6,now())
ON CONFLICT(control_user_id,auth_provider_config_id) DO UPDATE SET last_used_at=now(),metadata=EXCLUDED.metadata
RETURNING (xmax=0)`, kernel.NewID(), controlUserID, config.ID, config.Provider, external.Subject, metadata).Scan(&identityCreated)
		}
		if err == nil && organizationID == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,$2)
ON CONFLICT(control_user_id) DO UPDATE SET role=EXCLUDED.role,updated_at=now()`, controlUserID, role)
		} else if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO organization_memberships(organization_id,control_user_id,role) VALUES($1,$2,$3)
ON CONFLICT(organization_id,control_user_id) DO UPDATE SET role=EXCLUDED.role`, *organizationID, controlUserID, role)
		}
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE control_user_invitations SET accepted_by=$1,accepted_at=now(),updated_at=now() WHERE id=$2`, controlUserID, invitationID)
		}
		if err == nil && identityCreated {
			err = s.emitControlEvent(r.Context(), tx, r, "control_user.identity_linked", "control_user/"+controlUserID,
				map[string]any{"control_user_id": controlUserID, "provider": config.Provider})
		}
		if err == nil {
			err = s.emitControlEvent(r.Context(), tx, r, "control_user.invitation_accepted", "control_user_invitation/"+invitationID,
				controlInvitationEventData(invitationID, organizationID, controlUserID, role, config.Provider, "accepted"))
		}
		if err == nil {
			err = insertControlAuthAudit(r.Context(), tx, r, controlUserID, "control_user.invitation_accepted", "control_user_invitation", invitationID,
				map[string]any{"provider": config.Provider, "organization_id": organizationID, "role": role})
		}
	} else {
		err = fmt.Errorf("invalid control external flow")
	}
	refresh, tokenErr := secure.RandomToken("p93_control_refresh_", 32)
	sessionID := kernel.NewID()
	if err == nil && tokenErr == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO control_user_sessions
(id,control_user_id,refresh_digest,kind,ip_address,user_agent,amr,expires_at) VALUES($1,$2,$3,'control',$4,$5,$6,$7)`, sessionID, controlUserID,
			s.app.Vault.Digest(refresh), requestIPAddress(r), truncate(r.UserAgent(), 500), []string{config.Provider}, s.app.Now().Add(12*time.Hour))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_external_auth_challenges SET consumed_at=now(),locked_until=NULL WHERE id=$1`, challengeID)
	}
	access, tokenErr := s.issueControlUserAccessWithQuerier(r.Context(), tx, controlUserID, sessionID.String(), "control")
	if err != nil || tokenErr != nil {
		return fmt.Errorf("control external session failed")
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	s.setControlUserCookies(w, access, refresh, 12*time.Hour)
	http.Redirect(w, r, strings.TrimRight(s.app.PublicURL, "/")+"/?control_provider="+url.QueryEscape(config.Provider)+"&status=success", http.StatusFound)
	return nil
}

func (s *Server) consumeControlExternalChallenge(r *http.Request, challengeID string) {
	_, _ = s.app.DB.Exec(r.Context(), `UPDATE control_user_external_auth_challenges SET consumed_at=now(),locked_until=NULL WHERE id=$1`, challengeID)
}

func (s *Server) redirectControlExternal(w http.ResponseWriter, r *http.Request, provider, failure string) {
	query := url.Values{"control_provider": {provider}}
	if failure == "" {
		query.Set("status", "success")
	} else {
		query.Set("error", failure)
	}
	http.Redirect(w, r, strings.TrimRight(s.app.PublicURL, "/")+"/?"+query.Encode(), http.StatusFound)
}

func (s *Server) unlinkControlUserIdentity(w http.ResponseWriter, r *http.Request) {
	var recent bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT authenticated_at>now()-interval '10 minutes' FROM control_user_sessions
WHERE id=$1 AND control_user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, actor(r).SessionID, actor(r).ID).Scan(&recent)
	if !recent {
		kernel.WriteProblem(w, r, http.StatusConflict, "recent_authentication_required", "Sign in again before unlinking an external identity.")
		return
	}
	identityID := chi.URLParam(r, "identity_id")
	var provider string
	if s.app.DB.QueryRow(r.Context(), `SELECT provider FROM control_user_identities WHERE id=$1 AND control_user_id=$2`, identityID, actor(r).ID).Scan(&provider) != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "control_user_identity_not_found", "The linked identity was not found.")
		return
	}
	policy, err := s.loadControlAuthPolicy(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform authentication safety could not be checked.")
		return
	}
	var usable bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT
(EXISTS(SELECT 1 FROM notification_providers WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL) AND ($2 OR $3))
OR ($4 AND u.password_hash IS NOT NULL)
OR EXISTS(SELECT 1 FROM control_user_identities i JOIN auth_provider_configs p ON p.id=i.auth_provider_config_id
WHERE i.control_user_id=u.id AND i.id<>$5 AND p.disabled_at IS NULL AND p.control_login_enabled)
FROM control_users u WHERE u.id=$1`, actor(r).ID, policy.EmailCodeEnabled, policy.MagicLinkEnabled, policy.PasswordEnabled, identityID).Scan(&usable)
	if !usable {
		kernel.WriteProblem(w, r, http.StatusConflict, "control_auth_owner_lockout", "Unlinking this identity would leave the Platform user without a usable sign-in method.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM control_user_identities WHERE id=$1 AND control_user_id=$2`, identityID, actor(r).ID)
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.identity_unlinked", "control_user/"+actor(r).ID,
			map[string]any{"control_user_id": actor(r).ID, "provider": provider})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "control_user_identity_not_found", "The linked identity was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
