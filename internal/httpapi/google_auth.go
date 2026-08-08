package httpapi

import (
	"encoding/json"
	"fmt"
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

type googleProviderConfig struct {
	ID           string
	ClientID     string
	ClientSecret string
}

func (s *Server) configureGoogleProviderLegacy(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if !kernel.DecodeJSON(w, r, &request) || strings.TrimSpace(request.ClientID) == "" || strings.TrimSpace(request.ClientSecret) == "" {
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	var id string
	if s.app.DB.QueryRow(r.Context(), `SELECT id FROM application_secrets WHERE application_id=$1 AND kind='auth_provider' AND name='google'`, applicationID).Scan(&id) != nil {
		id = kernel.NewID().String()
	}
	ciphertext, err := s.app.Vault.Encrypt([]byte(request.ClientSecret), "application-secret:"+id)
	metadata, _ := json.Marshal(map[string]any{"client_id": strings.TrimSpace(request.ClientID)})
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO application_secrets(id,application_id,kind,name,ciphertext,metadata)
VALUES ($1,$2,'auth_provider','google',$3,$4) ON CONFLICT (application_id,kind,name) DO UPDATE
SET ciphertext=EXCLUDED.ciphertext,metadata=EXCLUDED.metadata,updated_at=now()`, id, applicationID, ciphertext, metadata)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "google_provider_configuration_failed", "The Google provider could not be configured.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"provider": "google", "client_id": request.ClientID,
		"callback_uri": s.googleCallbackURI(applicationID), "configured": true})
}

func (s *Server) listAuthProvidersLegacy(w http.ResponseWriter, r *http.Request) {
	var clientID string
	err := s.app.DB.QueryRow(r.Context(), `SELECT metadata->>'client_id' FROM application_secrets
WHERE application_id=$1 AND kind='auth_provider' AND name='google'`, chi.URLParam(r, "application_id")).Scan(&clientID)
	items := []map[string]any{}
	if err == nil && clientID != "" {
		items = append(items, map[string]any{"provider": "google", "configured": true, "client_id": clientID})
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) startGoogleAuth(w http.ResponseWriter, r *http.Request) {
	s.startGoogleAuthFlow(w, r, "", "")
}

func (s *Server) startGoogleLink(w http.ResponseWriter, r *http.Request) {
	s.startGoogleAuthFlow(w, r, "link", actor(r).ID)
}

func (s *Server) startGoogleAuthFlow(w http.ResponseWriter, r *http.Request, forcedFlow, requestedBy string) {
	var request struct {
		Flow        string `json:"flow,omitempty"`
		RedirectURI string `json:"redirect_uri"`
		LoginHint   string `json:"login_hint,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if forcedFlow != "" {
		request.Flow = forcedFlow
	}
	if request.Flow == "" {
		request.Flow = "automatic"
	}
	if request.Flow != "sign_in" && request.Flow != "sign_up" && request.Flow != "automatic" && request.Flow != "link" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_google_flow", "Google flow must be sign_in, sign_up, automatic, or link.")
		return
	}
	if request.Flow == "link" && requestedBy == "" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "authenticated_link_required", "Linking Google requires a directly authenticated user session.")
		return
	}
	var redirectAllowed bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients
WHERE application_id=$1 AND disabled_at IS NULL AND $2=ANY(redirect_uris))`, chi.URLParam(r, "application_id"), request.RedirectURI).Scan(&redirectAllowed)
	if !redirectAllowed {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "redirect_uri_not_allowed", "The redirect URI must exactly match an enabled client redirect URI.")
		return
	}
	provider, err := s.googleProvider(r)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "google_provider_unavailable", "Google authentication is not configured.")
		return
	}
	state, _ := secure.RandomToken("p93_google_state_", 32)
	nonce, _ := secure.RandomToken("", 32)
	verifier := oauth2.GenerateVerifier()
	challengeID := kernel.NewID()
	verifierCiphertext, err := s.app.Vault.Encrypt([]byte(verifier), "external-auth:"+challengeID.String())
	var requestedByUserID *string
	if requestedBy != "" {
		requestedByUserID = &requestedBy
	}
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO external_auth_challenges
(id,application_id,provider,flow,requested_by_user_id,app_redirect_uri,state_digest,nonce_digest,verifier_ciphertext,expires_at)
VALUES ($1,$2,'google',$3,$4,$5,$6,$7,$8,$9)`, challengeID, chi.URLParam(r, "application_id"), request.Flow,
			requestedByUserID, request.RedirectURI, s.app.Vault.Digest(state), s.app.Vault.Digest(nonce), verifierCiphertext, s.app.Now().Add(10*time.Minute))
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "google_auth_start_failed", "The Google authentication flow could not be started.")
		return
	}
	config := s.googleOAuthConfig(chi.URLParam(r, "application_id"), provider)
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("prompt", "select_account")}
	if request.LoginHint != "" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", request.LoginHint))
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"provider": "google", "authorize_url": config.AuthCodeURL(state, options...), "expires_in": 600})
}

func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_google_state", "The Google authentication state is missing.")
		return
	}
	var challengeID, flow, appRedirect, verifierCiphertext string
	var requestedBy *string
	var nonceDigest []byte
	err := s.app.DB.QueryRow(r.Context(), `UPDATE external_auth_challenges SET locked_until=now()+interval '2 minutes'
WHERE application_id=$1 AND provider='google' AND state_digest=$2 AND consumed_at IS NULL AND expires_at>now()
AND (locked_until IS NULL OR locked_until<now()) RETURNING id,flow,requested_by_user_id,app_redirect_uri,nonce_digest,verifier_ciphertext`,
		chi.URLParam(r, "application_id"), s.app.Vault.Digest(state)).Scan(&challengeID, &flow, &requestedBy, &appRedirect, &nonceDigest, &verifierCiphertext)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_google_state", "The Google authentication state is invalid or expired.")
		return
	}
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_denied")
		return
	}
	provider, err := s.googleProvider(r)
	verifier, decryptErr := s.app.Vault.Decrypt(verifierCiphertext, "external-auth:"+challengeID)
	if err != nil || decryptErr != nil || r.URL.Query().Get("code") == "" {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_exchange_failed")
		return
	}
	config := s.googleOAuthConfig(chi.URLParam(r, "application_id"), provider)
	token, err := config.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(string(verifier)))
	rawIDToken := ""
	if err == nil && token != nil {
		rawIDToken, _ = token.Extra("id_token").(string)
	}
	keySet := oidc.NewRemoteKeySet(r.Context(), "https://www.googleapis.com/oauth2/v3/certs")
	verifierInstance := oidc.NewVerifier("https://accounts.google.com", keySet, &oidc.Config{ClientID: provider.ClientID})
	idToken, verifyErr := verifierInstance.Verify(r.Context(), rawIDToken)
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		FirstName     string `json:"given_name"`
		LastName      string `json:"family_name"`
		Nonce         string `json:"nonce"`
	}
	if err == nil && verifyErr == nil {
		err = idToken.Claims(&claims)
	} else if err == nil {
		err = verifyErr
	}
	if err != nil || claims.Subject == "" || !claims.EmailVerified || !strings.Contains(claims.Email, "@") ||
		!equalBytes(nonceDigest, s.app.Vault.Digest(claims.Nonce)) {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_identity_invalid")
		return
	}
	userID, completeErr := s.completeGoogleIdentity(r, challengeID, flow, requestedBy, claims.Subject, claims.Email, claims.FirstName, claims.LastName)
	if completeErr != nil {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", completeErr.Error())
		return
	}
	exchangeCode, _ := secure.RandomToken("p93_external_", 32)
	exchangeID := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		defer rollback(tx, r.Context())
		_, err = tx.Exec(r.Context(), `INSERT INTO external_auth_exchanges
(id,application_id,user_id,credential_digest,expires_at) VALUES ($1,$2,$3,$4,$5)`, exchangeID,
			chi.URLParam(r, "application_id"), userID, s.app.Vault.Digest(exchangeCode), s.app.Now().Add(2*time.Minute))
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE external_auth_challenges SET consumed_at=now(),locked_until=NULL WHERE id=$1`, challengeID)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
	}
	if err != nil {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "exchange_creation_failed")
		return
	}
	s.redirectExternalAuth(w, r, appRedirect, exchangeID.String()+":"+exchangeCode, "")
}

func (s *Server) exchangeGoogleAuth(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Exchange string `json:"exchange"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	parts := strings.SplitN(request.Exchange, ":", 2)
	if len(parts) != 2 {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_external_exchange", "The external authentication exchange is invalid or expired.")
		return
	}
	var userID string
	err := s.app.DB.QueryRow(r.Context(), `UPDATE external_auth_exchanges SET consumed_at=now()
WHERE id=$1 AND application_id=$2 AND credential_digest=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING user_id`,
		parts[0], chi.URLParam(r, "application_id"), s.app.Vault.Digest(parts[1])).Scan(&userID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_external_exchange", "The external authentication exchange is invalid or expired.")
		return
	}
	s.completePrimaryAuthentication(w, r, userID, []string{"google"})
}

func (s *Server) completeGoogleIdentity(r *http.Request, challengeID, flow string, requestedBy *string, subject, email, firstName, lastName string) (string, error) {
	return s.completeExternalIdentity(r, "google", challengeID, flow, requestedBy, subject, email, firstName, lastName)
}

func (s *Server) completeExternalIdentity(r *http.Request, provider, challengeID, flow string, requestedBy *string, subject, email, firstName, lastName string) (string, error) {
	normalized := kernel.NormalizeEmail(email)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return "", fmt.Errorf("identity_link_failed")
	}
	defer rollback(tx, r.Context())
	var userID string
	identityErr := tx.QueryRow(r.Context(), `SELECT user_id FROM user_identities
WHERE application_id=$1 AND provider=$2 AND provider_subject=$3`, chi.URLParam(r, "application_id"), provider, subject).Scan(&userID)
	if identityErr == nil {
		if flow == "link" && (requestedBy == nil || *requestedBy != userID) {
			return "", fmt.Errorf("identity_already_linked")
		}
	} else if flow == "link" {
		if requestedBy == nil {
			return "", fmt.Errorf("authenticated_link_required")
		}
		var existingEmail string
		if tx.QueryRow(r.Context(), `SELECT normalized_email FROM users WHERE id=$1 AND application_id=$2 AND status='active'`,
			*requestedBy, chi.URLParam(r, "application_id")).Scan(&existingEmail) != nil || existingEmail != normalized {
			return "", fmt.Errorf("provider_email_mismatch")
		}
		userID = *requestedBy
		_, err = tx.Exec(r.Context(), `INSERT INTO user_identities(id,application_id,user_id,provider,provider_subject,metadata)
VALUES ($1,$2,$3,$4,$5,jsonb_build_object('email',$6))`, kernel.NewID(), chi.URLParam(r, "application_id"), userID, provider, subject, normalized)
	} else {
		var existingUserID string
		existingErr := tx.QueryRow(r.Context(), `SELECT id FROM users WHERE application_id=$1 AND normalized_email=$2`,
			chi.URLParam(r, "application_id"), normalized).Scan(&existingUserID)
		if existingErr == nil {
			return "", fmt.Errorf("account_link_required")
		}
		if flow == "sign_in" {
			return "", fmt.Errorf("provider_identity_not_found")
		}
		if !s.authFlag(r, "registration_enabled") {
			return "", fmt.Errorf("registration_disabled")
		}
		userID = kernel.NewID().String()
		_, err = tx.Exec(r.Context(), `INSERT INTO users
(id,application_id,email,normalized_email,first_name,last_name,email_verified_at) VALUES ($1,$2,$3,$4,$5,$6,now())`,
			userID, chi.URLParam(r, "application_id"), email, normalized, firstName, lastName)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO user_identities(id,application_id,user_id,provider,provider_subject,metadata)
VALUES ($1,$2,$3,$4,$5,jsonb_build_object('email',$6))`, kernel.NewID(), chi.URLParam(r, "application_id"), userID, provider, subject, normalized)
		}
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		return "", fmt.Errorf("identity_link_failed")
	}
	return userID, nil
}

func (s *Server) googleProvider(r *http.Request) (googleProviderConfig, error) {
	config, err := s.loadEffectiveAuthProvider(r.Context(), chi.URLParam(r, "application_id"), "google")
	if err != nil || config.ClientID == "" || config.Credentials["client_secret"] == "" {
		return googleProviderConfig{}, fmt.Errorf("google provider unavailable")
	}
	return googleProviderConfig{ID: config.ID, ClientID: config.ClientID, ClientSecret: config.Credentials["client_secret"]}, nil
}

func (s *Server) googleOAuthConfig(applicationID string, provider googleProviderConfig) oauth2.Config {
	return oauth2.Config{ClientID: provider.ClientID, ClientSecret: provider.ClientSecret, Endpoint: google.Endpoint,
		RedirectURL: s.googleCallbackURI(applicationID), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
}

func (s *Server) googleCallbackURI(applicationID string) string {
	return s.app.PublicURL + "/v1/applications/" + applicationID + "/auth/providers/google/callback"
}

func (s *Server) releaseExternalAuthChallenge(r *http.Request, challengeID string) {
	_, _ = s.app.DB.Exec(r.Context(), `UPDATE external_auth_challenges SET locked_until=NULL WHERE id=$1 AND consumed_at IS NULL`, challengeID)
}

func (s *Server) redirectExternalAuth(w http.ResponseWriter, r *http.Request, destination, exchange, errorCode string) {
	redirect, err := url.Parse(destination)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "external_auth_redirect_failed", "The external authentication redirect is invalid.")
		return
	}
	query := redirect.Query()
	if exchange != "" {
		query.Set("external_auth_exchange", exchange)
	}
	if errorCode != "" {
		query.Set("external_auth_error", errorCode)
	}
	redirect.RawQuery = query.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}
