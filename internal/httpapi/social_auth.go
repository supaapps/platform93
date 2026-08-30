package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
	"golang.org/x/oauth2"
)

func (s *Server) startSocialAuth(w http.ResponseWriter, r *http.Request) {
	s.startSocialAuthFlow(w, r, chi.URLParam(r, "provider"), "", "")
}

func (s *Server) startSocialLink(w http.ResponseWriter, r *http.Request) {
	s.startSocialAuthFlow(w, r, chi.URLParam(r, "provider"), "link", actor(r).ID)
}

func (s *Server) startSocialAuthFlow(w http.ResponseWriter, r *http.Request, provider, forcedFlow, requestedBy string) {
	if provider != "microsoft" && provider != "facebook" && provider != "linkedin" {
		kernel.WriteProblem(w, r, http.StatusNotFound, "auth_provider_not_found", "The authentication provider is unavailable.")
		return
	}
	var request struct {
		Flow          string `json:"flow,omitempty"`
		RedirectURI   string `json:"redirect_uri"`
		LoginHint     string `json:"login_hint,omitempty"`
		CodeChallenge string `json:"code_challenge,omitempty"`
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
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_external_auth_flow", "External authentication flow must be sign_in, sign_up, automatic, or link.")
		return
	}
	if request.Flow == "link" && requestedBy == "" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "authenticated_link_required", "Linking an identity requires a directly authenticated user session.")
		return
	}
	if request.CodeChallenge != "" && !invitationPKCEChallengePattern.MatchString(request.CodeChallenge) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_pkce_challenge", "The PKCE code challenge is invalid.")
		return
	}
	if err := validateRedirectURI(request.RedirectURI, true); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "redirect_uri_not_allowed", "The redirect URI is invalid or unsafe.")
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	var redirectAllowed, publicClient bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients WHERE application_id=$1 AND disabled_at IS NULL AND $2=ANY(redirect_uris)),
EXISTS(SELECT 1 FROM clients WHERE application_id=$1 AND disabled_at IS NULL AND $2=ANY(redirect_uris) AND client_type='public')`, applicationID, request.RedirectURI).Scan(&redirectAllowed, &publicClient)
	if !redirectAllowed || publicClient && request.CodeChallenge == "" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "pkce_or_redirect_invalid", "The redirect URI must match an enabled client, and public clients require PKCE.")
		return
	}
	config, err := s.loadEffectiveAuthProvider(r.Context(), applicationID, provider)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "auth_provider_unavailable", "The authentication provider is not configured.")
		return
	}
	state, _ := secure.RandomToken("p93_"+provider+"_state_", 32)
	nonce, _ := secure.RandomToken("", 32)
	verifier := oauth2.GenerateVerifier()
	challengeID := kernel.NewID()
	verifierCiphertext, err := s.app.Vault.Encrypt([]byte(verifier), "external-auth:"+challengeID.String())
	var requestedByUserID any
	if requestedBy != "" {
		requestedByUserID = requestedBy
	}
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO external_auth_challenges
(id,application_id,auth_provider_config_id,provider,flow,requested_by_user_id,app_redirect_uri,state_digest,nonce_digest,verifier_ciphertext,code_challenge,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, challengeID, applicationID, config.ID, provider, request.Flow,
			requestedByUserID, request.RedirectURI, s.app.Vault.Digest(state), s.app.Vault.Digest(nonce), verifierCiphertext,
			nullableAuthValue(request.CodeChallenge), s.app.Now().Add(10*time.Minute))
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "external_auth_start_failed", "The external authentication flow could not be started.")
		return
	}
	authorizeURL, err := providerAuthorizationURL(config, s.externalAuthCallbackURI(provider), state, nonce, verifier, request.LoginHint)
	if err != nil {
		s.releaseExternalAuthChallenge(r, challengeID.String())
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "external_auth_start_failed", "The provider authorization request could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"provider": provider, "authorize_url": authorizeURL, "expires_in": 600})
}

func nullableAuthValue(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *Server) routeSocialCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider != "microsoft" && provider != "facebook" && provider != "linkedin" {
		kernel.WriteProblem(w, r, http.StatusNotFound, "auth_provider_not_found", "The authentication provider is unavailable.")
		return
	}
	s.routeExternalAuthCallback(w, r, provider, func(w http.ResponseWriter, r *http.Request) {
		s.socialCallback(w, r, provider)
	})
}

func (s *Server) socialCallback(w http.ResponseWriter, r *http.Request, provider string) {
	state := r.Form.Get("state")
	var challengeID, providerConfigID, flow, appRedirect, verifierCiphertext string
	var requestedBy *string
	var invitationID *string
	var nonceDigest []byte
	var codeChallenge *string
	err := s.app.DB.QueryRow(r.Context(), `UPDATE external_auth_challenges SET locked_until=now()+interval '2 minutes'
WHERE application_id=$1 AND provider=$2 AND state_digest=$3 AND consumed_at IS NULL AND expires_at>now()
AND (locked_until IS NULL OR locked_until<now())
RETURNING id,auth_provider_config_id,flow,requested_by_user_id,invitation_id,app_redirect_uri,nonce_digest,verifier_ciphertext,code_challenge`,
		chi.URLParam(r, "application_id"), provider, s.app.Vault.Digest(state)).Scan(&challengeID, &providerConfigID, &flow, &requestedBy, &invitationID, &appRedirect, &nonceDigest, &verifierCiphertext, &codeChallenge)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_external_auth_state", "The external authentication state is invalid or expired.")
		return
	}
	if r.Form.Get("error") != "" || r.URL.Query().Get("error") != "" {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_denied")
		return
	}
	config, configErr := s.loadEffectiveAuthProvider(r.Context(), chi.URLParam(r, "application_id"), provider)
	verifier, decryptErr := s.app.Vault.Decrypt(verifierCiphertext, "external-auth:"+challengeID)
	if configErr != nil || config.ID != providerConfigID || decryptErr != nil || r.Form.Get("code") == "" {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_exchange_failed")
		return
	}
	external, err := exchangeExternalProviderIdentity(r.Context(), config, s.externalAuthCallbackURI(provider), r.Form.Get("code"), string(verifier), nonceDigest, s.app.Vault.Digest)
	if err != nil || external.Subject == "" {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_identity_invalid")
		return
	}
	if flow == "invitation" && invitationID != nil {
		userID, completeErr := s.completeApplicationInvitationExternalIdentity(r, *invitationID, config, external)
		if completeErr != nil {
			s.releaseExternalAuthChallenge(r, challengeID)
			s.redirectExternalAuth(w, r, appRedirect, "", "invitation_identity_invalid")
			return
		}
		challenge := ""
		if codeChallenge != nil {
			challenge = *codeChallenge
		}
		s.completeExternalAuthCallback(w, r, challengeID, appRedirect, userID, challenge)
		return
	}
	email := ""
	if external.TrustedEmail {
		email = external.Email
	}
	userID, completeErr := s.completeExternalIdentity(r, provider, challengeID, flow, requestedBy, external.Subject, email, external.FirstName, external.LastName)
	if completeErr != nil && completeErr.Error() == "provider_email_verification_required" && flow != "sign_in" && codeChallenge != nil {
		s.createExternalEmailEnrollment(w, r, config, challengeID, appRedirect, *codeChallenge, external)
		return
	}
	if completeErr != nil {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", completeErr.Error())
		return
	}
	challenge := ""
	if codeChallenge != nil {
		challenge = *codeChallenge
	}
	s.completeExternalAuthCallback(w, r, challengeID, appRedirect, userID, challenge)
}

func (s *Server) createExternalEmailEnrollment(w http.ResponseWriter, r *http.Request, config externalAuthProviderConfig, challengeID, appRedirect, codeChallenge string, external externalProviderIdentity) {
	credential, _ := secure.RandomToken("p93_external_email_", 32)
	enrollmentID := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		defer rollback(tx, r.Context())
		_, err = tx.Exec(r.Context(), `INSERT INTO external_auth_email_enrollments
(id,application_id,auth_provider_config_id,provider,provider_subject,first_name,last_name,suggested_email,app_redirect_uri,credential_digest,code_challenge,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, enrollmentID, chi.URLParam(r, "application_id"), config.ID, config.Provider,
			external.Subject, external.FirstName, external.LastName, nullableAuthValue(kernel.NormalizeEmail(external.Email)), appRedirect,
			s.app.Vault.Digest(credential), codeChallenge, s.app.Now().Add(10*time.Minute))
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE external_auth_challenges SET consumed_at=now(),locked_until=NULL WHERE id=$1`, challengeID)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
	}
	if err != nil {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "email_enrollment_failed")
		return
	}
	query := url.Values{"external_auth_provider": {config.Provider}, "external_auth_email_enrollment": {enrollmentID.String() + ":" + credential}}
	http.Redirect(w, r, appRedirect+querySeparator(appRedirect)+query.Encode(), http.StatusFound)
}

func querySeparator(destination string) string {
	if strings.Contains(destination, "?") {
		return "&"
	}
	return "?"
}

func (s *Server) exchangeSocialAuth(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider != "microsoft" && provider != "facebook" && provider != "linkedin" {
		kernel.WriteProblem(w, r, http.StatusNotFound, "auth_provider_not_found", "The authentication provider is unavailable.")
		return
	}
	s.exchangeExternalAuth(w, r, provider)
}
