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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func (s *Server) startApplicationInvitationProvider(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if !validExternalAuthProvider(provider) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "invitation_provider_not_found", "The invitation provider is unavailable.")
		return
	}
	var request struct {
		InvitationID  string `json:"invitation_id,omitempty"`
		Email         string `json:"email,omitempty"`
		Code          string `json:"code,omitempty"`
		LinkToken     string `json:"link_token,omitempty"`
		CodeChallenge string `json:"code_challenge"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Email = kernel.NormalizeEmail(request.Email)
	request.Code = strings.ToUpper(strings.TrimSpace(request.Code))
	codePath := request.Email != "" && invitationCodePattern.MatchString(request.Code) && request.InvitationID == "" && request.LinkToken == ""
	linkPath := request.InvitationID != "" && request.LinkToken != "" && request.Email == "" && request.Code == ""
	if (!codePath && !linkPath) || !invitationPKCEChallengePattern.MatchString(request.CodeChallenge) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_provider_invitation_credential", "Provide one invitation credential and a valid S256 PKCE challenge.")
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	rateSubject := request.InvitationID
	if rateSubject == "" {
		rateSubject = request.Email
	}
	if !s.allowAuthAttempt(w, r, "invitation_provider_start", applicationID+"|"+provider+"|"+rateSubject, 10, 15*time.Minute) {
		return
	}
	query := `SELECT id FROM application_invitations WHERE application_id=$1 AND onboarding_method=$2
AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`
	args := []any{applicationID, provider}
	if linkPath {
		query += ` AND id=$3 AND link_credential_digest=$4`
		args = append(args, request.InvitationID, s.app.Vault.Digest(request.LinkToken))
	} else {
		query += ` AND normalized_email=$3 AND code_credential_digest=$4`
		args = append(args, request.Email, s.app.Vault.Digest(request.Code))
	}
	var invitationID string
	if err := s.app.DB.QueryRow(r.Context(), query, args...).Scan(&invitationID); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_provider_invitation", "The invitation is invalid, expired, or already used.")
		return
	}
	config, err := s.loadEffectiveAuthProvider(r.Context(), applicationID, provider)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "invitation_provider_unavailable", "The invitation provider is no longer configured.")
		return
	}
	flows, err := s.loadApplicationFlowConfig(r.Context(), applicationID)
	if err != nil || flows.InvitationRedirectURI == "" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invitation_redirect_unconfigured", "The application invitation redirect is not configured.")
		return
	}
	state, _ := secure.RandomToken("p93_invitation_"+provider+"_state_", 32)
	nonce, _ := secure.RandomToken("", 32)
	verifier := oauth2.GenerateVerifier()
	challengeID := kernel.NewID()
	verifierValue := verifier
	if provider == "apple" || provider == "facebook" {
		verifierValue = provider
	}
	ciphertext, err := s.app.Vault.Encrypt([]byte(verifierValue), "external-auth:"+challengeID.String())
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO external_auth_challenges
(id,application_id,auth_provider_config_id,invitation_id,provider,flow,app_redirect_uri,state_digest,nonce_digest,verifier_ciphertext,code_challenge,expires_at)
VALUES($1,$2,$3,$4,$5,'invitation',$6,$7,$8,$9,$10,$11)`, challengeID, applicationID, config.ID, invitationID, provider,
			flows.InvitationRedirectURI, s.app.Vault.Digest(state), s.app.Vault.Digest(nonce), ciphertext, request.CodeChallenge, s.app.Now().Add(10*time.Minute))
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_provider_start_failed", "The provider invitation flow could not be started.")
		return
	}
	authorizeURL, err := s.applicationProviderAuthorizationURL(config, state, nonce, verifier)
	if err != nil {
		s.releaseExternalAuthChallenge(r, challengeID.String())
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_provider_start_failed", "The provider authorization request could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"provider": provider, "authorize_url": authorizeURL, "expires_in": 600})
}

func (s *Server) applicationProviderAuthorizationURL(config externalAuthProviderConfig, state, nonce, verifier string) (string, error) {
	if config.Provider == "google" {
		oauthConfig := oauth2.Config{ClientID: config.ClientID, ClientSecret: config.Credentials["client_secret"], Endpoint: google.Endpoint,
			RedirectURL: s.externalAuthCallbackURI("google"), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
		return oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("prompt", "select_account")), nil
	}
	if config.Provider == "apple" {
		query := url.Values{"client_id": {config.ClientID}, "redirect_uri": {s.externalAuthCallbackURI("apple")}, "response_type": {"code"},
			"response_mode": {"form_post"}, "scope": {"name email"}, "state": {state}, "nonce": {nonce}}
		return "https://appleid.apple.com/auth/authorize?" + query.Encode(), nil
	}
	return providerAuthorizationURL(config, s.externalAuthCallbackURI(config.Provider), state, nonce, verifier, "")
}

func (s *Server) completeApplicationInvitationExternalIdentity(r *http.Request, invitationID string, config externalAuthProviderConfig, external externalProviderIdentity) (string, error) {
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return "", err
	}
	defer rollback(tx, r.Context())
	applicationID := chi.URLParam(r, "application_id")
	var email string
	var workspaceID *string
	var appRoles, workspaceRoles []string
	err = tx.QueryRow(r.Context(), `SELECT normalized_email,workspace_id,application_roles,workspace_roles FROM application_invitations
WHERE id=$1 AND application_id=$2 AND onboarding_method=$3 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`,
		invitationID, applicationID, config.Provider).Scan(&email, &workspaceID, &appRoles, &workspaceRoles)
	if err != nil || external.TrustedEmail && kernel.NormalizeEmail(external.Email) != email {
		return "", fmt.Errorf("invitation_identity_mismatch")
	}
	var identityUserID, userID, status string
	identityErr := tx.QueryRow(r.Context(), `SELECT user_id FROM user_identities WHERE application_id=$1 AND provider=$2 AND provider_subject=$3 FOR UPDATE`,
		applicationID, config.Provider, external.Subject).Scan(&identityUserID)
	userErr := tx.QueryRow(r.Context(), `SELECT id,status FROM users WHERE application_id=$1 AND normalized_email=$2 FOR UPDATE`, applicationID, email).Scan(&userID, &status)
	if identityErr != nil && identityErr != pgx.ErrNoRows || userErr != nil && userErr != pgx.ErrNoRows {
		return "", fmt.Errorf("invitation_identity_lookup_failed")
	}
	if identityErr == nil && userErr == nil && identityUserID != userID || identityErr == nil && userErr == pgx.ErrNoRows {
		return "", fmt.Errorf("invitation_identity_conflict")
	}
	if userErr == pgx.ErrNoRows {
		if err = enforceUserLimit(r.Context(), tx, applicationID); err != nil {
			return "", err
		}
		userID, status = kernel.NewID().String(), "active"
		_, err = tx.Exec(r.Context(), `INSERT INTO users(id,application_id,email,normalized_email,first_name,last_name,email_verified_at)
VALUES($1,$2,$3,$3,$4,$5,now())`, userID, applicationID, email, external.FirstName, external.LastName)
	} else if userErr != nil || status != "active" {
		return "", fmt.Errorf("invited_account_unavailable")
	}
	metadata, _ := json.Marshal(map[string]any{"email": external.Email, "first_name": external.FirstName, "last_name": external.LastName})
	if err == nil && identityErr == pgx.ErrNoRows {
		_, err = tx.Exec(r.Context(), `INSERT INTO user_identities(id,application_id,user_id,provider,provider_subject,metadata,last_used_at)
VALUES($1,$2,$3,$4,$5,$6,now())`, kernel.NewID(), applicationID, userID, config.Provider, external.Subject, metadata)
	} else if err == nil && identityErr == nil {
		_, err = tx.Exec(r.Context(), `UPDATE user_identities SET last_used_at=now(),metadata=$1 WHERE application_id=$2 AND provider=$3 AND provider_subject=$4`,
			metadata, applicationID, config.Provider, external.Subject)
	}
	roleWorkspaceID := workspaceID
	if err == nil && workspaceID != nil {
		var owner bool
		_ = tx.QueryRow(r.Context(), `SELECT owner_user_id=$3 FROM workspaces WHERE id=$1 AND application_id=$2`, *workspaceID, applicationID, userID).Scan(&owner)
		if owner {
			roleWorkspaceID = nil
		} else {
			_, err = tx.Exec(r.Context(), `INSERT INTO workspace_memberships(application_id,workspace_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, applicationID, *workspaceID, userID)
		}
	}
	if err == nil {
		err = assignInvitationRoles(r.Context(), tx, applicationID, userID, roleWorkspaceID, appRoles, workspaceRoles)
	}
	if err == nil {
		result, updateErr := tx.Exec(r.Context(), `UPDATE application_invitations SET accepted_at=now(),updated_at=now() WHERE id=$1 AND accepted_at IS NULL`, invitationID)
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = pgx.ErrNoRows
		}
	}
	parsed, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(r.Context(), tx, &parsed, "application_invitation.accepted", "application_invitation/"+invitationID,
			map[string]any{"type": "user", "id": userID}, map[string]any{"invitation_id": invitationID, "user_id": userID, "workspace_id": workspaceID,
				"onboarding_method": config.Provider, "status": "accepted"})
	}
	if err != nil || parseErr != nil {
		return "", err
	}
	return userID, tx.Commit(r.Context())
}
