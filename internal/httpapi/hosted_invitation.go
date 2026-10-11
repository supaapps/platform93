package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
	"golang.org/x/oauth2"
)

func (s *Server) hostedInvitationClient(ctx context.Context, application, id, callback string) (string, string, error) {
	if _, err := uuid.Parse(id); err != nil {
		return "", "", errors.New("a hosted client and registered callback are required")
	}
	var client, start string
	var redirects []string
	err := s.app.DB.QueryRow(ctx, `SELECT client_id,initiate_login_uri,redirect_uris FROM clients WHERE id=$1 AND application_id=$2 AND disabled_at IS NULL AND authorization_ui='hosted'`, id, application).Scan(&client, &start, &redirects)
	if err != nil || start == "" || !stringSliceContains(redirects, callback) || validateHostedInitiationURI(start) != nil {
		return "", "", errors.New("configure a hosted client, its registered callback and application sign-in/start URL")
	}
	return client, start, nil
}

func (s *Server) startHostedInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "invitation_id")
	if _, err := uuid.Parse(id); err != nil || len(r.URL.Query().Get("link_token")) > 256 {
		kernel.WriteProblem(w, r, 400, "invalid_invitation", "The invitation is unavailable.")
		return
	}
	if !s.allowAuthAttempt(w, r, "hosted-invitation", id+":"+hex.EncodeToString(s.app.Vault.Digest(r.URL.Query().Get("link_token"))), 10, 5*time.Minute) {
		return
	}
	var app, clientDatabaseID, callback, onboarding string
	err := s.app.DB.QueryRow(r.Context(), `SELECT application_id,hosted_client_id,hosted_redirect_uri,onboarding_method FROM application_invitations WHERE id=$1 AND link_credential_digest=$2 AND hosted_client_id IS NOT NULL AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`, id, s.app.Vault.Digest(r.URL.Query().Get("link_token"))).Scan(&app, &clientDatabaseID, &callback, &onboarding)
	client, _, policyErr := s.hostedInvitationClient(r.Context(), app, clientDatabaseID, callback)
	if err != nil || policyErr != nil {
		kernel.WriteProblem(w, r, 401, "hosted_invitation_unavailable", "The invitation is invalid, expired or already accepted. Start sign-in from your application.")
		return
	}
	browser := s.hostedBrowser(w, r, true)
	i := hostedInteraction{ID: kernel.NewID().String(), ApplicationID: app, ClientID: client, Params: url.Values{"client_id": {client}, "redirect_uri": {callback}, "hosted_client_id": {clientDatabaseID}}, ExpiresAt: s.app.Now().Add(15 * time.Minute)}
	i.Private = hostedPrivateState{CSRF: oauth2.GenerateVerifier(), Verifier: oauth2.GenerateVerifier(), ForceLogin: true, InvitationID: id, InvitationToken: r.URL.Query().Get("link_token"), InvitationMethod: onboarding}
	raw, _ := json.Marshal(i.Private)
	cipher, err := s.app.Vault.Encrypt(raw, "hosted-interaction:"+i.ID)
	params, _ := json.Marshal(i.Params)
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO hosted_auth_interactions(id,application_id,client_id,browser_digest,csrf_digest,authorization_parameters,pkce_required,private_state_ciphertext,expires_at) VALUES($1,$2,$3,$4,$5,$6,true,$7,$8)`, i.ID, app, clientDatabaseID, s.app.Vault.Digest(browser), s.app.Vault.Digest(i.Private.CSRF), params, cipher, i.ExpiresAt)
	}
	if err != nil {
		kernel.WriteProblem(w, r, 500, "hosted_auth_unavailable", "The invitation could not be opened.")
		return
	}
	http.Redirect(w, r, strings.TrimRight(s.app.PublicURL, "/")+"/auth/?interaction="+i.ID, http.StatusSeeOther)
}
