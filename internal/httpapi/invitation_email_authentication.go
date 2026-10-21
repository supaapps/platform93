package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

type invitationCredential struct {
	InvitationID              string `json:"invitation_id,omitempty"`
	Email                     string `json:"email,omitempty"`
	Code                      string `json:"code,omitempty"`
	LinkToken                 string `json:"link_token,omitempty"`
	CodeChallenge             string `json:"code_challenge"`
	AuthenticationChallengeID string `json:"authentication_challenge_id,omitempty"`
	AuthenticationCode        string `json:"authentication_code,omitempty"`
	AuthenticationLinkToken   string `json:"authentication_link_token,omitempty"`
}

func (s *Server) invitationEmailAvailable(w http.ResponseWriter, r *http.Request) bool {
	var available bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM notification_providers WHERE disabled_at IS NULL AND (application_id=$1 OR (application_id IS NULL AND organization_id=(SELECT organization_id FROM applications WHERE id=$1) AND inheritable) OR (application_id IS NULL AND organization_id IS NULL AND inheritable)))`, chi.URLParam(r, "application_id")).Scan(&available)
	if err != nil || !available {
		kernel.WriteProblem(w, r, 503, "invitation_email_unavailable", "No active email delivery provider is available. Use a copy-only invitation or configure email delivery.")
		return false
	}
	return true
}

func (s *Server) startInvitationEmailAuthentication(w http.ResponseWriter, r *http.Request) {
	if !s.authFlag(r, "passwordless_enabled") {
		kernel.WriteProblem(w, r, 403, "passwordless_disabled", "Email invitation authentication is disabled for this application.")
		return
	}
	var in invitationCredential
	if !kernel.DecodeJSON(w, r, &in) {
		return
	}
	if !invitationPKCEChallengePattern.MatchString(in.CodeChallenge) {
		kernel.WriteProblem(w, r, 422, "pkce_required", "An S256 challenge is required.")
		return
	}
	in.Email = kernel.NormalizeEmail(in.Email)
	in.Code = strings.ToUpper(strings.TrimSpace(in.Code))
	linkPath := in.InvitationID != "" && in.LinkToken != "" && in.Email == "" && in.Code == ""
	codePath := in.InvitationID == "" && in.LinkToken == "" && in.Email != "" && invitationCodePattern.MatchString(in.Code)
	if !linkPath && !codePath {
		kernel.WriteProblem(w, r, 422, "invalid_invitation_credential", "Provide exactly one invitation credential.")
		return
	}
	app := chi.URLParam(r, "application_id")
	if !s.invitationEmailAvailable(w, r) {
		return
	}
	if !s.allowAuthAttempt(w, r, "invitation_email_authentication", in.InvitationID+in.Email, 5, 10*time.Minute) {
		return
	}
	var id, email string
	var version int64
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,normalized_email,version FROM application_invitations WHERE application_id=$1 AND onboarding_method='email' AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() AND ((id=$2 AND link_credential_digest=$3) OR (normalized_email=$4 AND code_credential_digest=$5))`, app, nullableActorID(in.InvitationID), s.app.Vault.Digest(in.LinkToken), in.Email, s.app.Vault.Digest(in.Code)).Scan(&id, &email, &version)
	if err != nil {
		kernel.WriteProblem(w, r, 401, "invalid_invitation", "The invitation is unavailable.")
		return
	}
	flows, err := s.loadApplicationFlowConfig(r.Context(), app)
	if callback, ok := r.Context().Value(hostedContextKey{}).(string); ok && callback != "" {
		flows.InvitationRedirectURI = callback
		err = nil
	}
	if err != nil || flows.InvitationRedirectURI == "" {
		kernel.WriteProblem(w, r, 422, "invitation_redirect_unconfigured", "The invitation redirect is not configured.")
		return
	}
	challenge := kernel.NewID().String()
	code := randomCode(8)
	link, err := secure.RandomToken("p93_invitation_auth_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, 503, "authentication_unavailable", "Authentication is unavailable.")
		return
	}
	magic := appendCredentialQuery(flows.InvitationRedirectURI, map[string]string{"invitation_id": id, "challenge_id": challenge, "link_token": link, "platform93_flow": "invitation_authentication"})
	template, locale, payload, err := s.renderSystemNotification(r.Context(), &app, applicationSignInTemplate, email, map[string]any{"code": code, "magic_link": magic, "expires_minutes": 10, "intent": "sign_in"})
	if err != nil {
		kernel.WriteProblem(w, r, 503, "authentication_email_unavailable", "The authentication email could not be queued.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 503, "authentication_unavailable", "Authentication is unavailable.")
		return
	}
	defer rollback(tx, r.Context())
	var lockedVersion int64
	if err = tx.QueryRow(r.Context(), `SELECT version FROM application_invitations WHERE application_id=$1 AND id=$2 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, app, id).Scan(&lockedVersion); err != nil || lockedVersion != version || s.revalidateInvitationAuthority(r, tx, id) != nil {
		kernel.WriteProblem(w, r, 401, "invalid_invitation", "The invitation changed or is unavailable.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO invitation_email_challenges(id,application_id,invitation_id,invitation_version,code_challenge,code_digest,link_digest,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, challenge, app, id, version, in.CodeChallenge, s.app.Vault.Digest(code), s.app.Vault.Digest(link), s.app.Now().Add(10*time.Minute))
	if err == nil {
		var encrypted string
		encrypted, err = s.app.Vault.Encrypt(payload, "notification:"+challenge)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO notifications(id,application_id,template_id,recipient,locale,payload_ciphertext,status) VALUES($1,$2,$3,$4,$5,$6,'queued')`, challenge, app, template, email, locale, encrypted)
		}
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 503, "authentication_email_unavailable", "The authentication email could not be queued.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	kernel.WriteJSON(w, 202, map[string]any{"challenge_id": challenge, "invitation_id": id, "expires_in": 600})
}

func (s *Server) verifyInvitationRecipient(w http.ResponseWriter, r *http.Request, tx pgx.Tx, id, email string, version int64, in invitationCredential, requireMailbox bool) bool {
	if !requireMailbox && r.Header.Get("Authorization") != "" {
		var verified bool
		a := actor(r)
		if a.Type == "user" && a.DelegatedBy == "" {
			_ = tx.QueryRow(r.Context(), `SELECT normalized_email=$3 AND email_verified_at IS NOT NULL AND status='active' FROM users WHERE application_id=$1 AND id=$2`, chi.URLParam(r, "application_id"), a.ID, email).Scan(&verified)
		}
		if verified {
			return true
		}
		if !verified {
			kernel.WriteProblem(w, r, 401, "invitation_identity_mismatch", "Sign in as the verified invited email to accept.")
			return false
		}
	}
	if in.AuthenticationChallengeID == "" {
		kernel.WriteProblem(w, r, 401, "invitation_authentication_required", "Authenticate the invited email independently before accepting this invitation.")
		return false
	}
	if (in.AuthenticationCode == "") == (in.AuthenticationLinkToken == "") {
		kernel.WriteProblem(w, r, 422, "authentication_proof_required", "Provide one independent authentication code or link token.")
		return false
	}
	var code, link []byte
	var attempts int
	err := tx.QueryRow(r.Context(), `SELECT code_digest,link_digest,attempts FROM invitation_email_challenges WHERE id=$1 AND application_id=$2 AND invitation_id=$3 AND invitation_version=$4 AND code_challenge=$5 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, in.AuthenticationChallengeID, chi.URLParam(r, "application_id"), id, version, in.CodeChallenge).Scan(&code, &link, &attempts)
	valid := err == nil && attempts < 8 && ((in.AuthenticationCode != "" && equalBytes(code, s.app.Vault.Digest(strings.ToUpper(in.AuthenticationCode)))) || (in.AuthenticationLinkToken != "" && equalBytes(link, s.app.Vault.Digest(in.AuthenticationLinkToken))))
	if !valid {
		if err == nil {
			// Before this point acceptance only reads/locks rows. Commit only the
			// failed-attempt counter; never add credential or grant writes here.
			_, _ = tx.Exec(r.Context(), `UPDATE invitation_email_challenges SET attempts=attempts+1 WHERE id=$1`, in.AuthenticationChallengeID)
			_ = tx.Commit(r.Context())
		}
		kernel.WriteProblem(w, r, 401, "invalid_invitation_authentication", "The independent authentication proof is invalid or expired.")
		return false
	}
	_, err = tx.Exec(r.Context(), `UPDATE invitation_email_challenges SET consumed_at=now() WHERE id=$1`, in.AuthenticationChallengeID)
	if err != nil {
		kernel.WriteProblem(w, r, 503, "authentication_unavailable", "Recipient authentication could not be completed.")
		return false
	}
	return true
}
