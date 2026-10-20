package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) rotateInvitationCredentials(w http.ResponseWriter, r *http.Request) {
	s.rotateInvitation(w, r, false)
}
func (s *Server) rotateInvitation(w http.ResponseWriter, r *http.Request, resend bool) {
	var in struct {
		SendEmail *bool  `json:"send_email,omitempty"`
		Reason    string `json:"reason,omitempty"`
	}
	if r.ContentLength != 0 && !kernel.DecodeJSON(w, r, &in) {
		return
	}
	send := resend || in.SendEmail == nil || *in.SendEmail
	if !resend && !requireAdministrationKey(w, r) {
		return
	}
	if actor(r).Type != "control_user" && (!administrationReason(w, r, in.Reason) || !requireAdministrationKey(w, r)) {
		return
	}
	app, id := chi.URLParam(r, "application_id"), chi.URLParam(r, "invitation_id")
	var workspace, hostedClient, hostedRedirect *string
	var email, method string
	var appRoles, workspaceRoles []string
	var available time.Time
	var version int64
	var lastSent *time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT workspace_id,normalized_email,application_roles,workspace_roles,onboarding_method,resend_available_at,version,hosted_client_id,hosted_redirect_uri,last_sent_at FROM application_invitations WHERE application_id=$1 AND id=$2 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`, app, id).Scan(&workspace, &email, &appRoles, &workspaceRoles, &method, &available, &version, &hostedClient, &hostedRedirect, &lastSent)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "invitation_not_found", "The pending invitation was not found.")
		return
	}
	ws := ""
	if workspace != nil {
		ws = *workspace
	}
	if !s.canManageInvitations(w, r, ws) {
		return
	}
	if routeWorkspace := chi.URLParam(r, "workspace_id"); routeWorkspace != "" && routeWorkspace != ws {
		kernel.WriteProblem(w, r, 404, "invitation_not_found", "The invitation was not found.")
		return
	}
	if actor(r).Type == "user" {
		config, e := s.internalApplicationConfig(r)
		if e != nil || !config.UserInvitationsEnabled {
			kernel.WriteProblem(w, r, 403, "user_invitations_disabled", "Application users are not allowed to create or rotate invitations.")
			return
		}
	}
	if actor(r).Type != "control_user" && !administrationIfMatch(w, r, version) {
		return
	}
	if available.After(s.app.Now()) {
		w.Header().Set("Retry-After", fmtInt(int(available.Sub(s.app.Now()).Seconds())+1))
		kernel.WriteProblem(w, r, 429, "invitation_resend_cooldown", "Wait before rotating or resending this invitation.")
		return
	}
	if !s.allowAuthAttempt(w, r, "invitation_rotation", email+"|"+ws+"|"+actor(r).ID, 10, time.Minute) {
		return
	}
	code := randomCode(8)
	link, err := secure.RandomToken("p93_invite_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, 503, "invitation_unavailable", "Credentials could not be generated.")
		return
	}
	hc, hr := "", ""
	if hostedClient != nil {
		hc = *hostedClient
	}
	if hostedRedirect != nil {
		hr = *hostedRedirect
	}
	uri, template, workspaceName, err := s.invitationPresentation(r.Context(), app, id, link, ws, method, hc, hr)
	if err != nil {
		kernel.WriteProblem(w, r, 422, "invitation_redirect_unconfigured", "Configure the invitation destination.")
		return
	}
	expires := s.app.Now().Add(7 * 24 * time.Hour)
	sent := lastSent
	var templateID, locale, cipher, notification string
	if send {
		if !s.invitationEmailAvailable(w, r) {
			return
		}
		variables := map[string]any{"invitation_code": code, "invitation_link": uri, "role_keys": strings.Join(append(append([]string{}, appRoles...), workspaceRoles...), ", "), "expires_at": templateTimestamp(expires), "inviter_name": s.inviterDisplayName(r.Context(), app, actor(r))}
		if ws != "" {
			variables["workspace_id"] = ws
			variables["workspace_name"] = workspaceName
		}
		var payload []byte
		var e error
		templateID, locale, payload, e = s.renderSystemNotification(r.Context(), &app, template, email, variables)
		if e != nil {
			kernel.WriteProblem(w, r, 503, "invitation_template_unavailable", "The invitation email could not be queued.")
			return
		}
		notification = kernel.NewID().String()
		cipher, e = s.app.Vault.Encrypt(payload, "notification:"+notification)
		if e != nil {
			kernel.WriteProblem(w, r, 503, "invitation_delivery_failed", "The invitation email could not be queued.")
			return
		}
		now := s.app.Now()
		sent = &now
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 503, "invitation_unavailable", "The invitation could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	if !s.invitationMutationEnabled(r, tx) {
		kernel.WriteProblem(w, r, 403, "user_invitations_disabled", "Application user invitations are disabled.")
		return
	}
	var lockedVersion int64
	if err = tx.QueryRow(r.Context(), `SELECT version FROM application_invitations WHERE application_id=$1 AND id=$2 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, app, id).Scan(&lockedVersion); err != nil || lockedVersion != version {
		kernel.WriteProblem(w, r, 409, "invitation_rotation_conflict", "The invitation changed concurrently.")
		return
	}
	if actor(r).Type != "control_user" {
		live, e := s.applicationAdminScopes(r, tx, actor(r))
		if e != nil || s.validateInvitationRolesAuthority(r, tx, actor(r), live, ws, appRoles, workspaceRoles) != nil {
			kernel.WriteProblem(w, r, 403, "invitation_authority_required", "Current invitation and role permissions are required.")
			return
		}
	}
	if send {
		_, err = tx.Exec(r.Context(), `INSERT INTO notifications(id,application_id,template_id,recipient,locale,payload_ciphertext,status) VALUES($1,$2,$3,$4,$5,$6,'queued')`, notification, app, templateID, email, locale, cipher)
		if err != nil {
			kernel.WriteProblem(w, r, 503, "invitation_delivery_failed", "The invitation email could not be queued.")
			return
		}
	}
	_, err = tx.Exec(r.Context(), `UPDATE application_invitations SET link_credential_digest=$3,code_credential_digest=$4,expires_at=$5,last_sent_at=COALESCE($6,last_sent_at),resend_available_at=now()+interval '60 seconds',version=version+1,updated_at=now(),inviter_type=$7,inviter_id=$8 WHERE application_id=$1 AND id=$2`, app, id, s.app.Vault.Digest(link), s.app.Vault.Digest(code), expires, sent, actor(r).Type, actor(r).ID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM invitation_email_challenges WHERE invitation_id=$1`, id)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE external_auth_challenges SET consumed_at=now(),locked_until=NULL WHERE application_id=$1 AND invitation_id=$2 AND consumed_at IS NULL`, app, id)
	}
	if err == nil {
		err = s.auditApplicationAdministration(r, tx, "invitation.rotated", id, in.Reason)
	}
	if err == nil {
		parsed := uuid.MustParse(app)
		_, err = s.app.Emit(r.Context(), tx, &parsed, "application_invitation.resent", "application_invitation/"+id, actor(r), map[string]any{"invitation_id": id, "status": "pending", "expires_at": expires})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 409, "invitation_rotation_conflict", "The invitation could not be rotated.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", kernel.ETag(version+1))
	kernel.WriteJSON(w, 202, map[string]any{"id": id, "invitation_url": uri, "email_queued": send, "version": version + 1, "last_sent_at": sent, "resend_available_at": s.app.Now().Add(time.Minute), "expires_at": expires})
}
