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

func (s *Server) createInstallationControlUserInvitation(w http.ResponseWriter, r *http.Request) {
	role, allowed := s.installationRole(r)
	if !allowed || role != "owner" && role != "admin" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required.")
		return
	}
	var request struct {
		Email            string `json:"email"`
		Role             string `json:"role"`
		OnboardingMethod string `json:"onboarding_method,omitempty"`
		ExpiresIn        int64  `json:"expires_in,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Email = kernel.NormalizeEmail(request.Email)
	if request.OnboardingMethod == "" {
		request.OnboardingMethod = "email"
	}
	if request.ExpiresIn == 0 {
		request.ExpiresIn = int64((7 * 24 * time.Hour).Seconds())
	}
	if !strings.Contains(request.Email, "@") || !validInstallationRole(request.Role) || !validControlOnboardingMethod(request.OnboardingMethod) ||
		request.ExpiresIn < 300 || request.ExpiresIn > int64((30*24*time.Hour).Seconds()) || request.Role == "owner" && role != "owner" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_installation_invitation", "Email, role, onboarding method, or expiry is invalid.")
		return
	}
	if request.OnboardingMethod != "email" {
		if _, err := s.loadControlAuthProvider(r, request.OnboardingMethod); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "control_auth_provider_unavailable", "The selected onboarding provider is not enabled for Platform login.")
			return
		}
	}
	token, _ := secure.RandomToken("p93_control_invite_", 32)
	id, expiresAt := kernel.NewID(), s.app.Now().Add(time.Duration(request.ExpiresIn)*time.Second)
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO control_user_invitations
(id,normalized_email,role,onboarding_method,credential_digest,invited_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			id, request.Email, request.Role, request.OnboardingMethod, s.app.Vault.Digest(token), actor(r).ID, expiresAt)
	}
	if err == nil {
		err = s.queueControlUserInvitation(r, tx, nil, request.Email, request.Role, request.OnboardingMethod, id.String(), token, expiresAt)
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.invitation_created", "control_user_invitation/"+id.String(),
			controlInvitationEventData(id.String(), nil, "", request.Role, request.OnboardingMethod, "pending"))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "installation_invitation_conflict", "The Platform user invitation could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "email": request.Email, "role": request.Role, "onboarding_method": request.OnboardingMethod,
		"expires_at": expiresAt, "invitation_token": token, "token_returned_once": true})
}

func (s *Server) listInstallationControlUserInvitations(w http.ResponseWriter, r *http.Request) {
	if _, allowed := s.installationRole(r); !allowed {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_role_required", "An installation role is required.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,normalized_email,role,onboarding_method,invited_by,accepted_by,expires_at,accepted_at,revoked_at,created_at,updated_at
FROM control_user_invitations WHERE organization_id IS NULL ORDER BY created_at DESC,id DESC`)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform user invitations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, email, role, method, invitedBy string
		var acceptedBy *string
		var expiresAt, createdAt, updatedAt time.Time
		var acceptedAt, revokedAt *time.Time
		if rows.Scan(&id, &email, &role, &method, &invitedBy, &acceptedBy, &expiresAt, &acceptedAt, &revokedAt, &createdAt, &updatedAt) == nil {
			status := "pending"
			if acceptedAt != nil {
				status = "accepted"
			} else if revokedAt != nil {
				status = "revoked"
			} else if expiresAt.Before(s.app.Now()) {
				status = "expired"
			}
			items = append(items, map[string]any{"id": id, "email": email, "role": role, "onboarding_method": method, "invited_by": invitedBy,
				"accepted_by": acceptedBy, "expires_at": expiresAt, "accepted_at": acceptedAt, "revoked_at": revokedAt, "created_at": createdAt, "updated_at": updatedAt, "status": status})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) resendInstallationControlUserInvitation(w http.ResponseWriter, r *http.Request) {
	role, allowed := s.installationRole(r)
	if !allowed || role != "owner" && role != "admin" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required.")
		return
	}
	var request struct {
		OnboardingMethod string `json:"onboarding_method,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 && !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.OnboardingMethod != "" && !validControlOnboardingMethod(request.OnboardingMethod) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_onboarding_method", "Platform user onboarding must use email or a supported external authentication provider.")
		return
	}
	if request.OnboardingMethod != "" && request.OnboardingMethod != "email" {
		if _, err := s.loadControlAuthProvider(r, request.OnboardingMethod); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "control_auth_provider_unavailable", "The selected onboarding provider is not enabled for Platform login.")
			return
		}
	}
	token, _ := secure.RandomToken("p93_control_invite_", 32)
	tx, err := s.app.DB.Begin(r.Context())
	var email, invitedRole, method string
	var expiresAt time.Time
	if err == nil {
		err = tx.QueryRow(r.Context(), `UPDATE control_user_invitations SET credential_digest=$1,onboarding_method=COALESCE(NULLIF($2,''),onboarding_method),
expires_at=now()+interval '7 days',updated_at=now() WHERE id=$3 AND organization_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL
RETURNING normalized_email,role,onboarding_method,expires_at`, s.app.Vault.Digest(token), request.OnboardingMethod, chi.URLParam(r, "invitation_id")).Scan(&email, &invitedRole, &method, &expiresAt)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_external_auth_challenges SET consumed_at=COALESCE(consumed_at,now()),locked_until=NULL
WHERE invitation_id=$1 AND consumed_at IS NULL`, chi.URLParam(r, "invitation_id"))
	}
	if err == nil {
		err = s.queueControlUserInvitation(r, tx, nil, email, invitedRole, method, chi.URLParam(r, "invitation_id"), token, expiresAt)
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.invitation_resent", "control_user_invitation/"+chi.URLParam(r, "invitation_id"),
			controlInvitationEventData(chi.URLParam(r, "invitation_id"), nil, "", invitedRole, method, "pending"))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "installation_invitation_not_found", "A pending Platform user invitation was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": chi.URLParam(r, "invitation_id"), "onboarding_method": method, "expires_at": expiresAt, "invitation_token": token, "token_returned_once": true})
}

func (s *Server) revokeInstallationControlUserInvitation(w http.ResponseWriter, r *http.Request) {
	role, allowed := s.installationRole(r)
	if !allowed || role != "owner" && role != "admin" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The Platform user invitation could not be revoked.")
		return
	}
	defer rollback(tx, r.Context())
	var invitedRole, method string
	if err = tx.QueryRow(r.Context(), `SELECT role,onboarding_method FROM control_user_invitations
WHERE id=$1 AND organization_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL FOR UPDATE`, chi.URLParam(r, "invitation_id")).Scan(&invitedRole, &method); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "installation_invitation_not_found", "A pending Platform user invitation was not found.")
		return
	}
	result, err := tx.Exec(r.Context(), `UPDATE control_user_invitations SET revoked_at=now(),updated_at=now()
WHERE id=$1 AND organization_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL`, chi.URLParam(r, "invitation_id"))
	if err == nil && result.RowsAffected() == 1 {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_external_auth_challenges SET consumed_at=COALESCE(consumed_at,now()),locked_until=NULL
WHERE invitation_id=$1 AND consumed_at IS NULL`, chi.URLParam(r, "invitation_id"))
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.invitation_revoked", "control_user_invitation/"+chi.URLParam(r, "invitation_id"),
			controlInvitationEventData(chi.URLParam(r, "invitation_id"), nil, "", invitedRole, method, "revoked"))
	}
	if err != nil || result.RowsAffected() != 1 || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "installation_invitation_not_found", "A pending Platform user invitation was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) queueControlUserInvitation(r *http.Request, tx pgx.Tx, organizationID *string, recipient, role, method, invitationID, token string, expiresAt time.Time) error {
	var smtp bool
	_ = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM notification_providers WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL)`).Scan(&smtp)
	if !smtp {
		return nil
	}
	notificationID := kernel.NewID()
	link := appendCredentialQuery(strings.TrimRight(s.app.PublicURL, "/")+"/?control_invitation=true", map[string]string{
		"invitation_id": invitationID, "invitation_token": token, "onboarding_method": method,
	})
	templateID, locale, payload, err := s.renderSystemNotification(r.Context(), nil, controlUserInvitationTemplate, recipient, map[string]any{
		"role": role, "onboarding_method": method, "invitation_link": link, "invitation_token": token, "expires_at": templateTimestamp(expiresAt),
	})
	if err != nil {
		return err
	}
	ciphertext, err := s.app.Vault.Encrypt(payload, "notification:"+notificationID.String())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO notifications(id,organization_id,template_id,recipient,category,locale,payload_ciphertext,status)
VALUES($1,$2,$3,$4,'security',$5,$6,'queued')`, notificationID, organizationID, templateID, recipient, locale, ciphertext)
	}
	return err
}
