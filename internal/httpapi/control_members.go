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

func (s *Server) listOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if !s.controlUserBelongsToOrganization(r, organizationID) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT o.id,o.email,o.display_name,o.status,m.role,m.created_at
FROM organization_memberships m JOIN control_users o ON o.id=m.control_user_id
WHERE m.organization_id=$1 ORDER BY m.created_at,o.id`, organizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Organization members could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, email, displayName, status, role string
		var createdAt time.Time
		if rows.Scan(&id, &email, &displayName, &status, &role, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "control_user_id": id, "email": email, "display_name": displayName, "status": status, "role": role, "created_at": createdAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) updateOrganizationMember(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Role string `json:"role"`
	}
	if !kernel.DecodeJSON(w, r, &request) || !validOrganizationRole(request.Role) {
		return
	}
	organizationID, memberID := chi.URLParam(r, "organization_id"), chi.URLParam(r, "member_id")
	callerRole, allowed := s.organizationManagementRole(r, organizationID)
	if !allowed || callerRole != "owner" && (request.Role == "owner" || request.Role == "admin") {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "The Platform user cannot assign this organization role.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The organization member could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	var currentRole string
	err = tx.QueryRow(r.Context(), `SELECT role FROM organization_memberships WHERE organization_id=$1 AND control_user_id=$2 FOR UPDATE`, organizationID, memberID).Scan(&currentRole)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_member_not_found", "The organization member was not found.")
		return
	}
	if currentRole == "owner" && request.Role != "owner" && !organizationHasAnotherOwner(r, tx, organizationID, memberID) {
		kernel.WriteProblem(w, r, http.StatusConflict, "last_organization_owner", "The final organization owner cannot be demoted.")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE organization_memberships SET role=$1 WHERE organization_id=$2 AND control_user_id=$3`, request.Role, organizationID, memberID)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "organization_member_update_failed", "The organization member could not be updated.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteOrganizationMember(w http.ResponseWriter, r *http.Request) {
	organizationID, memberID := chi.URLParam(r, "organization_id"), chi.URLParam(r, "member_id")
	callerRole, allowed := s.organizationManagementRole(r, organizationID)
	if !allowed {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "The Platform user cannot remove organization members.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The organization member could not be removed.")
		return
	}
	defer rollback(tx, r.Context())
	var memberRole string
	err = tx.QueryRow(r.Context(), `SELECT role FROM organization_memberships WHERE organization_id=$1 AND control_user_id=$2 FOR UPDATE`, organizationID, memberID).Scan(&memberRole)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_member_not_found", "The organization member was not found.")
		return
	}
	if callerRole != "owner" && (memberRole == "owner" || memberRole == "admin") {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "Only an owner can remove owners or administrators.")
		return
	}
	if memberRole == "owner" && !organizationHasAnotherOwner(r, tx, organizationID, memberID) {
		kernel.WriteProblem(w, r, http.StatusConflict, "last_organization_owner", "The final organization owner cannot be removed.")
		return
	}
	_, err = tx.Exec(r.Context(), `DELETE FROM organization_memberships WHERE organization_id=$1 AND control_user_id=$2`, organizationID, memberID)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "organization_member_removal_failed", "The organization member could not be removed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
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
	if request.ExpiresIn == 0 {
		request.ExpiresIn = int64((7 * 24 * time.Hour).Seconds())
	}
	if request.OnboardingMethod == "" {
		request.OnboardingMethod = "email"
	}
	organizationID := chi.URLParam(r, "organization_id")
	callerRole, allowed := s.organizationManagementRole(r, organizationID)
	if !allowed || callerRole != "owner" && (request.Role == "owner" || request.Role == "admin") {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "The Platform user cannot invite this organization role.")
		return
	}
	if !strings.Contains(request.Email, "@") || !validOrganizationRole(request.Role) || !validControlOnboardingMethod(request.OnboardingMethod) || request.ExpiresIn < 300 || request.ExpiresIn > int64((30*24*time.Hour).Seconds()) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_organization_invitation", "Email, role, or expiry is invalid.")
		return
	}
	if request.OnboardingMethod != "email" {
		if _, err := s.loadControlAuthProvider(r, request.OnboardingMethod); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "control_auth_provider_unavailable", "The selected onboarding provider is not enabled for Platform login.")
			return
		}
	}
	token, err := secure.RandomToken("p93_org_invite_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_creation_failed", "The invitation credential could not be created.")
		return
	}
	id := kernel.NewID()
	expiresAt := s.app.Now().Add(time.Duration(request.ExpiresIn) * time.Second)
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO control_user_invitations
(id,organization_id,normalized_email,role,onboarding_method,credential_digest,invited_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			id, organizationID, request.Email, request.Role, request.OnboardingMethod, s.app.Vault.Digest(token), actor(r).ID, expiresAt)
	}
	if err == nil {
		err = s.queueOrganizationInvitation(r, tx, organizationID, id.String(), request.Email, request.Role, request.OnboardingMethod, token, expiresAt)
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.invitation_created", "control_user_invitation/"+id.String(),
			controlInvitationEventData(id.String(), &organizationID, "", request.Role, request.OnboardingMethod, "pending"))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "organization_invitation_conflict", "A pending invitation already exists or could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "email": request.Email, "role": request.Role, "onboarding_method": request.OnboardingMethod, "expires_at": expiresAt, "invitation_token": token, "token_returned_once": true})
}

func (s *Server) listOrganizationInvitations(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if !s.controlUserBelongsToOrganization(r, organizationID) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,normalized_email,role,onboarding_method,invited_by,accepted_by,expires_at,accepted_at,revoked_at,created_at,updated_at
FROM control_user_invitations WHERE organization_id=$1 ORDER BY created_at DESC,id DESC`, organizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Organization invitations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, email, role, onboardingMethod, invitedBy string
		var acceptedBy *string
		var expiresAt, createdAt, updatedAt time.Time
		var acceptedAt, revokedAt *time.Time
		if rows.Scan(&id, &email, &role, &onboardingMethod, &invitedBy, &acceptedBy, &expiresAt, &acceptedAt, &revokedAt, &createdAt, &updatedAt) == nil {
			status := "pending"
			if acceptedAt != nil {
				status = "accepted"
			} else if revokedAt != nil {
				status = "revoked"
			} else if expiresAt.Before(s.app.Now()) {
				status = "expired"
			}
			items = append(items, map[string]any{"id": id, "email": email, "role": role, "onboarding_method": onboardingMethod, "invited_by": invitedBy, "accepted_by": acceptedBy,
				"expires_at": expiresAt, "accepted_at": acceptedAt, "revoked_at": revokedAt, "created_at": createdAt, "updated_at": updatedAt, "status": status})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) resendOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	organizationID, invitationID := chi.URLParam(r, "organization_id"), chi.URLParam(r, "invitation_id")
	if _, allowed := s.organizationManagementRole(r, organizationID); !allowed {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "The Platform user cannot resend organization invitations.")
		return
	}
	token, tokenErr := secure.RandomToken("p93_org_invite_", 32)
	if tokenErr != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_creation_failed", "The invitation credential could not be rotated.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	var request struct {
		OnboardingMethod string `json:"onboarding_method,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 && !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.OnboardingMethod != "" && !validControlOnboardingMethod(request.OnboardingMethod) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_onboarding_method", "Onboarding method must be email, google, or apple.")
		return
	}
	if request.OnboardingMethod != "" && request.OnboardingMethod != "email" {
		if _, err := s.loadControlAuthProvider(r, request.OnboardingMethod); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "control_auth_provider_unavailable", "The selected onboarding provider is not enabled for Platform login.")
			return
		}
	}
	var email, role, onboardingMethod string
	var expiresAt time.Time
	if err == nil {
		err = tx.QueryRow(r.Context(), `UPDATE control_user_invitations SET credential_digest=$1,
onboarding_method=COALESCE(NULLIF($2,''),onboarding_method),expires_at=now()+interval '7 days',updated_at=now()
WHERE id=$3 AND organization_id=$4 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING normalized_email,role,onboarding_method,expires_at`,
			s.app.Vault.Digest(token), request.OnboardingMethod, invitationID, organizationID).Scan(&email, &role, &onboardingMethod, &expiresAt)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_external_auth_challenges SET consumed_at=COALESCE(consumed_at,now()),locked_until=NULL
WHERE invitation_id=$1 AND consumed_at IS NULL`, invitationID)
	}
	if err == nil {
		err = s.queueOrganizationInvitation(r, tx, organizationID, invitationID, email, role, onboardingMethod, token, expiresAt)
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.invitation_resent", "control_user_invitation/"+invitationID,
			controlInvitationEventData(invitationID, &organizationID, "", role, onboardingMethod, "pending"))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_invitation_not_found", "A pending organization invitation was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": invitationID, "onboarding_method": onboardingMethod, "expires_at": expiresAt, "invitation_token": token, "token_returned_once": true})
}

func (s *Server) revokeOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if _, allowed := s.organizationManagementRole(r, organizationID); !allowed {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "The Platform user cannot revoke organization invitations.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The organization invitation could not be revoked.")
		return
	}
	defer rollback(tx, r.Context())
	var invitedRole, onboardingMethod string
	if err = tx.QueryRow(r.Context(), `SELECT role,onboarding_method FROM control_user_invitations
WHERE id=$1 AND organization_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL FOR UPDATE`, chi.URLParam(r, "invitation_id"), organizationID).Scan(&invitedRole, &onboardingMethod); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_invitation_not_found", "A pending organization invitation was not found.")
		return
	}
	result, err := tx.Exec(r.Context(), `UPDATE control_user_invitations SET revoked_at=now(),updated_at=now()
WHERE id=$1 AND organization_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, chi.URLParam(r, "invitation_id"), organizationID)
	if err == nil && result.RowsAffected() == 1 {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_external_auth_challenges SET consumed_at=COALESCE(consumed_at,now()),locked_until=NULL
WHERE invitation_id=$1 AND consumed_at IS NULL`, chi.URLParam(r, "invitation_id"))
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.invitation_revoked", "control_user_invitation/"+chi.URLParam(r, "invitation_id"),
			controlInvitationEventData(chi.URLParam(r, "invitation_id"), &organizationID, "", invitedRole, onboardingMethod, "revoked"))
	}
	if err != nil || result.RowsAffected() != 1 || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_invitation_not_found", "A pending organization invitation was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) acceptOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		InvitationToken string `json:"invitation_token"`
		DisplayName     string `json:"display_name,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) || request.InvitationToken == "" {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The organization invitation could not be accepted.")
		return
	}
	defer rollback(tx, r.Context())
	var invitationID, email, role string
	var organizationID *string
	err = tx.QueryRow(r.Context(), `SELECT id,organization_id,normalized_email,role FROM control_user_invitations
WHERE credential_digest=$1 AND onboarding_method='email' AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, s.app.Vault.Digest(request.InvitationToken)).
		Scan(&invitationID, &organizationID, &email, &role)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_organization_invitation", "The organization invitation is invalid or expired.")
		return
	}
	var controlUserID, status string
	err = tx.QueryRow(r.Context(), `INSERT INTO control_users(id,email,normalized_email,display_name)
VALUES($1,$2,$2,$3) ON CONFLICT(normalized_email) DO UPDATE SET display_name=CASE WHEN EXCLUDED.display_name='' THEN control_users.display_name ELSE EXCLUDED.display_name END
RETURNING id,status`, kernel.NewID(), email, truncate(request.DisplayName, 200)).Scan(&controlUserID, &status)
	if err != nil || status != "active" {
		kernel.WriteProblem(w, r, http.StatusConflict, "control_user_account_unavailable", "The invited Platform user account is unavailable.")
		return
	}
	if organizationID == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,$2)
ON CONFLICT(control_user_id) DO UPDATE SET role=EXCLUDED.role,updated_at=now()`, controlUserID, role)
	} else {
		_, err = tx.Exec(r.Context(), `INSERT INTO organization_memberships(organization_id,control_user_id,role) VALUES($1,$2,$3)
ON CONFLICT(organization_id,control_user_id) DO UPDATE SET role=EXCLUDED.role`, *organizationID, controlUserID, role)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_invitations SET accepted_by=$1,accepted_at=now(),updated_at=now() WHERE id=$2`, controlUserID, invitationID)
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_user.invitation_accepted", "control_user_invitation/"+invitationID,
			controlInvitationEventData(invitationID, organizationID, controlUserID, role, "email", "accepted"))
	}
	if err == nil {
		err = insertControlAuthAudit(r.Context(), tx, r, controlUserID, "control_user.invitation_accepted", "control_user_invitation", invitationID,
			map[string]any{"provider": "email", "organization_id": organizationID, "role": role})
	}
	refresh, tokenErr := secure.RandomToken("p93_control_refresh_", 32)
	sessionID := kernel.NewID()
	if err == nil && tokenErr == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO control_user_sessions
	(id,control_user_id,refresh_digest,kind,ip_address,user_agent,amr,expires_at) VALUES($1,$2,$3,'control',$4,$5,$6,$7)`, sessionID, controlUserID,
			s.app.Vault.Digest(refresh), requestIPAddress(r), truncate(r.UserAgent(), 500), []string{"invitation"}, s.app.Now().Add(12*time.Hour))
	}
	// The membership and session are still uncommitted, so issue against this transaction.
	access, accessErr := s.issueControlUserAccessWithQuerier(r.Context(), tx, controlUserID, sessionID.String(), "control")
	if err != nil || tokenErr != nil || accessErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "organization_invitation_acceptance_failed", "The organization invitation could not be accepted.")
		return
	}
	s.setControlUserCookies(w, access, refresh, 12*time.Hour)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"organization_id": organizationID, "control_user_id": controlUserID, "role": role, "access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 300})
}

func (s *Server) queueOrganizationInvitation(r *http.Request, tx pgx.Tx, organizationID, invitationID, recipient, role, onboardingMethod, token string, expiresAt time.Time) error {
	notificationID := kernel.NewID()
	var organizationName string
	if err := tx.QueryRow(r.Context(), `SELECT name FROM organizations WHERE id=$1 AND deleted_at IS NULL`, organizationID).Scan(&organizationName); err != nil {
		return err
	}
	invitationLink := appendCredentialQuery(strings.TrimRight(s.app.PublicURL, "/")+"/?control_invitation=true", map[string]string{
		"invitation_id": invitationID, "invitation_token": token, "onboarding_method": onboardingMethod,
	})
	templateID, templateLocale, payload, err := s.renderSystemNotification(r.Context(), nil, organizationInviteTemplate, recipient, map[string]any{
		"organization_name": organizationName, "role": role, "invitation_link": invitationLink,
		"invitation_token": token, "expires_at": templateTimestamp(expiresAt),
	})
	if err != nil {
		return err
	}
	ciphertext, err := s.app.Vault.Encrypt(payload, "notification:"+notificationID.String())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO notifications(id,organization_id,template_id,recipient,category,locale,payload_ciphertext,status)
VALUES($1,$2,$3,$4,'security',$5,$6,'queued')`, notificationID, organizationID, templateID, recipient, templateLocale, ciphertext)
	}
	return err
}

func (s *Server) organizationManagementRole(r *http.Request, organizationID string) (string, bool) {
	if actor(r).Type == "management_client" && actorHasPermission(actor(r), managementOrganizationsScope) {
		return "owner", true
	}
	if role, ok := s.installationRole(r); ok && (role == "owner" || role == "admin") {
		return role, true
	}
	var role string
	err := s.app.DB.QueryRow(r.Context(), `SELECT role FROM organization_memberships WHERE organization_id=$1 AND control_user_id=$2`, organizationID, actor(r).ID).Scan(&role)
	return role, err == nil && (role == "owner" || role == "admin")
}

func (s *Server) controlUserBelongsToOrganization(r *http.Request, organizationID string) bool {
	if actor(r).Type == "management_client" && actorHasPermission(actor(r), managementOrganizationsScope) {
		return true
	}
	if _, ok := s.installationRole(r); ok {
		return true
	}
	var exists bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE organization_id=$1 AND control_user_id=$2)`, organizationID, actor(r).ID).Scan(&exists)
	return exists
}

func organizationHasAnotherOwner(r *http.Request, tx pgx.Tx, organizationID, memberID string) bool {
	var exists bool
	_ = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE organization_id=$1 AND control_user_id<>$2 AND role='owner')`, organizationID, memberID).Scan(&exists)
	return exists
}

func validOrganizationRole(value string) bool {
	return value == "owner" || value == "admin" || value == "member" || value == "auditor"
}

func validControlOnboardingMethod(value string) bool {
	return value == "email" || value == "google" || value == "apple"
}
