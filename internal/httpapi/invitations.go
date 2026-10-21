package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

const applicationInvitationTemplate = "platform93.application_invitation"

var invitationPKCEChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var invitationPKCEVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
var invitationCodePattern = regexp.MustCompile(`^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$`)
var errInvalidInvitationRedirect = errors.New("invitation redirect is not configured")

type invitationRequest struct {
	Email               string   `json:"email"`
	WorkspaceID         string   `json:"workspace_id,omitempty"`
	ApplicationRoleKeys []string `json:"application_role_keys,omitempty"`
	WorkspaceRoleKeys   []string `json:"workspace_role_keys,omitempty"`
	RoleKeys            []string `json:"role_keys,omitempty"`
	OnboardingMethod    string   `json:"onboarding_method,omitempty"`
	ExpiresIn           int64    `json:"expires_in,omitempty"`
	HostedClientID      string   `json:"hosted_client_id,omitempty"`
	HostedRedirectURI   string   `json:"hosted_redirect_uri,omitempty"`
	SendEmail           *bool    `json:"send_email,omitempty"`
	Reason              string   `json:"reason,omitempty"`
}

func (s *Server) createControlInvitation(w http.ResponseWriter, r *http.Request) {
	s.createInvitation(w, r, true)
}

func (s *Server) createApplicationInvitation(w http.ResponseWriter, r *http.Request) {
	if (actor(r).Type != "client" && actor(r).Type != "user") || !actorHasPermission(actor(r), applicationPermission(r, "invitations/manage")) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "invitation_management_required", "A machine client with invitation management permission is required.")
		return
	}
	s.createInvitation(w, r, true)
}

func (s *Server) createWorkspaceInvitation(w http.ResponseWriter, r *http.Request) {
	s.createInvitation(w, r, false)
}

func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request, applicationManaged bool) {
	if current := actor(r); current.DelegatedBy != "" || (current.Type != "user" && current.Type != "client" && current.Type != "control_user") {
		kernel.WriteProblem(w, r, 403, "direct_application_actor_required", "A direct application user, authorized machine client, or control administrator is required.")
		return
	}
	var request invitationRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	sendEmail := request.SendEmail == nil || *request.SendEmail
	applicationID := chi.URLParam(r, "application_id")
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if parseErr != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_application_id", "The application identifier must be a UUID.")
		return
	}
	if request.WorkspaceID == "" {
		request.WorkspaceID = chi.URLParam(r, "workspace_id")
	}
	if routeWorkspace := chi.URLParam(r, "workspace_id"); routeWorkspace != "" && routeWorkspace != request.WorkspaceID {
		kernel.WriteProblem(w, r, 422, "workspace_mismatch", "The invitation workspace must match the route.")
		return
	}
	if len(request.WorkspaceRoleKeys) == 0 {
		request.WorkspaceRoleKeys = request.RoleKeys
	}
	request.ApplicationRoleKeys = uniqueStrings(request.ApplicationRoleKeys)
	request.WorkspaceRoleKeys = uniqueStrings(request.WorkspaceRoleKeys)
	if request.OnboardingMethod == "" {
		request.OnboardingMethod = "email"
	}
	normalized := kernel.NormalizeEmail(request.Email)
	if request.OnboardingMethod != "email" && !validExternalAuthProvider(request.OnboardingMethod) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_invitation_onboarding_method", "Invitation onboarding must use email or a supported external authentication provider.")
		return
	}
	if !strings.Contains(normalized, "@") || len(request.ApplicationRoleKeys)+len(request.WorkspaceRoleKeys) > 20 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_invitation", "A valid email and at most twenty role keys are required.")
		return
	}
	if request.OnboardingMethod != "email" {
		if _, err := s.loadEffectiveAuthProvider(r.Context(), applicationID, request.OnboardingMethod); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invitation_provider_unavailable", "The selected invitation provider is not configured for this application.")
			return
		}
	}
	if request.ExpiresIn == 0 {
		request.ExpiresIn = int64((7 * 24 * time.Hour).Seconds())
	}
	if request.ExpiresIn < 300 || request.ExpiresIn > int64((30*24*time.Hour).Seconds()) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_invitation_expiry", "Invitation expiry must be between five minutes and thirty days.")
		return
	}
	current := actor(r)
	if !s.allowAuthAttempt(w, r, "invitation_create", normalized+"|"+request.WorkspaceID+"|"+current.Type+":"+current.ID, 10, time.Minute) {
		return
	}
	if current.Type == "user" {
		config, err := s.internalApplicationConfig(r)
		if err != nil || !config.UserInvitationsEnabled {
			kernel.WriteProblem(w, r, http.StatusForbidden, "user_invitations_disabled", "Application users are not allowed to invite users.")
			return
		}
		canManageWorkspaceInvitations := !applicationManaged && request.WorkspaceID != "" && (s.canAccessWorkspace(r, true) || s.canAccessWorkspace(r, false) && actorHasPermission(current, workspacePermission(r, "invitations/manage")))
		appManager := applicationManaged && actorHasPermission(current, applicationPermission(r, "invitations/manage"))
		if !appManager && (request.WorkspaceID == "" || len(request.ApplicationRoleKeys) > 0 || !canManageWorkspaceInvitations) {
			kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_invitation_required", "This user may only invite users into an authorized workspace.")
			return
		}
	}
	if current.Type == "client" && !applicationManaged && !actorHasPermission(current, workspacePermission(r, "invitations/manage")) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "invitation_management_required", "Workspace invitation management permission is required.")
		return
	}
	if request.WorkspaceID == "" && len(request.WorkspaceRoleKeys) > 0 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "workspace_required", "Workspace roles require a workspace.")
		return
	}
	if !s.validInvitationRoles(r.Context(), applicationID, request.WorkspaceID, request.ApplicationRoleKeys, request.WorkspaceRoleKeys) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_invitation_roles", "One or more invitation roles are invalid for this application or workspace.")
		return
	}
	code := randomCode(8)
	link, err := secure.RandomToken("p93_invite_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_creation_failed", "Invitation credentials could not be created.")
		return
	}
	id, notificationID := kernel.NewID(), kernel.NewID()
	expiresAt := s.app.Now().Add(time.Duration(request.ExpiresIn) * time.Second)
	linkURI, templateKey, workspaceName, presentationErr := s.invitationPresentation(r.Context(), applicationID, id.String(), link, request.WorkspaceID, request.OnboardingMethod, request.HostedClientID, request.HostedRedirectURI)
	if presentationErr != nil {
		if request.HostedClientID != "" || request.HostedRedirectURI != "" {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "hosted_invitation_unconfigured", "Hosted invitations require an enabled hosted client, a registered callback, and a configured application sign-in/start URL.")
			return
		}
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invitation_redirect_unconfigured", "Configure the application's invitation redirect before creating invitations.")
		return
	}
	roleKeys := append(append([]string{}, request.ApplicationRoleKeys...), request.WorkspaceRoleKeys...)
	variables := map[string]any{"invitation_code": code, "invitation_link": linkURI, "role_keys": strings.Join(roleKeys, ", "), "expires_at": templateTimestamp(expiresAt), "inviter_name": s.inviterDisplayName(r.Context(), applicationID, current)}
	if request.WorkspaceID != "" {
		variables["workspace_id"], variables["workspace_name"] = request.WorkspaceID, workspaceName
	}
	var templateID, locale string
	var payload []byte
	var renderErr error
	if sendEmail && !s.invitationEmailAvailable(w, r) {
		return
	}
	if sendEmail {
		templateID, locale, payload, renderErr = s.renderSystemNotification(r.Context(), &applicationID, templateKey, normalized, variables)
	}
	if renderErr != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_template_unavailable", "The invitation email template is unavailable or invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The invitation could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	if current.Type == "user" || current.Type == "client" {
		if !s.invitationMutationEnabled(r, tx) {
			kernel.WriteProblem(w, r, 403, "user_invitations_disabled", "Application user invitations are disabled.")
			return
		}
		if !requireAdministrationKey(w, r) || !administrationReason(w, r, request.Reason) {
			return
		}
		live, authorityErr := s.applicationAdminScopes(r, tx, current)
		if authorityErr != nil || s.validateInvitationRolesAuthority(r, tx, current, live, request.WorkspaceID, request.ApplicationRoleKeys, request.WorkspaceRoleKeys) != nil {
			kernel.WriteProblem(w, r, 403, "invitation_authority_required", "Current invitation and role permissions are required.")
			return
		}
	}
	var workspace any
	if request.WorkspaceID != "" {
		workspace = request.WorkspaceID
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO application_invitations
(id,application_id,workspace_id,normalized_email,link_credential_digest,code_credential_digest,application_roles,workspace_roles,onboarding_method,expires_at,inviter_type,inviter_id,last_sent_at,resend_available_at,hosted_client_id,hosted_redirect_uri)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $15 THEN now() END,now()+interval '60 seconds',$13,$14)`, id, applicationID, workspace, normalized,
		s.app.Vault.Digest(link), s.app.Vault.Digest(code), request.ApplicationRoleKeys, request.WorkspaceRoleKeys, request.OnboardingMethod, expiresAt, current.Type, nullableActorID(current.ID), nullableActorID(request.HostedClientID), nullableText(request.HostedRedirectURI), sendEmail)
	if err == nil && sendEmail {
		ciphertext, encryptErr := s.app.Vault.Encrypt(payload, "notification:"+notificationID.String())
		if encryptErr != nil {
			err = encryptErr
		} else {
			_, err = tx.Exec(r.Context(), `INSERT INTO notifications(id,application_id,template_id,recipient,locale,payload_ciphertext,status)
VALUES($1,$2,$3,$4,$5,$6,'queued')`, notificationID, applicationID, templateID, normalized, locale, ciphertext)
		}
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &parsedApplicationID, "application_invitation.created", "application_invitation/"+id.String(), current,
			map[string]any{"invitation_id": id, "workspace_id": workspace, "application_role_keys": request.ApplicationRoleKeys, "workspace_role_keys": request.WorkspaceRoleKeys, "onboarding_method": request.OnboardingMethod, "status": "pending"})
	}
	if err == nil {
		err = s.auditApplicationAdministration(r, tx, "invitation.created", id.String(), request.Reason)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		writeCreationProblem(w, r, err, "invitation_conflict", "A pending invitation already exists.", "invitation_creation_failed", "application_invitations_pending_email")
		return
	}
	var lastSent any
	if sendEmail {
		lastSent = s.app.Now()
	}
	w.Header().Set("Cache-Control", "no-store")
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"invitation_url": linkURI, "version": int64(1), "email_queued": sendEmail, "id": id, "application_id": applicationID, "email": normalized, "workspace_id": workspace, "application_role_keys": request.ApplicationRoleKeys,
		"workspace_role_keys": request.WorkspaceRoleKeys, "onboarding_method": request.OnboardingMethod, "status": "pending", "expires_at": expiresAt, "last_sent_at": lastSent, "resend_available_at": s.app.Now().Add(time.Minute),
		"hosted_client_id": nullableActorID(request.HostedClientID), "hosted_redirect_uri": nullableText(request.HostedRedirectURI)})
}

func nullableActorID(value string) any {
	if _, err := uuid.Parse(value); err == nil {
		return value
	}
	return nil
}

func (s *Server) inviterDisplayName(ctx context.Context, applicationID string, current kernel.Actor) string {
	var name string
	switch current.Type {
	case "control_user":
		_ = s.app.DB.QueryRow(ctx, `SELECT COALESCE(NULLIF(display_name,''),email) FROM control_users WHERE id=$1`, current.ID).Scan(&name)
	case "client":
		_ = s.app.DB.QueryRow(ctx, `SELECT name FROM clients WHERE id=$1 AND application_id=$2`, current.ID, applicationID).Scan(&name)
	case "user":
		_ = s.app.DB.QueryRow(ctx, `SELECT COALESCE(NULLIF(trim(first_name||' '||last_name),''),email) FROM users WHERE id=$1 AND application_id=$2`, current.ID, applicationID).Scan(&name)
	}
	return stringWithFallback(name, current.ID)
}

func applicationPermission(r *http.Request, suffix string) string {
	return "/applications/" + chi.URLParam(r, "application_id") + "/" + strings.Trim(suffix, "/")
}

func workspacePermission(r *http.Request, suffix string) string {
	return applicationPermission(r, "workspaces/"+chi.URLParam(r, "workspace_id")+"/"+strings.Trim(suffix, "/"))
}

func (s *Server) validInvitationRoles(ctx context.Context, applicationID, workspaceID string, applicationRoles, workspaceRoles []string) bool {
	var applicationCount, workspaceCount int
	if s.app.DB.QueryRow(ctx, `SELECT
(SELECT count(*) FROM roles WHERE application_id=$1 AND scope='application' AND key=ANY($2)),
(SELECT count(*) FROM roles WHERE application_id=$1 AND scope='workspace' AND key=ANY($3))`, applicationID, applicationRoles, workspaceRoles).Scan(&applicationCount, &workspaceCount) != nil {
		return false
	}
	if applicationCount != len(applicationRoles) || workspaceCount != len(workspaceRoles) {
		return false
	}
	if workspaceID != "" {
		var exists bool
		_ = s.app.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM workspaces WHERE id=$1 AND application_id=$2 AND deleted_at IS NULL)`, workspaceID, applicationID).Scan(&exists)
		return exists
	}
	return true
}

func nullableText(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Server) invitationPresentation(ctx context.Context, applicationID, invitationID, linkToken, workspaceID, onboardingMethod string, hosted ...string) (string, string, string, error) {
	var clientID, callback string
	if len(hosted) == 2 {
		clientID, callback = hosted[0], hosted[1]
	} else {
		_ = s.app.DB.QueryRow(ctx, `SELECT COALESCE(hosted_client_id::text,''),COALESCE(hosted_redirect_uri,'') FROM application_invitations WHERE id=$1 AND application_id=$2`, invitationID, applicationID).Scan(&clientID, &callback)
	}
	destination := ""
	if clientID != "" || callback != "" {
		if _, _, err := s.hostedInvitationClient(ctx, applicationID, clientID, callback); err != nil {
			return "", "", "", err
		}
		destination = strings.TrimRight(s.app.PublicURL, "/") + "/auth/invitations/" + invitationID
	} else {
		flows, err := s.loadApplicationFlowConfig(ctx, applicationID)
		if err != nil || flows.InvitationRedirectURI == "" {
			return "", "", "", errInvalidInvitationRedirect
		}
		destination = flows.InvitationRedirectURI
	}
	link := appendCredentialQuery(destination, map[string]string{"application_id": applicationID, "invitation_id": invitationID,
		"link_token": linkToken, "onboarding_method": onboardingMethod, "platform93_flow": "invitation"})
	if workspaceID == "" {
		return link, applicationInvitationTemplate, "", nil
	}
	var name string
	if err := s.app.DB.QueryRow(ctx, `SELECT name FROM workspaces WHERE id=$1 AND application_id=$2`, workspaceID, applicationID).Scan(&name); err != nil {
		return "", "", "", err
	}
	return link, workspaceInvitationTemplate, name, nil
}

func (s *Server) listInvitations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	applicationID, workspaceID := chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id")
	if !s.canManageInvitations(w, r, workspaceID) {
		return
	}
	query := `SELECT id,workspace_id,normalized_email,application_roles,workspace_roles,onboarding_method,expires_at,accepted_at,revoked_at,last_sent_at,resend_available_at,created_at,hosted_client_id,hosted_redirect_uri,version
FROM application_invitations WHERE application_id=$1`
	args := []any{applicationID}
	if workspaceID != "" {
		query += ` AND workspace_id=$2`
		args = append(args, workspaceID)
	}
	params := r.URL.Query()
	if !params.Has("limit") {
		params.Set("limit", "20")
	}
	r.URL.RawQuery = params.Encode()
	query, args, limit, valid := referenceSearch(w, r, query, args, "id", "normalized_email")
	if !valid {
		return
	}
	rows, err := s.app.DB.Query(r.Context(), query, args...)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Invitations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, email, onboardingMethod string
		var workspace *string
		var hostedClientID, hostedRedirectURI *string
		var appRoles, workspaceRoles []string
		var expires, resend, created time.Time
		var sent *time.Time
		var version int64
		var accepted, revoked *time.Time
		if rows.Scan(&id, &workspace, &email, &appRoles, &workspaceRoles, &onboardingMethod, &expires, &accepted, &revoked, &sent, &resend, &created, &hostedClientID, &hostedRedirectURI, &version) == nil {
			status := "pending"
			if accepted != nil {
				status = "accepted"
			} else if revoked != nil {
				status = "revoked"
			} else if expires.Before(s.app.Now()) {
				status = "expired"
			}
			items = append(items, map[string]any{"id": id, "application_id": applicationID, "workspace_id": workspace, "email": email, "application_role_keys": appRoles,
				"workspace_role_keys": workspaceRoles, "onboarding_method": onboardingMethod, "status": status, "expires_at": expires, "accepted_at": accepted, "revoked_at": revoked,
				"version": version, "last_sent_at": sent, "resend_available_at": resend, "created_at": created, "hosted_client_id": hostedClientID, "hosted_redirect_uri": hostedRedirectURI})
		}
	}
	if rows.Err() != nil {
		kernel.WriteProblem(w, r, 503, "invitations_unavailable", "Invitations could not be loaded.")
		return
	}
	items, cursor := referencePage(items, limit, func(item map[string]any) string { return item["id"].(string) })
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": cursor})
}

func (s *Server) getInvitation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	applicationID, invitationID := chi.URLParam(r, "application_id"), chi.URLParam(r, "invitation_id")
	var workspaceID *string
	var hostedClientID, hostedRedirectURI *string
	var email, onboardingMethod string
	var applicationRoles, workspaceRoles []string
	var expiresAt, resendAvailableAt, createdAt, updatedAt time.Time
	var lastSentAt *time.Time
	var version int64
	var acceptedAt, revokedAt, expirationRecordedAt *time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT workspace_id,normalized_email,application_roles,workspace_roles,onboarding_method,expires_at,accepted_at,revoked_at,
last_sent_at,resend_available_at,expiration_recorded_at,created_at,updated_at,hosted_client_id,hosted_redirect_uri,version FROM application_invitations WHERE id=$1 AND application_id=$2`, invitationID, applicationID).
		Scan(&workspaceID, &email, &applicationRoles, &workspaceRoles, &onboardingMethod, &expiresAt, &acceptedAt, &revokedAt, &lastSentAt, &resendAvailableAt, &expirationRecordedAt, &createdAt, &updatedAt, &hostedClientID, &hostedRedirectURI, &version)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "invitation_not_found", "The invitation was not found.")
		return
	}
	resolvedWorkspaceID := ""
	if workspaceID != nil {
		resolvedWorkspaceID = *workspaceID
	}
	if !s.canManageInvitations(w, r, resolvedWorkspaceID) {
		return
	}
	status := "pending"
	if acceptedAt != nil {
		status = "accepted"
	} else if revokedAt != nil {
		status = "revoked"
	} else if expirationRecordedAt != nil || expiresAt.Before(s.app.Now()) {
		status = "expired"
	}
	w.Header().Set("ETag", kernel.ETag(version))
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"version": version, "id": invitationID, "application_id": applicationID, "workspace_id": workspaceID, "email": email,
		"application_role_keys": applicationRoles, "workspace_role_keys": workspaceRoles, "onboarding_method": onboardingMethod, "status": status, "expires_at": expiresAt,
		"accepted_at": acceptedAt, "revoked_at": revokedAt, "last_sent_at": lastSentAt, "resend_available_at": resendAvailableAt,
		"created_at": createdAt, "updated_at": updatedAt, "hosted_client_id": hostedClientID, "hosted_redirect_uri": hostedRedirectURI})
}

func (s *Server) resendInvitation(w http.ResponseWriter, r *http.Request) {
	s.rotateInvitation(w, r, true)
}

func fmtInt(value int) string { return strconv.Itoa(value) }

func (s *Server) listMyInvitations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT i.id,i.workspace_id,i.normalized_email,i.application_roles,i.workspace_roles,i.onboarding_method,i.expires_at,i.last_sent_at,i.created_at
FROM application_invitations i JOIN users u ON u.application_id=i.application_id AND u.normalized_email=i.normalized_email
WHERE i.application_id=$1 AND u.id=$2 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>now() ORDER BY i.created_at DESC`,
		chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Invitations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, email, onboardingMethod string
		var workspace *string
		var appRoles, workspaceRoles []string
		var expires, created time.Time
		var sent *time.Time
		if rows.Scan(&id, &workspace, &email, &appRoles, &workspaceRoles, &onboardingMethod, &expires, &sent, &created) == nil {
			items = append(items, map[string]any{"id": id, "application_id": chi.URLParam(r, "application_id"), "workspace_id": workspace, "email": email, "application_role_keys": appRoles, "workspace_role_keys": workspaceRoles, "onboarding_method": onboardingMethod, "status": "pending", "expires_at": expires, "last_sent_at": sent, "created_at": created})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) revokeWorkspaceInvitation(w http.ResponseWriter, r *http.Request) {
	s.revokeInvitation(w, r)
}

func (s *Server) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Reason string `json:"reason"`
	}
	if actor(r).Type != "control_user" {
		if !kernel.DecodeJSON(w, r, &input) || !administrationReason(w, r, input.Reason) {
			return
		}
	}
	applicationID, invitationID := chi.URLParam(r, "application_id"), chi.URLParam(r, "invitation_id")
	var workspaceID *string
	if err := s.app.DB.QueryRow(r.Context(), `SELECT workspace_id FROM application_invitations
WHERE id=$1 AND application_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, invitationID, applicationID).Scan(&workspaceID); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "invitation_not_found", "A pending invitation was not found.")
		return
	}
	resolvedWorkspaceID := ""
	if workspaceID != nil {
		resolvedWorkspaceID = *workspaceID
	}
	if routeWorkspace := chi.URLParam(r, "workspace_id"); routeWorkspace != "" && routeWorkspace != resolvedWorkspaceID {
		kernel.WriteProblem(w, r, 404, "invitation_not_found", "The invitation was not found.")
		return
	}
	if !s.canManageInvitations(w, r, resolvedWorkspaceID) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The invitation could not be revoked.")
		return
	}
	defer rollback(tx, r.Context())
	var version int64
	if err = tx.QueryRow(r.Context(), `SELECT version FROM application_invitations WHERE application_id=$1 AND id=$2 AND accepted_at IS NULL AND revoked_at IS NULL FOR UPDATE`, applicationID, invitationID).Scan(&version); err != nil {
		kernel.WriteProblem(w, r, 404, "invitation_not_found", "The invitation was not found.")
		return
	}
	if actor(r).Type != "control_user" && !administrationIfMatch(w, r, version) {
		return
	}
	if actor(r).Type != "control_user" {
		live, err := s.applicationAdminScopes(r, tx, actor(r))
		if err != nil || !(administrationAllows(actor(r), live, applicationPermission(r, "invitations/manage")) || workspaceID != nil && administrationAllows(actor(r), live, applicationPermission(r, "workspaces/"+*workspaceID+"/invitations/manage"))) {
			kernel.WriteProblem(w, r, 403, "invitation_management_required", "Current invitation management permission is required.")
			return
		}
	}
	result, err := tx.Exec(r.Context(), `UPDATE application_invitations SET revoked_at=now(),version=version+1,updated_at=now()
WHERE id=$1 AND application_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, invitationID, applicationID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "invitation_not_found", "A pending invitation was not found.")
		return
	}
	parsed, parseErr := uuid.Parse(applicationID)
	if parseErr == nil {
		_, err = s.app.Emit(r.Context(), tx, &parsed, "application_invitation.revoked", "application_invitation/"+invitationID, actor(r), map[string]any{"invitation_id": invitationID, "workspace_id": workspaceID, "status": "revoked"})
	}
	if err == nil {
		err = s.auditApplicationAdministration(r, tx, "invitation.revoked", invitationID, input.Reason)
	}
	if parseErr != nil || err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invitation_revoke_failed", "The invitation could not be revoked.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) canManageInvitations(w http.ResponseWriter, r *http.Request, workspaceID string) bool {
	current := actor(r)
	if current.Type == "control_user" {
		return true
	}
	if (current.Type == "user" || current.Type == "client") && current.DelegatedBy == "" {
		tx, err := s.app.DB.Begin(r.Context())
		if err == nil {
			defer rollback(tx, r.Context())
			live, e := s.applicationAdminScopes(r, tx, current)
			if e == nil {
				if administrationAllows(current, live, applicationPermission(r, "invitations/manage")) || workspaceID != "" && administrationAllows(current, live, applicationPermission(r, "workspaces/"+workspaceID+"/invitations/manage")) {
					return true
				}
			}
		}
	}
	kernel.WriteProblem(w, r, http.StatusForbidden, "invitation_management_required", "Invitation management permission is required.")
	return false
}

func (s *Server) exchangeInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		var authenticated *http.Request
		buffer := newBufferedResponse()
		s.requireUser(http.HandlerFunc(func(_ http.ResponseWriter, verified *http.Request) {
			if actor(verified).Type == "user" && actor(verified).DelegatedBy == "" {
				authenticated = verified
			}
		})).ServeHTTP(buffer, r)
		if authenticated == nil {
			kernel.WriteProblem(w, r, 401, "invitation_identity_mismatch", "A direct application-user session is required.")
			return
		}
		r = authenticated
	}
	var request invitationCredential
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !invitationPKCEChallengePattern.MatchString(request.CodeChallenge) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "pkce_required", "A valid S256 PKCE code challenge is required.")
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	request.Email = kernel.NormalizeEmail(request.Email)
	codePath := request.Email != "" && request.Code != "" && request.InvitationID == "" && request.LinkToken == ""
	linkPath := request.InvitationID != "" && request.LinkToken != "" && request.Email == "" && request.Code == ""
	request.Code = strings.ToUpper(strings.TrimSpace(request.Code))
	if !codePath && !linkPath || codePath && !invitationCodePattern.MatchString(request.Code) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_invitation_credential", "Provide either email with code or invitation ID with link token.")
		return
	}
	rateLimitSubject := request.InvitationID
	if rateLimitSubject == "" {
		rateLimitSubject = request.Email
	}
	if rateLimitSubject == "" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invitation_identifier_required", "An invitation ID or recipient email is required.")
		return
	}
	if !s.allowAuthAttempt(w, r, "invitation_exchange", applicationID+":"+rateLimitSubject, 10, 15*time.Minute) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The invitation could not be accepted.")
		return
	}
	defer rollback(tx, r.Context())
	var invitationID, email, onboardingMethod string
	var workspaceID *string
	var appRoles, workspaceRoles []string
	var codeDigest, linkDigest []byte
	var invitationVersion int64
	query := `SELECT id,workspace_id,normalized_email,application_roles,workspace_roles,onboarding_method,code_credential_digest,link_credential_digest,version
FROM application_invitations WHERE application_id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()`
	args := []any{applicationID}
	if request.InvitationID != "" {
		query += ` AND id=$2`
		args = append(args, request.InvitationID)
	} else {
		query += ` AND normalized_email=$2 AND code_credential_digest=$3`
		args = append(args, request.Email, s.app.Vault.Digest(strings.ToUpper(request.Code)))
	}
	query += ` FOR UPDATE`
	err = tx.QueryRow(r.Context(), query, args...).Scan(&invitationID, &workspaceID, &email, &appRoles, &workspaceRoles, &onboardingMethod, &codeDigest, &linkDigest, &invitationVersion)
	valid := err == nil && onboardingMethod == "email" && ((request.Code != "" && request.Email == email && equalBytes(codeDigest, s.app.Vault.Digest(strings.ToUpper(request.Code)))) ||
		(request.LinkToken != "" && equalBytes(linkDigest, s.app.Vault.Digest(request.LinkToken))))
	if !valid {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_invitation", "The invitation is invalid, expired, or already used.")
		return
	}
	if err = s.revalidateInvitationAuthority(r, tx, invitationID); err != nil {
		kernel.WriteProblem(w, r, 403, "invitation_authority_revoked", "The inviter no longer has the required authority.")
		return
	}
	var userID, status string
	var establishedRecipient bool
	// Verification after invitation creation must not bless credentials planted
	// on an unverified account before the mailbox owner arrives.
	err = tx.QueryRow(r.Context(), `SELECT u.id,u.status,
 (u.email_verified_at IS NOT NULL AND u.email_verified_at<i.created_at) OR NOT (
 u.password_hash IS NOT NULL OR
 EXISTS(SELECT 1 FROM user_identities x WHERE x.application_id=u.application_id AND x.user_id=u.id) OR
 EXISTS(SELECT 1 FROM user_authentication_methods x WHERE x.application_id=u.application_id AND x.user_id=u.id AND x.status<>'disabled') OR
 EXISTS(SELECT 1 FROM personal_api_keys x WHERE x.application_id=u.application_id AND x.user_id=u.id AND x.revoked_at IS NULL) OR
 EXISTS(SELECT 1 FROM user_sessions x WHERE x.application_id=u.application_id AND x.user_id=u.id AND x.revoked_at IS NULL AND x.amr && ARRAY['pwd','password','google','apple','facebook','microsoft','linkedin','webauthn','totp']))
 FROM users u JOIN application_invitations i ON i.application_id=u.application_id AND i.id=$3
 WHERE u.application_id=$1 AND u.normalized_email=$2 FOR UPDATE OF u`, applicationID, email, invitationID).Scan(&userID, &status, &establishedRecipient)
	recoverCredentials := err == nil && !establishedRecipient
	if err != nil && err != pgx.ErrNoRows || err == nil && status != "active" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invited_account_unavailable", "The invited account is unavailable.")
		return
	}
	if !s.verifyInvitationRecipient(w, r, tx, invitationID, email, invitationVersion, request, recoverCredentials) {
		return
	}
	if err == pgx.ErrNoRows {
		if limitErr := enforceUserLimit(r.Context(), tx, applicationID); limitErr != nil {
			kernel.WriteProblem(w, r, http.StatusConflict, "invited_user_creation_failed", "The invited account could not be created.")
			return
		}
		userID, status = kernel.NewID().String(), "active"
		_, err = tx.Exec(r.Context(), `INSERT INTO users(id,application_id,email,normalized_email,email_verified_at)
VALUES($1,$2,$3,$3,now())`, userID, applicationID, email)
		parsedApplicationID, parseErr := uuid.Parse(applicationID)
		if err == nil && parseErr == nil {
			_, err = s.app.Emit(r.Context(), tx, &parsedApplicationID, "user.created", "user/"+userID, map[string]any{"type": "invitation"}, map[string]any{"user_id": userID, "email_verified": true, "is_org_verified": false})
		}
	} else if err == nil && status == "active" {
		if recoverCredentials {
			err = s.recoverInvitationCredentials(r, tx, userID, invitationID)
			if err != nil {
				kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "invitation_recovery_failed", "Account recovery could not be committed. Retry with the same invitation and mailbox proof.")
				return
			}
		} else {
			_, err = tx.Exec(r.Context(), `UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()),updated_at=now() WHERE id=$1 AND application_id=$2`, userID, applicationID)
		}
	}
	if err != nil || status != "active" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invited_account_unavailable", "The invited account is unavailable.")
		return
	}
	roleWorkspaceID := workspaceID
	if workspaceID != nil {
		var owner bool
		_ = tx.QueryRow(r.Context(), `SELECT owner_user_id=$3 FROM workspaces WHERE id=$1 AND application_id=$2`, *workspaceID, applicationID, userID).Scan(&owner)
		if !owner {
			_, err = tx.Exec(r.Context(), `INSERT INTO workspace_memberships(application_id,workspace_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, applicationID, *workspaceID, userID)
		} else {
			roleWorkspaceID = nil
		}
	}
	if err == nil {
		err = assignInvitationRoles(r.Context(), tx, applicationID, userID, roleWorkspaceID, appRoles, workspaceRoles)
	}
	if err == nil {
		result, updateErr := tx.Exec(r.Context(), `UPDATE application_invitations SET accepted_at=now(),version=version+1,updated_at=now() WHERE id=$1 AND accepted_at IS NULL AND revoked_at IS NULL`, invitationID)
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = pgx.ErrNoRows
		}
	}
	authorizationCode, codeErr := secure.RandomToken("p93_invitation_code_", 32)
	if err == nil && codeErr == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO invitation_authorization_codes(id,application_id,user_id,code_digest,code_challenge,expires_at)
VALUES($1,$2,$3,$4,$5,now()+interval '5 minutes')`, kernel.NewID(), applicationID, userID, s.app.Vault.Digest(authorizationCode), request.CodeChallenge)
	} else if codeErr != nil {
		err = codeErr
	}
	parsed, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(r.Context(), tx, &parsed, "application_invitation.accepted", "application_invitation/"+invitationID, map[string]any{"type": "user", "id": userID}, map[string]any{"invitation_id": invitationID, "user_id": userID, "workspace_id": workspaceID, "status": "accepted"})
	}
	if err != nil || parseErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "invitation_acceptance_failed", "The invitation could not be accepted.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"authorization_code": authorizationCode, "expires_in": 300})
}

func (s *Server) redeemInvitationAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AuthorizationCode string `json:"authorization_code"`
		CodeVerifier      string `json:"code_verifier"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !invitationPKCEVerifierPattern.MatchString(request.CodeVerifier) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_pkce_verifier", "A valid PKCE code verifier is required.")
		return
	}
	digest := sha256.Sum256([]byte(request.CodeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The invitation authorization code could not be redeemed.")
		return
	}
	defer rollback(tx, r.Context())
	var id, userID, expectedChallenge string
	var epoch int64
	err = tx.QueryRow(r.Context(), `SELECT c.id,c.user_id,c.code_challenge,u.authentication_epoch FROM invitation_authorization_codes c JOIN users u ON u.id=c.user_id AND u.application_id=c.application_id
WHERE c.application_id=$1 AND c.code_digest=$2 AND c.used_at IS NULL AND c.expires_at>now() FOR UPDATE OF c`, chi.URLParam(r, "application_id"), s.app.Vault.Digest(request.AuthorizationCode)).Scan(&id, &userID, &expectedChallenge, &epoch)
	if err != nil || !equalBytes([]byte(challenge), []byte(expectedChallenge)) {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_invitation_authorization_code", "The invitation authorization code is invalid, expired, or already used.")
		return
	}
	result, err := tx.Exec(r.Context(), `UPDATE invitation_authorization_codes SET used_at=now() WHERE id=$1 AND used_at IS NULL`, id)
	if err != nil || result.RowsAffected() != 1 || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "invitation_authorization_conflict", "The invitation authorization code was already used.")
		return
	}
	s.completePrimaryAuthentication(w, withAuthenticationEpoch(r, epoch), userID, []string{"invitation", "pkce"})
}

func assignInvitationRoles(ctx context.Context, tx pgx.Tx, applicationID, userID string, workspaceID *string, appRoles, workspaceRoles []string) error {
	for _, roleKey := range appRoles {
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments(id,application_id,user_id,role_id)
SELECT $1,$2,$3,id FROM roles WHERE application_id=$2 AND key=$4 AND scope='application' ON CONFLICT DO NOTHING`, kernel.NewID(), applicationID, userID, roleKey)
		if err != nil {
			return err
		}
	}
	if workspaceID != nil {
		for _, roleKey := range workspaceRoles {
			_, err := tx.Exec(ctx, `INSERT INTO role_assignments(id,application_id,user_id,role_id,workspace_id)
SELECT $1,$2,$3,id,$4 FROM roles WHERE application_id=$2 AND key=$5 AND scope='workspace' ON CONFLICT DO NOTHING`, kernel.NewID(), applicationID, userID, *workspaceID, roleKey)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) listWorkspaceAccess(w http.ResponseWriter, r *http.Request) {
	if actor(r).Type == "user" && !s.canAccessWorkspace(r, false) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_access_required", "Workspace access is required.")
		return
	}
	applicationID, workspaceID := chi.URLParam(r, "application_id"), chi.URLParam(r, "workspace_id")
	items := []map[string]any{}
	var ownerID, ownerEmail, firstName, lastName string
	if s.app.DB.QueryRow(r.Context(), `SELECT u.id,u.email,u.first_name,u.last_name FROM workspaces w JOIN users u ON u.id=w.owner_user_id
WHERE w.id=$1 AND w.application_id=$2 AND w.deleted_at IS NULL`, workspaceID, applicationID).Scan(&ownerID, &ownerEmail, &firstName, &lastName) != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "workspace_not_found", "The workspace was not found.")
		return
	}
	items = append(items, map[string]any{"entry_type": "user", "status": "owner", "user_id": ownerID, "email": ownerEmail, "first_name": firstName, "last_name": lastName, "role_keys": []string{}})
	rows, _ := s.app.DB.Query(r.Context(), `SELECT u.id,u.email,u.first_name,u.last_name,COALESCE(array_agg(DISTINCT ro.key) FILTER(WHERE ro.key IS NOT NULL),'{}')
FROM workspace_memberships m JOIN users u ON u.id=m.user_id LEFT JOIN role_assignments ra ON ra.user_id=u.id AND ra.workspace_id=m.workspace_id
LEFT JOIN roles ro ON ro.id=ra.role_id WHERE m.application_id=$1 AND m.workspace_id=$2 GROUP BY u.id ORDER BY u.email`, applicationID, workspaceID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, email, first, last string
			var roles []string
			if rows.Scan(&id, &email, &first, &last, &roles) == nil {
				items = append(items, map[string]any{"entry_type": "user", "status": "active", "user_id": id, "email": email, "first_name": first, "last_name": last, "role_keys": roles})
			}
		}
	}
	invites, _ := s.app.DB.Query(r.Context(), `SELECT id,normalized_email,workspace_roles,expires_at,last_sent_at,resend_available_at FROM application_invitations
WHERE application_id=$1 AND workspace_id=$2 AND accepted_at IS NULL AND revoked_at IS NULL ORDER BY created_at DESC`, applicationID, workspaceID)
	if invites != nil {
		defer invites.Close()
		for invites.Next() {
			var id, email string
			var roles []string
			var expires, sent, resend time.Time
			if invites.Scan(&id, &email, &roles, &expires, &sent, &resend) == nil {
				status := "pending"
				if expires.Before(s.app.Now()) {
					status = "expired"
				}
				items = append(items, map[string]any{"entry_type": "invitation", "status": status, "invitation_id": id, "email": email, "role_keys": roles, "expires_at": expires, "last_sent_at": sent, "resend_available_at": resend})
			}
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}
