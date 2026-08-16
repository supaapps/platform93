package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) createDelegation(w http.ResponseWriter, r *http.Request) {
	if !s.delegationEnabled(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "delegation_disabled", "Platform user delegation is disabled for this application.")
		return
	}
	var request struct {
		UserID      string   `json:"user_id"`
		WorkspaceID string   `json:"workspace_id,omitempty"`
		Reason      string   `json:"reason"`
		RedirectURI string   `json:"redirect_uri"`
		Permissions []string `json:"permissions"`
		ExpiresIn   int64    `json:"expires_in,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	request.Permissions = uniqueStrings(request.Permissions)
	if request.ExpiresIn == 0 {
		request.ExpiresIn = 900
	}
	if request.UserID == "" || request.Reason == "" || len(request.Reason) > 500 || request.RedirectURI == "" ||
		len(request.Permissions) == 0 || len(request.Permissions) > 50 || request.ExpiresIn < 60 || request.ExpiresIn > 1800 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_delegation", "User, reason, allowlisted redirect, permissions, and an expiry of one to thirty minutes are required.")
		return
	}
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	var redirectAllowed, userActive bool
	err = s.app.DB.QueryRow(r.Context(), `SELECT
EXISTS(SELECT 1 FROM clients WHERE application_id=$1 AND disabled_at IS NULL AND $2=ANY(redirect_uris)),
EXISTS(SELECT 1 FROM users WHERE id=$3 AND application_id=$1 AND status='active')`, applicationID, request.RedirectURI, request.UserID).
		Scan(&redirectAllowed, &userActive)
	if err != nil || !redirectAllowed || !userActive {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_delegation_target", "The active user or exact client redirect URI was not found in this application.")
		return
	}
	if request.WorkspaceID != "" && !s.userBelongsToWorkspace(r.Context(), applicationID.String(), request.UserID, request.WorkspaceID) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_delegation_workspace", "The target user is not a member of the selected workspace.")
		return
	}
	var workspaceID *string
	if request.WorkspaceID != "" {
		workspaceID = &request.WorkspaceID
	}
	canonicalPermissions := make([]string, 0, len(request.Permissions))
	for _, permission := range request.Permissions {
		canonical, canonicalErr := platformauthz.CanonicalScope(applicationID.String(), workspaceID, permission)
		if canonicalErr != nil || strings.Split(permission, ":")[0] == "roles" {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_delegation_permissions", "Delegated permissions must be unique lowercase ASCII colon-delimited keys; a wildcard is allowed only as the final complete segment.")
			return
		}
		canonicalPermissions = append(canonicalPermissions, canonical)
	}
	userPermissions := s.permissionsForWorkspace(r, applicationID, request.UserID, request.WorkspaceID)
	for _, requested := range canonicalPermissions {
		allowed := false
		for _, granted := range userPermissions {
			if permissionMatches(granted, requested) {
				allowed = true
				break
			}
		}
		if !allowed {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_delegation_permissions", "Delegated permissions must be a reduction of the target user's live permissions.")
			return
		}
	}
	exchangeCode, err := secure.RandomToken("p93_delegate_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "delegation_creation_failed", "The delegation exchange code could not be generated.")
		return
	}
	id := kernel.NewID()
	expiresAt := s.app.Now().Add(time.Duration(request.ExpiresIn) * time.Second)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The delegation could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO delegations
(id,application_id,control_user_id,user_id,workspace_id,reason,redirect_uri,permissions,exchange_digest,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, applicationID, actor(r).ID, request.UserID, workspaceID,
		request.Reason, request.RedirectURI, canonicalPermissions, s.app.Vault.Digest(exchangeCode), expiresAt)
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "delegation.created", "delegation/"+id.String(), actor(r),
			map[string]any{"delegation_id": id, "user_id": request.UserID, "workspace_id": workspaceID, "permissions": canonicalPermissions,
				"reason": request.Reason, "expires_at": expiresAt})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "delegation_creation_failed", "The delegation could not be committed.")
		return
	}
	redirect, _ := url.Parse(request.RedirectURI)
	query := redirect.Query()
	query.Set("delegation_id", id.String())
	query.Set("exchange_code", exchangeCode)
	redirect.RawQuery = query.Encode()
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "user_id": request.UserID, "workspace_id": workspaceID,
		"permissions": canonicalPermissions, "reason": request.Reason, "expires_at": expiresAt, "exchange_code": exchangeCode,
		"redirect_to": redirect.String()})
}

func (s *Server) listDelegations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT d.id,d.control_user_id,d.user_id,u.email,d.workspace_id,d.reason,d.redirect_uri,d.permissions,
d.expires_at,d.exchanged_at,d.revoked_at,d.created_at FROM delegations d JOIN users u ON u.id=d.user_id
WHERE d.application_id=$1 ORDER BY d.created_at DESC,d.id DESC`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Delegations could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		item, ok := scanDelegation(rows)
		if ok {
			items = append(items, item)
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getDelegation(w http.ResponseWriter, r *http.Request) {
	row := s.app.DB.QueryRow(r.Context(), `SELECT d.id,d.control_user_id,d.user_id,u.email,d.workspace_id,d.reason,d.redirect_uri,d.permissions,
d.expires_at,d.exchanged_at,d.revoked_at,d.created_at FROM delegations d JOIN users u ON u.id=d.user_id
WHERE d.id=$1 AND d.application_id=$2`, chi.URLParam(r, "delegation_id"), chi.URLParam(r, "application_id"))
	item, ok := scanDelegation(row)
	if !ok {
		kernel.WriteProblem(w, r, http.StatusNotFound, "delegation_not_found", "The delegation was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, item)
}

func (s *Server) revokeDelegation(w http.ResponseWriter, r *http.Request) {
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The delegation could not be revoked.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE delegations SET revoked_at=COALESCE(revoked_at,now())
WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "delegation_id"), applicationID)
	if err == nil && result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "delegation_not_found", "The delegation was not found.")
		return
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE delegation_id=$1`, chi.URLParam(r, "delegation_id"))
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "delegation.revoked", "delegation/"+chi.URLParam(r, "delegation_id"), actor(r),
			map[string]any{"delegation_id": chi.URLParam(r, "delegation_id")})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "delegation_revocation_failed", "The delegation could not be revoked.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) exchangeDelegation(w http.ResponseWriter, r *http.Request) {
	if !s.delegationEnabled(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "delegation_disabled", "Platform user delegation is disabled for this application.")
		return
	}
	var request struct {
		ExchangeCode string `json:"exchange_code"`
	}
	if !kernel.DecodeJSON(w, r, &request) || request.ExchangeCode == "" {
		return
	}
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The delegation could not be exchanged.")
		return
	}
	defer rollback(tx, r.Context())
	var userID, controlUserID string
	var workspaceID *string
	var permissions []string
	var expiresAt time.Time
	var email, locale string
	var emailVerified, orgVerified bool
	err = tx.QueryRow(r.Context(), `SELECT d.user_id,d.control_user_id,d.workspace_id,d.permissions,d.expires_at,u.email,u.locale,
	u.email_verified_at IS NOT NULL,u.is_org_verified FROM delegations d JOIN users u ON u.id=d.user_id
	WHERE d.id=$1 AND d.application_id=$2 AND d.exchange_digest=$3
AND d.exchanged_at IS NULL AND d.revoked_at IS NULL AND d.expires_at>now() AND u.status='active' FOR UPDATE OF d`,
		chi.URLParam(r, "delegation_id"), applicationID, s.app.Vault.Digest(request.ExchangeCode)).
		Scan(&userID, &controlUserID, &workspaceID, &permissions, &expiresAt, &email, &locale, &emailVerified, &orgVerified)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_delegation_exchange", "The delegation exchange code is invalid, expired, or already used.")
		return
	}
	selectedWorkspace := ""
	if workspaceID != nil {
		selectedWorkspace = *workspaceID
		if !s.userBelongsToWorkspace(r.Context(), applicationID.String(), userID, selectedWorkspace) {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "inactive_workspace_membership", "The delegated workspace membership is no longer active.")
			return
		}
	}
	livePermissions := s.permissionsForWorkspace(r, applicationID, userID, selectedWorkspace)
	for _, delegatedPermission := range permissions {
		allowed := false
		for _, granted := range livePermissions {
			if permissionMatches(granted, delegatedPermission) {
				allowed = true
				break
			}
		}
		if !allowed {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "delegation_permissions_changed", "The target user no longer has all delegated permissions.")
			return
		}
	}
	sessionID := kernel.NewID()
	internalRefresh, _ := secure.RandomToken("p93_delegated_internal_", 32)
	_, err = tx.Exec(r.Context(), `INSERT INTO user_sessions
	(id,application_id,user_id,delegation_id,refresh_digest,user_agent,authenticated_at,amr,expires_at)
	VALUES ($1,$2,$3,$4,$5,$6,now(),ARRAY['delegation'],$7)`, sessionID, applicationID, userID,
		chi.URLParam(r, "delegation_id"), s.app.Vault.Digest(internalRefresh), truncate(r.UserAgent(), 512), expiresAt)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE delegations SET exchanged_at=now() WHERE id=$1`, chi.URLParam(r, "delegation_id"))
	}
	kid, privateKey, keyErr := s.app.ActiveSigningKey(r.Context())
	now := s.app.Now()
	accessExpires := expiresAt
	if accessExpires.After(now.Add(15 * time.Minute)) {
		accessExpires = now.Add(15 * time.Minute)
	}
	var access string
	if err == nil && keyErr == nil {
		customClaims, claimsErr := s.customClaimsForUser(r.Context(), applicationID.String(), userID)
		if claimsErr != nil {
			err = claimsErr
		} else {
			access, err = identity.Sign(privateKey, kid, identity.Claims{Issuer: s.app.Issuer(), Subject: userID, Audience: []string{s.app.ApplicationAudience(applicationID)},
				ExpiresAt: accessExpires.Unix(), IssuedAt: now.Unix(), NotBefore: now.Add(-5 * time.Second).Unix(), JWTID: kernel.NewID().String(),
				SessionID: sessionID.String(), ApplicationID: applicationID.String(), TokenKind: "access", ActorType: "user", Scope: strings.Join(permissions, " "), Email: email, Locale: locale, EmailVerified: emailVerified,
				Roles: emptyRoleClaims(), IsOrgVerified: orgVerified, CustomClaims: customClaims, AMR: []string{"delegation"},
				Actor: &identity.Actor{Subject: controlUserID, Type: "control_user"}})
		}
	} else if keyErr != nil {
		err = keyErr
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "delegation.exchanged", "delegation/"+chi.URLParam(r, "delegation_id"),
			map[string]any{"type": "control_user", "id": controlUserID}, map[string]any{"delegation_id": chi.URLParam(r, "delegation_id"), "user_id": userID})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "delegation_exchange_failed", "The delegated session could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer",
		"expires_in": int64(accessExpires.Sub(now).Seconds()), "delegated": true, "delegation_id": chi.URLParam(r, "delegation_id")})
}

func scanDelegation(row scanner) (map[string]any, bool) {
	var id, controlUserID, userID, email, reason, redirectURI string
	var workspaceID *string
	var permissions []string
	var expiresAt, createdAt time.Time
	var exchangedAt, revokedAt *time.Time
	if row.Scan(&id, &controlUserID, &userID, &email, &workspaceID, &reason, &redirectURI, &permissions,
		&expiresAt, &exchangedAt, &revokedAt, &createdAt) != nil {
		return nil, false
	}
	status := "pending"
	if revokedAt != nil {
		status = "revoked"
	} else if expiresAt.Before(time.Now()) {
		status = "expired"
	} else if exchangedAt != nil {
		status = "active"
	}
	return map[string]any{"id": id, "control_user_id": controlUserID, "user_id": userID, "user_email": email, "workspace_id": workspaceID,
		"reason": reason, "redirect_uri": redirectURI, "permissions": permissions, "expires_at": expiresAt,
		"exchanged_at": exchangedAt, "revoked_at": revokedAt, "created_at": createdAt, "status": status}, true
}
