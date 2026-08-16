package httpapi

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

var (
	controlUserDummyPasswordOnce sync.Once
	controlUserDummyPasswordHash string
)

func (s *Server) getControlUserAccount(w http.ResponseWriter, r *http.Request) {
	var id, email, displayName, status string
	var passwordEnabled bool
	var createdAt, updatedAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,email,display_name,status,password_hash IS NOT NULL,created_at,updated_at
FROM control_users WHERE id=$1`, actor(r).ID).Scan(&id, &email, &displayName, &status, &passwordEnabled, &createdAt, &updatedAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "control_user_not_found", "The signed-in Platform user account was not found.")
		return
	}
	installationRole, hasInstallationRole := s.installationRole(r)
	var installationRoleValue any
	if hasInstallationRole {
		installationRoleValue = installationRole
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT o.id,o.name,m.role FROM organization_memberships m
JOIN organizations o ON o.id=m.organization_id WHERE m.control_user_id=$1 AND o.deleted_at IS NULL ORDER BY o.name,o.id`, id)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform user organization access could not be loaded.")
		return
	}
	defer rows.Close()
	organizations := []map[string]any{}
	for rows.Next() {
		var organizationID, name, role string
		if rows.Scan(&organizationID, &name, &role) == nil {
			organizations = append(organizations, map[string]any{"id": organizationID, "name": name, "role": role})
		}
	}
	identityRows, identityErr := s.app.DB.Query(r.Context(), `SELECT i.id,i.provider,i.metadata,i.created_at,i.last_used_at,
p.disabled_at IS NULL AND p.control_login_enabled FROM control_user_identities i
JOIN auth_provider_configs p ON p.id=i.auth_provider_config_id WHERE i.control_user_id=$1 ORDER BY i.created_at`, id)
	identities := []map[string]any{}
	if identityErr == nil {
		defer identityRows.Close()
		for identityRows.Next() {
			var identityID, provider string
			var metadata map[string]any
			var identityCreatedAt time.Time
			var lastUsedAt *time.Time
			var available bool
			if identityRows.Scan(&identityID, &provider, &metadata, &identityCreatedAt, &lastUsedAt, &available) == nil {
				identities = append(identities, map[string]any{"id": identityID, "provider": provider, "metadata": metadata,
					"available": available, "created_at": identityCreatedAt, "last_used_at": lastUsedAt})
			}
		}
	}
	policy, _ := s.loadControlAuthPolicy(r.Context())
	var smtp bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM notification_providers WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL)`).Scan(&smtp)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{
		"id": id, "email": email, "display_name": displayName, "status": status,
		"installation_role": installationRoleValue, "organizations": organizations,
		"sign_in_methods": map[string]any{"email_code": policy.EmailCodeEnabled && smtp, "magic_link": policy.MagicLinkEnabled && smtp,
			"password": policy.PasswordEnabled && passwordEnabled, "external_identities": identities},
		"created_at": createdAt, "updated_at": updatedAt,
	})
}

func (s *Server) updateControlUserAccount(w http.ResponseWriter, r *http.Request) {
	var request struct {
		DisplayName string `json:"display_name"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.DisplayName = strings.TrimSpace(request.DisplayName)
	if request.DisplayName == "" || len(request.DisplayName) > 200 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_control_user_profile", "Display name must contain between 1 and 200 characters.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE control_users SET display_name=$1,updated_at=now() WHERE id=$2 AND status='active'`, request.DisplayName, actor(r).ID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "control_user_not_found", "The signed-in Platform user account was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) changeControlUserPassword(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	var currentHash *string
	var sessionCreatedAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT o.password_hash,s.created_at FROM control_users o
JOIN control_user_sessions s ON s.control_user_id=o.id WHERE o.id=$1 AND s.id=$2 AND s.revoked_at IS NULL AND s.expires_at>now()`, actor(r).ID, actor(r).SessionID).
		Scan(&currentHash, &sessionCreatedAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "control_user_session_required", "An active Platform user session is required.")
		return
	}
	if currentHash != nil {
		if !identity.VerifyPassword(*currentHash, request.CurrentPassword) {
			kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_current_password", "The current password is incorrect.")
			return
		}
	} else if sessionCreatedAt.Before(s.app.Now().Add(-10 * time.Minute)) {
		kernel.WriteProblem(w, r, http.StatusConflict, "recent_authentication_required", "Sign in again with an email code or magic link before adding a password.")
		return
	}
	newHash, err := identity.HashPassword(request.NewPassword)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_password", err.Error())
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The Platform user password could not be changed.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `UPDATE control_users SET password_hash=$1,updated_at=now() WHERE id=$2`, newHash, actor(r).ID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE control_user_id=$1 AND id<>$2 AND revoked_at IS NULL`, actor(r).ID, actor(r).SessionID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "control_user_password_change_failed", "The Platform user password could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) controlUserPasswordLogin(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	policy, policyErr := s.loadControlAuthPolicy(r.Context())
	if policyErr != nil || !policy.PasswordEnabled {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "control_password_login_unavailable", "Platform password sign-in is unavailable.")
		return
	}
	normalized := kernel.NormalizeEmail(request.Email)
	if !s.allowAuthAttempt(w, r, "control_user_password", normalized, 8, 10*time.Minute) {
		return
	}
	var controlUserID, passwordHash string
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,password_hash FROM control_users
WHERE normalized_email=$1 AND status='active' AND password_hash IS NOT NULL`, normalized).Scan(&controlUserID, &passwordHash)
	found := err == nil
	if !found {
		controlUserDummyPasswordOnce.Do(func() {
			controlUserDummyPasswordHash, _ = identity.HashPassword("platform93 timing equalization credential")
		})
		passwordHash = controlUserDummyPasswordHash
	}
	validPassword := identity.VerifyPassword(passwordHash, request.Password)
	if !found || !validPassword {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_control_user_credentials", "The email address or password is incorrect.")
		return
	}
	refresh, err := secure.RandomToken("p93_control_refresh_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The Platform user session could not be created.")
		return
	}
	sessionID := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The Platform user session could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO control_user_sessions
(id,control_user_id,refresh_digest,kind,ip_address,user_agent,amr,expires_at) VALUES($1,$2,$3,'control',$4,$5,$6,$7)`,
		sessionID, controlUserID, s.app.Vault.Digest(refresh), requestIPAddress(r), truncate(r.UserAgent(), 500), []string{"password"}, s.app.Now().Add(12*time.Hour))
	access, tokenErr := s.issueControlUserAccessWithQuerier(r.Context(), tx, controlUserID, sessionID.String(), "control")
	if err != nil || tokenErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "control_user_session_failed", "The Platform user session could not be committed.")
		return
	}
	s.setControlUserCookies(w, access, refresh, 12*time.Hour)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 300})
}
