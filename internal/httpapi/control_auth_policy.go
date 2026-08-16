package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/supaapps/platform93/internal/kernel"
)

type controlAuthPolicy struct {
	EmailCodeEnabled bool `json:"email_code_enabled"`
	MagicLinkEnabled bool `json:"magic_link_enabled"`
	PasswordEnabled  bool `json:"password_enabled"`
}

func (s *Server) loadControlAuthPolicy(ctx context.Context) (controlAuthPolicy, error) {
	var value controlAuthPolicy
	err := s.app.DB.QueryRow(ctx, `SELECT control_email_code_enabled,control_magic_link_enabled,control_password_enabled
FROM installations LIMIT 1`).Scan(&value.EmailCodeEnabled, &value.MagicLinkEnabled, &value.PasswordEnabled)
	return value, err
}

func (s *Server) controlAuthMethods(w http.ResponseWriter, r *http.Request) {
	policy, err := s.loadControlAuthPolicy(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "control_auth_unavailable", "Platform authentication configuration is unavailable.")
		return
	}
	var smtp bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM notification_providers
WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL)`).Scan(&smtp)
	providers := []string{}
	rows, queryErr := s.app.DB.Query(r.Context(), `SELECT provider FROM auth_provider_configs
WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL AND control_login_enabled ORDER BY provider`)
	if queryErr == nil {
		defer rows.Close()
		for rows.Next() {
			var provider string
			if rows.Scan(&provider) == nil {
				providers = append(providers, provider)
			}
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{
		"email_code": policy.EmailCodeEnabled && smtp,
		"magic_link": policy.MagicLinkEnabled && smtp,
		"password":   policy.PasswordEnabled,
		"providers":  providers,
	})
}

func (s *Server) getControlAuthPolicy(w http.ResponseWriter, r *http.Request) {
	if _, allowed := s.installationRole(r); !allowed {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_role_required", "An installation role is required.")
		return
	}
	policy, err := s.loadControlAuthPolicy(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform authentication policy could not be loaded.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, policy)
}

func (s *Server) updateControlAuthPolicy(w http.ResponseWriter, r *http.Request) {
	role, allowed := s.installationRole(r)
	if !allowed || role != "owner" && role != "admin" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required.")
		return
	}
	var request struct {
		EmailCodeEnabled     bool `json:"email_code_enabled"`
		MagicLinkEnabled     bool `json:"magic_link_enabled"`
		PasswordEnabled      bool `json:"password_enabled"`
		ConfirmAffectedUsers bool `json:"confirm_affected_users,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	policy := controlAuthPolicy{EmailCodeEnabled: request.EmailCodeEnabled, MagicLinkEnabled: request.MagicLinkEnabled, PasswordEnabled: request.PasswordEnabled}
	if !s.allowControlPolicyChange(w, r, policy, request.ConfirmAffectedUsers, "") {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE installations SET control_email_code_enabled=$1,
control_magic_link_enabled=$2,control_password_enabled=$3,updated_at=now()`, policy.EmailCodeEnabled, policy.MagicLinkEnabled, policy.PasswordEnabled)
	}
	if err == nil {
		err = s.emitControlEvent(r.Context(), tx, r, "control_auth.policy_updated", "installation/identity", map[string]any{
			"email_code_enabled": policy.EmailCodeEnabled, "magic_link_enabled": policy.MagicLinkEnabled, "password_enabled": policy.PasswordEnabled,
		})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "control_auth_policy_update_failed", "Platform authentication policy could not be updated.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) allowControlMethodRemoval(w http.ResponseWriter, r *http.Request, excludedProvider string, confirmed bool) bool {
	policy, err := s.loadControlAuthPolicy(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform authentication safety could not be checked.")
		return false
	}
	return s.allowControlPolicyChange(w, r, policy, confirmed, excludedProvider)
}

func (s *Server) allowControlPolicyChange(w http.ResponseWriter, r *http.Request, policy controlAuthPolicy, confirmed bool, excludedProvider string) bool {
	var smtp bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM notification_providers
WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL)`).Scan(&smtp)
	return s.allowControlPolicyChangeWithSMTP(w, r, policy, confirmed, excludedProvider, smtp)
}

func (s *Server) allowControlSMTPRemoval(w http.ResponseWriter, r *http.Request, providerID string, confirmed bool) bool {
	var active, anotherActive bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT
EXISTS(SELECT 1 FROM notification_providers WHERE id=$1 AND application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL),
EXISTS(SELECT 1 FROM notification_providers WHERE id<>$1 AND application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL)`, providerID).Scan(&active, &anotherActive)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform authentication safety could not be checked.")
		return false
	}
	if !active || anotherActive {
		return true
	}
	policy, err := s.loadControlAuthPolicy(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform authentication safety could not be checked.")
		return false
	}
	return s.allowControlPolicyChangeWithSMTP(w, r, policy, confirmed, "", false)
}

func (s *Server) allowControlPolicyChangeWithSMTP(w http.ResponseWriter, r *http.Request, policy controlAuthPolicy, confirmed bool, excludedProvider string, smtp bool) bool {
	rows, err := s.app.DB.Query(r.Context(), `SELECT u.id,u.password_hash IS NOT NULL,
EXISTS(SELECT 1 FROM installation_control_user_roles ir WHERE ir.control_user_id=u.id AND ir.role='owner'),
EXISTS(SELECT 1 FROM control_user_identities i JOIN auth_provider_configs p ON p.id=i.auth_provider_config_id
WHERE i.control_user_id=u.id AND p.disabled_at IS NULL AND p.control_login_enabled AND p.provider<>$1)
FROM control_users u WHERE u.status='active'`, excludedProvider)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform authentication safety could not be checked.")
		return false
	}
	defer rows.Close()
	affected := 0
	protected := false
	currentID := actor(r).ID
	for rows.Next() {
		var id string
		var hasPassword, owner, hasExternal bool
		if rows.Scan(&id, &hasPassword, &owner, &hasExternal) != nil {
			continue
		}
		usable := smtp && (policy.EmailCodeEnabled || policy.MagicLinkEnabled) || policy.PasswordEnabled && hasPassword || hasExternal
		if usable {
			continue
		}
		affected++
		if owner || id == currentID {
			protected = true
		}
	}
	if protected {
		writeControlAuthImpact(w, r, "control_auth_owner_lockout", "The change would leave the current Platform user or an installation owner without a usable sign-in method.", affected)
		return false
	}
	if affected > 0 && !confirmed {
		writeControlAuthImpact(w, r, "control_auth_confirmation_required", "The change would remove the final usable sign-in method from active Platform users. Confirm the affected users to continue.", affected)
		return false
	}
	return true
}

func writeControlAuthImpact(w http.ResponseWriter, r *http.Request, code, detail string, affected int) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "https://platform93.dev/problems/" + code, "title": "Platform authentication change rejected",
		"status": http.StatusConflict, "detail": detail, "code": code, "affected_users": affected,
		"request_id": kernel.RequestID(r.Context()),
	})
}
