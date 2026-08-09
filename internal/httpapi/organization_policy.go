package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

const (
	settingPublicRegistration            = "public_registration"
	settingPasswordAuthentication        = "password_authentication"
	settingPasswordlessAuthentication    = "passwordless_authentication"
	settingPersonalAPIKeys               = "personal_api_keys"
	settingDelegation                    = "delegation"
	settingOrganizationProviderOverrides = "organization_provider_overrides"
	settingApplicationProviderOverrides  = "application_provider_overrides"
	settingCustomEvents                  = "custom_events"
	settingWebhooks                      = "webhooks"
)

var organizationSettingKeys = []string{
	settingPublicRegistration, settingPasswordAuthentication, settingPasswordlessAuthentication,
	settingPersonalAPIKeys, settingDelegation, settingOrganizationProviderOverrides,
	settingApplicationProviderOverrides, settingCustomEvents, settingWebhooks,
}

type organizationPolicy struct {
	OrganizationID  string          `json:"organization_id"`
	MaxApplications *int            `json:"max_applications"`
	MaxUsers        *int            `json:"max_users"`
	EnabledSettings map[string]bool `json:"enabled_settings"`
	Version         int64           `json:"version"`
}

func defaultOrganizationSettings() map[string]bool {
	settings := make(map[string]bool, len(organizationSettingKeys))
	for _, key := range organizationSettingKeys {
		settings[key] = true
	}
	return settings
}

func scanOrganizationPolicy(row pgx.Row) (organizationPolicy, error) {
	var policy organizationPolicy
	var raw []byte
	err := row.Scan(&policy.OrganizationID, &policy.MaxApplications, &policy.MaxUsers, &raw, &policy.Version)
	policy.EnabledSettings = defaultOrganizationSettings()
	if err == nil {
		_ = json.Unmarshal(raw, &policy.EnabledSettings)
	}
	return policy, err
}

func (s *Server) loadOrganizationPolicy(ctx context.Context, organizationID string) (organizationPolicy, error) {
	return scanOrganizationPolicy(s.app.DB.QueryRow(ctx, `SELECT organization_id,max_applications,max_users,enabled_settings,version
FROM organization_policies WHERE organization_id=$1`, organizationID))
}

func (s *Server) organizationPolicyForApplication(ctx context.Context, applicationID string) (organizationPolicy, error) {
	return scanOrganizationPolicy(s.app.DB.QueryRow(ctx, `SELECT p.organization_id,p.max_applications,p.max_users,p.enabled_settings,p.version
FROM organization_policies p JOIN applications a ON a.organization_id=p.organization_id WHERE a.id=$1`, applicationID))
}

func (s *Server) organizationSettingEnabled(ctx context.Context, applicationID, setting string) bool {
	policy, err := s.organizationPolicyForApplication(ctx, applicationID)
	return err == nil && policy.EnabledSettings[setting]
}

func (s *Server) requireOrganizationSetting(w http.ResponseWriter, r *http.Request, setting string) bool {
	if s.organizationSettingEnabled(r.Context(), chi.URLParam(r, "application_id"), setting) {
		return true
	}
	kernel.WriteProblem(w, r, http.StatusForbidden, "organization_setting_disabled", "This capability is disabled by the installation-managed organization policy.")
	return false
}

func (s *Server) getOrganizationPolicy(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if actor(r).Type != "management_client" && !s.operatorBelongsToOrganization(r, organizationID) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
		return
	}
	policy, err := s.loadOrganizationPolicy(r.Context(), organizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_policy_not_found", "The organization policy was not found.")
		return
	}
	var applications, users int64
	_ = s.app.DB.QueryRow(r.Context(), `SELECT
(SELECT count(*) FROM applications WHERE organization_id=$1 AND deleted_at IS NULL),
(SELECT count(*) FROM users u JOIN applications a ON a.id=u.application_id WHERE a.organization_id=$1 AND u.status<>'deleted')`, organizationID).Scan(&applications, &users)
	w.Header().Set("ETag", kernel.ETag(policy.Version))
	kernel.WriteJSON(w, http.StatusOK, map[string]any{
		"organization_id": policy.OrganizationID, "max_applications": policy.MaxApplications, "max_users": policy.MaxUsers,
		"enabled_settings": policy.EnabledSettings, "version": policy.Version,
		"usage": map[string]int64{"applications": applications, "users": users},
	})
}

func (s *Server) updateOrganizationPolicy(w http.ResponseWriter, r *http.Request) {
	if actor(r).Type != "management_client" {
		role, ok := s.installationRole(r)
		if !ok || role != "owner" && role != "admin" {
			kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner, administrator, or management client is required.")
			return
		}
	}
	var request struct {
		MaxApplications *int            `json:"max_applications"`
		MaxUsers        *int            `json:"max_users"`
		EnabledSettings map[string]bool `json:"enabled_settings"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.MaxApplications != nil && *request.MaxApplications < 0 || request.MaxUsers != nil && *request.MaxUsers < 0 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_organization_limits", "Organization limits must be null or non-negative integers.")
		return
	}
	settings := defaultOrganizationSettings()
	for key, value := range request.EnabledSettings {
		known := false
		for _, allowed := range organizationSettingKeys {
			known = known || key == allowed
		}
		if !known {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_organization_setting", "The organization policy contains an unknown setting: "+key)
			return
		}
		settings[key] = value
	}
	organizationID := chi.URLParam(r, "organization_id")
	current, err := s.loadOrganizationPolicy(r.Context(), organizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_policy_not_found", "The organization policy was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, current.Version) {
		return
	}
	encoded, _ := json.Marshal(settings)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The organization policy could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE organization_policies SET max_applications=$1,max_users=$2,enabled_settings=$3,
version=version+1,updated_at=now() WHERE organization_id=$4 AND version=$5`, request.MaxApplications, request.MaxUsers, encoded, organizationID, current.Version)
	if err == nil && result.RowsAffected() != 1 {
		err = pgx.ErrNoRows
	}
	if err == nil {
		err = applyOrganizationPolicyRestrictions(r.Context(), tx, organizationID, settings)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "organization_policy_conflict", "The organization policy changed concurrently or could not be applied.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(current.Version+1))
	w.WriteHeader(http.StatusNoContent)
}

func applyOrganizationPolicyRestrictions(ctx context.Context, tx pgx.Tx, organizationID string, settings map[string]bool) error {
	rows, err := tx.Query(ctx, `SELECT id,internal_config FROM applications WHERE organization_id=$1 AND deleted_at IS NULL FOR UPDATE`, organizationID)
	if err != nil {
		return err
	}
	type applicationConfig struct {
		id     string
		config applicationInternalConfig
	}
	applications := []applicationConfig{}
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		config := defaultApplicationInternalConfig()
		if err = json.Unmarshal(raw, &config); err != nil {
			rows.Close()
			return err
		}
		if !settings[settingPublicRegistration] {
			config.RegistrationMode = "invite_only"
		}
		config.PasswordEnabled = config.PasswordEnabled && settings[settingPasswordAuthentication]
		config.PasswordlessEnabled = config.PasswordlessEnabled && settings[settingPasswordlessAuthentication]
		config.PersonalAPIKeysEnabled = config.PersonalAPIKeysEnabled && settings[settingPersonalAPIKeys]
		config.DelegationEnabled = config.DelegationEnabled && settings[settingDelegation]
		applications = append(applications, applicationConfig{id: id, config: config})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, application := range applications {
		raw, _ := json.Marshal(application.config)
		if _, err = tx.Exec(ctx, `UPDATE applications SET internal_config=$1,version=version+1,updated_at=now() WHERE id=$2`, raw, application.id); err != nil {
			return err
		}
	}
	if !settings[settingPersonalAPIKeys] {
		_, err = tx.Exec(ctx, `UPDATE personal_api_keys k SET revoked_at=COALESCE(k.revoked_at,now())
FROM applications a WHERE a.id=k.application_id AND a.organization_id=$1 AND k.revoked_at IS NULL`, organizationID)
	}
	if err == nil && !settings[settingDelegation] {
		_, err = tx.Exec(ctx, `UPDATE delegations d SET revoked_at=COALESCE(d.revoked_at,now())
FROM applications a WHERE a.id=d.application_id AND a.organization_id=$1 AND d.revoked_at IS NULL`, organizationID)
	}
	if err == nil && !settings[settingDelegation] {
		_, err = tx.Exec(ctx, `UPDATE user_sessions s SET revoked_at=COALESCE(s.revoked_at,now())
FROM applications a WHERE a.id=s.application_id AND a.organization_id=$1 AND s.delegation_id IS NOT NULL AND s.revoked_at IS NULL`, organizationID)
	}
	if err == nil && !settings[settingWebhooks] {
		_, err = tx.Exec(ctx, `UPDATE webhook_endpoints w SET disabled_at=COALESCE(w.disabled_at,now()),version=version+1
FROM applications a WHERE a.id=w.application_id AND a.organization_id=$1 AND w.disabled_at IS NULL`, organizationID)
	}
	return err
}

func enforceApplicationLimit(ctx context.Context, tx pgx.Tx, organizationID string) error {
	var limit *int
	if err := tx.QueryRow(ctx, `SELECT max_applications FROM organization_policies WHERE organization_id=$1 FOR UPDATE`, organizationID).Scan(&limit); err != nil {
		return err
	}
	if limit == nil {
		return nil
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM applications WHERE organization_id=$1 AND deleted_at IS NULL`, organizationID).Scan(&count); err != nil {
		return err
	}
	if count >= *limit {
		return organizationLimitError{"applications", *limit}
	}
	return nil
}

func enforceUserLimit(ctx context.Context, tx pgx.Tx, applicationID string) error {
	var organizationID string
	var limit *int
	if err := tx.QueryRow(ctx, `SELECT p.organization_id,p.max_users FROM organization_policies p
JOIN applications a ON a.organization_id=p.organization_id WHERE a.id=$1 FOR UPDATE OF p`, applicationID).Scan(&organizationID, &limit); err != nil {
		return err
	}
	if limit == nil {
		return nil
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users u JOIN applications a ON a.id=u.application_id
WHERE a.organization_id=$1 AND u.status<>'deleted'`, organizationID).Scan(&count); err != nil {
		return err
	}
	if count >= *limit {
		return organizationLimitError{"users", *limit}
	}
	return nil
}

type organizationLimitError struct {
	resource string
	limit    int
}

func (e organizationLimitError) Error() string {
	return "organization " + e.resource + " limit reached"
}
