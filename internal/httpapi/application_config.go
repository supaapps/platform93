package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/supaapps/platform93/internal/kernel"
)

type applicationInternalConfig struct {
	RegistrationMode       string `json:"registration_mode"`
	PasswordEnabled        bool   `json:"password_enabled"`
	PasswordlessEnabled    bool   `json:"passwordless_enabled"`
	PersonalAPIKeysEnabled bool   `json:"personal_api_keys_enabled"`
	DelegationEnabled      bool   `json:"delegation_enabled"`
}

func defaultApplicationInternalConfig() applicationInternalConfig {
	return applicationInternalConfig{
		RegistrationMode:    "public",
		PasswordEnabled:     true,
		PasswordlessEnabled: true,
	}
}

func loadApplicationInternalConfig(ctx context.Context, queryer *pgxpool.Pool, applicationID string) (applicationInternalConfig, error) {
	var raw []byte
	if err := queryer.QueryRow(ctx, "SELECT internal_config FROM applications WHERE id=$1 AND deleted_at IS NULL", applicationID).Scan(&raw); err != nil {
		return applicationInternalConfig{}, err
	}
	config := defaultApplicationInternalConfig()
	if err := json.Unmarshal(raw, &config); err != nil {
		return applicationInternalConfig{}, err
	}
	return config, nil
}

func (s *Server) updatePublicApplicationConfig(w http.ResponseWriter, r *http.Request) {
	var config map[string]any
	if !kernel.DecodeJSON(w, r, &config) {
		return
	}
	if config == nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_public_config", "Public configuration must be a JSON object.")
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	var version int64
	if err := s.app.DB.QueryRow(r.Context(), "SELECT version FROM applications WHERE id=$1 AND deleted_at IS NULL", applicationID).Scan(&version); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	encoded, _ := json.Marshal(config)
	result, err := s.app.DB.Exec(r.Context(), `UPDATE applications SET public_config=$1,version=version+1,updated_at=now()
WHERE id=$2 AND version=$3 AND deleted_at IS NULL`, encoded, applicationID, version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "application_version_conflict", "The application changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateInternalApplicationConfig(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if !kernel.DecodeJSON(w, r, &raw) {
		return
	}
	allowed := map[string]bool{
		"registration_mode": true, "password_enabled": true, "passwordless_enabled": true,
		"personal_api_keys_enabled": true, "delegation_enabled": true,
	}
	for key := range raw {
		if !allowed[key] {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_internal_config", "The internal application configuration contains an unknown setting.")
			return
		}
	}
	applicationID := chi.URLParam(r, "application_id")
	var currentRaw []byte
	var version int64
	if err := s.app.DB.QueryRow(r.Context(), "SELECT internal_config,version FROM applications WHERE id=$1 AND deleted_at IS NULL", applicationID).Scan(&currentRaw, &version); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	current := defaultApplicationInternalConfig()
	if json.Unmarshal(currentRaw, &current) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invalid_stored_config", "The stored application configuration is invalid.")
		return
	}
	previousDelegationEnabled := current.DelegationEnabled
	previousPersonalAPIKeysEnabled := current.PersonalAPIKeysEnabled
	for key, value := range raw {
		switch key {
		case "registration_mode":
			if json.Unmarshal(value, &current.RegistrationMode) != nil || current.RegistrationMode != "public" && current.RegistrationMode != "invite_only" {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_registration_mode", "Registration mode must be public or invite_only.")
				return
			}
		case "password_enabled":
			if json.Unmarshal(value, &current.PasswordEnabled) != nil {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_internal_config", "password_enabled must be boolean.")
				return
			}
		case "passwordless_enabled":
			if json.Unmarshal(value, &current.PasswordlessEnabled) != nil {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_internal_config", "passwordless_enabled must be boolean.")
				return
			}
		case "personal_api_keys_enabled":
			if json.Unmarshal(value, &current.PersonalAPIKeysEnabled) != nil {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_internal_config", "personal_api_keys_enabled must be boolean.")
				return
			}
		case "delegation_enabled":
			if json.Unmarshal(value, &current.DelegationEnabled) != nil {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_internal_config", "delegation_enabled must be boolean.")
				return
			}
		}
	}
	policy, policyErr := s.organizationPolicyForApplication(r.Context(), applicationID)
	if policyErr != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "organization_policy_unavailable", "The organization policy could not be loaded.")
		return
	}
	if current.RegistrationMode == "public" && !policy.EnabledSettings[settingPublicRegistration] ||
		current.PasswordEnabled && !policy.EnabledSettings[settingPasswordAuthentication] ||
		current.PasswordlessEnabled && !policy.EnabledSettings[settingPasswordlessAuthentication] ||
		current.PersonalAPIKeysEnabled && !policy.EnabledSettings[settingPersonalAPIKeys] ||
		current.DelegationEnabled && !policy.EnabledSettings[settingDelegation] {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_setting_disabled", "The installation-managed organization policy does not allow one or more requested application settings.")
		return
	}
	encoded, _ := json.Marshal(current)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The application configuration could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE applications SET internal_config=$1,version=version+1,updated_at=now()
WHERE id=$2 AND version=$3 AND deleted_at IS NULL`, encoded, applicationID, version)
	if err == nil && result.RowsAffected() != 1 {
		err = pgx.ErrNoRows
	}
	if err == nil && previousDelegationEnabled && !current.DelegationEnabled {
		_, err = tx.Exec(r.Context(), `UPDATE delegations SET revoked_at=COALESCE(revoked_at,now()) WHERE application_id=$1 AND revoked_at IS NULL`, applicationID)
	}
	if err == nil && previousDelegationEnabled && !current.DelegationEnabled {
		_, err = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE application_id=$1 AND delegation_id IS NOT NULL AND revoked_at IS NULL`, applicationID)
	}
	if err == nil && previousPersonalAPIKeysEnabled && !current.PersonalAPIKeysEnabled {
		_, err = tx.Exec(r.Context(), `UPDATE personal_api_keys SET revoked_at=COALESCE(revoked_at,now())
WHERE application_id=$1 AND revoked_at IS NULL`, applicationID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "application_version_conflict", "The application changed concurrently or the policy could not be applied.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) internalApplicationConfig(r *http.Request) (applicationInternalConfig, error) {
	return loadApplicationInternalConfig(r.Context(), s.app.DB, chi.URLParam(r, "application_id"))
}

func (s *Server) registrationEnabled(r *http.Request) bool {
	config, err := s.internalApplicationConfig(r)
	return err == nil && config.RegistrationMode == "public" && s.organizationSettingEnabled(r.Context(), chi.URLParam(r, "application_id"), settingPublicRegistration)
}

func (s *Server) delegationEnabled(r *http.Request) bool {
	config, err := s.internalApplicationConfig(r)
	return err == nil && config.DelegationEnabled && s.organizationSettingEnabled(r.Context(), chi.URLParam(r, "application_id"), settingDelegation)
}
