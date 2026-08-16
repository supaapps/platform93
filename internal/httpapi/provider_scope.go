package httpapi

import (
	"net/http"

	"github.com/supaapps/platform93/internal/kernel"
)

type providerScope struct {
	OrganizationID *string
	ApplicationID  *string
}

func installationProviderScope() providerScope { return providerScope{} }

func organizationProviderScope(id string) providerScope {
	return providerScope{OrganizationID: &id}
}

func applicationProviderScope(id string) providerScope {
	return providerScope{ApplicationID: &id}
}

func (scope providerScope) name() string {
	if scope.ApplicationID != nil {
		return "application"
	}
	if scope.OrganizationID != nil {
		return "organization"
	}
	return "installation"
}

func (scope providerScope) inheritable(requested bool) bool {
	return scope.ApplicationID == nil && requested
}

func (s *Server) authorizeProviderScope(w http.ResponseWriter, r *http.Request, scope providerScope, write bool) bool {
	if scope.ApplicationID != nil {
		var organizationID string
		if err := s.app.DB.QueryRow(r.Context(), "SELECT organization_id FROM applications WHERE id=$1 AND deleted_at IS NULL", *scope.ApplicationID).Scan(&organizationID); err != nil {
			kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
			return false
		}
		if write {
			if _, allowed := s.organizationManagementRole(r, organizationID); !allowed {
				kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "An organization owner or administrator is required to manage application providers.")
				return false
			}
		} else if !s.controlUserBelongsToOrganization(r, organizationID) {
			kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
			return false
		}
		if write && !s.organizationSettingEnabled(r.Context(), *scope.ApplicationID, settingApplicationProviderOverrides) {
			kernel.WriteProblem(w, r, http.StatusForbidden, "organization_setting_disabled", "Application-level provider overrides are disabled by the organization policy.")
			return false
		}
		return true
	}
	if scope.OrganizationID != nil {
		if write {
			var enabled bool
			_ = s.app.DB.QueryRow(r.Context(), `SELECT COALESCE((enabled_settings->>'organization_provider_overrides')::boolean,true)
FROM organization_policies WHERE organization_id=$1`, *scope.OrganizationID).Scan(&enabled)
			if !enabled {
				kernel.WriteProblem(w, r, http.StatusForbidden, "organization_setting_disabled", "Organization-level provider overrides are disabled by the installation policy.")
				return false
			}
			if _, allowed := s.organizationManagementRole(r, *scope.OrganizationID); allowed {
				return true
			}
			kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "An organization owner or administrator is required to manage providers.")
			return false
		}
		if s.controlUserBelongsToOrganization(r, *scope.OrganizationID) {
			return true
		}
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
		return false
	}
	role, allowed := s.installationRole(r)
	if allowed && (!write || role == "owner" || role == "admin") {
		return true
	}
	kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "An installation owner or administrator is required to manage installation providers.")
	return false
}
