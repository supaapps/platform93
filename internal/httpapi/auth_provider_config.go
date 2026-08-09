package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

type externalAuthProviderConfig struct {
	ID          string
	Provider    string
	ClientID    string
	Credentials map[string]string
	Scope       string
	Inheritable bool
}

func (s *Server) configureGoogleProvider(w http.ResponseWriter, r *http.Request) {
	s.configureAuthProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")), "google")
}

func (s *Server) configureAppleProvider(w http.ResponseWriter, r *http.Request) {
	s.configureAuthProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")), "apple")
}

func (s *Server) configureInstallationAuthProvider(w http.ResponseWriter, r *http.Request) {
	s.configureAuthProvider(w, r, installationProviderScope(), chi.URLParam(r, "provider"))
}

func (s *Server) configureOrganizationAuthProvider(w http.ResponseWriter, r *http.Request) {
	s.configureAuthProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")), chi.URLParam(r, "provider"))
}

func (s *Server) updateInstallationAuthProvider(w http.ResponseWriter, r *http.Request) {
	s.updateAuthProvider(w, r, installationProviderScope())
}

func (s *Server) updateOrganizationAuthProvider(w http.ResponseWriter, r *http.Request) {
	s.updateAuthProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) updateAuthProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	provider := chi.URLParam(r, "provider")
	if provider != "google" && provider != "apple" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "unsupported_auth_provider", "Authentication provider must be google or apple.")
		return
	}
	var request struct {
		Inheritable *bool `json:"inheritable"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Inheritable == nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "inheritance_required", "The inheritable boolean is required.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE auth_provider_configs SET inheritable=$1,updated_at=now()
WHERE provider=$2 AND application_id IS NULL AND organization_id IS NOT DISTINCT FROM $3::uuid AND disabled_at IS NULL`, *request.Inheritable, provider, scope.OrganizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "auth_provider_update_failed", "The authentication provider could not be updated.")
		return
	}
	if result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "auth_provider_not_found", "The authentication provider was not found at this scope.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) configureAuthProvider(w http.ResponseWriter, r *http.Request, scope providerScope, provider string) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	var request struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret,omitempty"`
		TeamID       string `json:"team_id,omitempty"`
		KeyID        string `json:"key_id,omitempty"`
		PrivateKey   string `json:"private_key_pem,omitempty"`
		Inheritable  bool   `json:"inheritable,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.ClientID = strings.TrimSpace(request.ClientID)
	credentials := map[string]string{}
	if provider == "google" {
		credentials["client_secret"] = strings.TrimSpace(request.ClientSecret)
	} else if provider == "apple" {
		credentials["team_id"] = strings.TrimSpace(request.TeamID)
		credentials["key_id"] = strings.TrimSpace(request.KeyID)
		credentials["private_key_pem"] = strings.TrimSpace(request.PrivateKey)
	} else {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "unsupported_auth_provider", "Authentication provider must be google or apple.")
		return
	}
	if request.ClientID == "" || provider == "google" && credentials["client_secret"] == "" || provider == "apple" && (credentials["team_id"] == "" || credentials["key_id"] == "" || credentials["private_key_pem"] == "") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_auth_provider", "The provider client identifier and credentials are required.")
		return
	}
	if provider == "apple" {
		if _, err := createAppleClientSecret(externalAuthProviderConfig{ClientID: request.ClientID, Credentials: credentials}, s.app.Now()); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_apple_private_key", "The Apple private key must be a valid ES256 PKCS#8 or EC private key.")
			return
		}
	}
	var id string
	_ = s.app.DB.QueryRow(r.Context(), `SELECT id FROM auth_provider_configs WHERE provider=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid AND disabled_at IS NULL`, provider, scope.ApplicationID, scope.OrganizationID).Scan(&id)
	if id == "" {
		id = kernel.NewID().String()
	}
	encoded, _ := json.Marshal(credentials)
	ciphertext, err := s.app.Vault.Encrypt(encoded, "auth-provider:"+id)
	if err == nil {
		result, updateErr := s.app.DB.Exec(r.Context(), `UPDATE auth_provider_configs SET client_id=$1,config_ciphertext=$2,inheritable=$3,updated_at=now()
WHERE id=$4`, request.ClientID, ciphertext, scope.inheritable(request.Inheritable), id)
		err = updateErr
		if err == nil && result.RowsAffected() == 0 {
			_, err = s.app.DB.Exec(r.Context(), `INSERT INTO auth_provider_configs(id,organization_id,application_id,provider,client_id,config_ciphertext,inheritable)
VALUES($1,$2,$3,$4,$5,$6,$7)`, id, scope.OrganizationID, scope.ApplicationID, provider, request.ClientID, ciphertext, scope.inheritable(request.Inheritable))
		}
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "auth_provider_configuration_failed", "The authentication provider could not be configured.")
		return
	}
	applicationID := "{application_id}"
	if scope.ApplicationID != nil {
		applicationID = *scope.ApplicationID
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "provider": provider, "client_id": request.ClientID, "configured": true,
		"scope": scope.name(), "inheritable": scope.inheritable(request.Inheritable), "callback_uri": s.externalAuthCallbackURI(applicationID, provider)})
}

func (s *Server) listAuthProviders(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	items := []map[string]any{}
	for _, provider := range []string{"google", "apple"} {
		if config, err := s.loadEffectiveAuthProvider(r.Context(), applicationID, provider); err == nil {
			items = append(items, authProviderResponse(config, s.externalAuthCallbackURI(applicationID, provider)))
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) listApplicationAuthProviders(w http.ResponseWriter, r *http.Request) {
	s.listAuthProviders(w, r)
}

func (s *Server) listInstallationAuthProviders(w http.ResponseWriter, r *http.Request) {
	s.listAuthProvidersForScope(w, r, installationProviderScope())
}

func (s *Server) listOrganizationAuthProviders(w http.ResponseWriter, r *http.Request) {
	s.listAuthProvidersForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) listAuthProvidersForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, false) {
		return
	}
	query := `SELECT id,provider,client_id,inheritable,created_at,updated_at,
CASE WHEN organization_id IS NOT NULL THEN 'organization' ELSE 'installation' END
FROM auth_provider_configs
WHERE application_id IS NULL AND organization_id IS NOT DISTINCT FROM $1::uuid AND disabled_at IS NULL ORDER BY provider`
	if scope.OrganizationID != nil {
		query = `SELECT id,provider,client_id,inheritable,created_at,updated_at,
CASE WHEN organization_id IS NOT NULL THEN 'organization' ELSE 'installation' END
FROM auth_provider_configs
WHERE application_id IS NULL AND disabled_at IS NULL AND (organization_id=$1 OR (organization_id IS NULL AND inheritable))
ORDER BY provider,organization_id NULLS LAST`
	}
	rows, err := s.app.DB.Query(r.Context(), query, scope.OrganizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Authentication providers could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, provider, clientID string
		var inheritable bool
		var createdAt, updatedAt time.Time
		var providerScope string
		if rows.Scan(&id, &provider, &clientID, &inheritable, &createdAt, &updatedAt, &providerScope) == nil {
			items = append(items, map[string]any{"id": id, "provider": provider, "client_id": clientID, "scope": providerScope, "inheritable": inheritable, "inherited": providerScope != scope.name(), "configured": true, "callback_uri": s.externalAuthCallbackURI("{application_id}", provider), "created_at": createdAt, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) disableInstallationAuthProvider(w http.ResponseWriter, r *http.Request) {
	s.disableAuthProvider(w, r, installationProviderScope())
}

func (s *Server) disableOrganizationAuthProvider(w http.ResponseWriter, r *http.Request) {
	s.disableAuthProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) disableApplicationAuthProvider(w http.ResponseWriter, r *http.Request) {
	s.disableAuthProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) disableAuthProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE auth_provider_configs SET disabled_at=now(),updated_at=now()
WHERE provider=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid AND disabled_at IS NULL`, chi.URLParam(r, "provider"), scope.ApplicationID, scope.OrganizationID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "auth_provider_not_found", "The authentication provider was not found at this scope.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadEffectiveAuthProvider(ctx context.Context, applicationID, provider string) (externalAuthProviderConfig, error) {
	var value externalAuthProviderConfig
	var ciphertext string
	err := s.app.DB.QueryRow(ctx, `SELECT ap.id,ap.provider,ap.client_id,ap.config_ciphertext,ap.inheritable,
CASE WHEN ap.application_id IS NOT NULL THEN 'application' WHEN ap.organization_id IS NOT NULL THEN 'organization' ELSE 'installation' END
FROM auth_provider_configs ap JOIN applications a ON a.id=$1
WHERE ap.provider=$2 AND ap.disabled_at IS NULL AND (ap.application_id=$1 OR
(ap.application_id IS NULL AND ap.organization_id=a.organization_id AND ap.inheritable) OR
(ap.application_id IS NULL AND ap.organization_id IS NULL AND ap.inheritable))
ORDER BY CASE WHEN ap.application_id IS NOT NULL THEN 0 WHEN ap.organization_id IS NOT NULL THEN 1 ELSE 2 END LIMIT 1`, applicationID, provider).
		Scan(&value.ID, &value.Provider, &value.ClientID, &ciphertext, &value.Inheritable, &value.Scope)
	if err != nil && provider == "google" {
		var metadata []byte
		err = s.app.DB.QueryRow(ctx, `SELECT id,metadata,ciphertext FROM application_secrets WHERE application_id=$1 AND kind='auth_provider' AND name='google'`, applicationID).Scan(&value.ID, &metadata, &ciphertext)
		var decoded struct {
			ClientID string `json:"client_id"`
		}
		_ = json.Unmarshal(metadata, &decoded)
		value.Provider, value.ClientID, value.Scope = "google", decoded.ClientID, "application"
		if err == nil {
			secret, decryptErr := s.app.Vault.Decrypt(ciphertext, "application-secret:"+value.ID)
			if decryptErr == nil {
				value.Credentials = map[string]string{"client_secret": string(secret)}
				return value, nil
			}
			err = decryptErr
		}
	}
	if err != nil {
		return externalAuthProviderConfig{}, err
	}
	plaintext, err := s.app.Vault.Decrypt(ciphertext, "auth-provider:"+value.ID)
	if err != nil || json.Unmarshal(plaintext, &value.Credentials) != nil {
		return externalAuthProviderConfig{}, fmt.Errorf("%s provider unavailable", provider)
	}
	return value, nil
}

func authProviderResponse(config externalAuthProviderConfig, callbackURI string) map[string]any {
	return map[string]any{"id": config.ID, "provider": config.Provider, "client_id": config.ClientID, "configured": true, "scope": config.Scope,
		"inheritable": config.Inheritable, "inherited": config.Scope != "application", "callback_uri": callbackURI}
}

func (s *Server) externalAuthCallbackURI(applicationID, provider string) string {
	return s.app.PublicURL + "/v1/applications/" + applicationID + "/auth/providers/" + provider + "/callback"
}
