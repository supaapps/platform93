package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) getInstallationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.getBillingProviderForScope(w, r, installationProviderScope())
}

func (s *Server) getOrganizationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.getBillingProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) getBillingProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, false) {
		return
	}
	var value []byte
	err := s.app.DB.QueryRow(r.Context(), `SELECT to_jsonb(pc)-'secret_ciphertext'-'webhook_secret_ciphertext' FROM provider_connections pc
WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid`,
		chi.URLParam(r, "provider_id"), scope.ApplicationID, scope.OrganizationID).Scan(&value)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_provider_not_found", "The billing provider was not found.")
		return
	}
	result, _ := decodeAny(value).(map[string]any)
	result["scope"] = scope.name()
	result["webhook_uri"] = s.app.PublicURL + "/provider-webhooks/stripe/" + stringValue(result["public_id"])
	kernel.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) updateInstallationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.updateBillingProviderForScope(w, r, installationProviderScope())
}

func (s *Server) updateOrganizationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.updateBillingProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) updateBillingProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	var request struct {
		Secret        string         `json:"secret,omitempty"`
		WebhookSecret string         `json:"webhook_secret,omitempty"`
		Metadata      map[string]any `json:"metadata,omitempty"`
		Inheritable   *bool          `json:"inheritable,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	providerID := chi.URLParam(r, "provider_id")
	var exists bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM provider_connections WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid)`, providerID, scope.ApplicationID, scope.OrganizationID).Scan(&exists)
	if !exists {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_provider_not_found", "The billing provider was not found.")
		return
	}
	var secretCiphertext, webhookCiphertext any
	var err error
	if request.Secret != "" {
		if !strings.HasPrefix(request.Secret, "sk_") {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_provider_secret", "A valid Stripe secret is required.")
			return
		}
		secretCiphertext, err = s.app.Vault.Encrypt([]byte(request.Secret), "billing-provider:"+providerID+":secret")
	}
	if err == nil && request.WebhookSecret != "" {
		if !strings.HasPrefix(request.WebhookSecret, "whsec_") {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_webhook_secret", "A valid Stripe webhook signing secret is required.")
			return
		}
		webhookCiphertext, err = s.app.Vault.Encrypt([]byte(request.WebhookSecret), "billing-provider:"+providerID+":webhook")
	}
	metadata, _ := json.Marshal(request.Metadata)
	credentialsChanged := request.Secret != "" || request.WebhookSecret != ""
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `UPDATE provider_connections SET secret_ciphertext=COALESCE($1,secret_ciphertext),webhook_secret_ciphertext=COALESCE($2,webhook_secret_ciphertext),
metadata=CASE WHEN $3::jsonb IS NULL THEN metadata ELSE $3 END,inheritable=CASE WHEN $4::boolean IS NULL THEN inheritable ELSE $4 END,
status=CASE WHEN $5 THEN 'active' ELSE status END,updated_at=now()
WHERE id=$6 AND application_id IS NOT DISTINCT FROM $7::uuid AND organization_id IS NOT DISTINCT FROM $8::uuid`, secretCiphertext, webhookCiphertext, nullableJSON(func() *map[string]any {
			if request.Metadata == nil {
				return nil
			}
			return &request.Metadata
		}(), metadata), request.Inheritable, credentialsChanged, providerID, scope.ApplicationID, scope.OrganizationID)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "billing_provider_update_failed", "The billing provider could not be updated.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) verifyInstallationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.verifyBillingProviderForScope(w, r, installationProviderScope())
}

func (s *Server) verifyOrganizationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.verifyBillingProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) verifyBillingProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	providerID := chi.URLParam(r, "provider_id")
	var ciphertext, version string
	err := s.app.DB.QueryRow(r.Context(), `SELECT secret_ciphertext,api_version FROM provider_connections WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid`, providerID, scope.ApplicationID, scope.OrganizationID).Scan(&ciphertext, &version)
	secret, decryptErr := s.app.Vault.Decrypt(ciphertext, "billing-provider:"+providerID+":secret")
	if err != nil || decryptErr != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_provider_not_found", "The billing provider was not found.")
		return
	}
	_, err = stripeRequest(r.Context(), http.MethodGet, "https://api.stripe.com/v1/balance", string(secret), version, "platform93-provider-verify-"+providerID, url.Values{})
	status := "active"
	if err != nil {
		status = "error"
	}
	_, _ = s.app.DB.Exec(r.Context(), `UPDATE provider_connections SET status=$1,updated_at=now() WHERE id=$2`, status, providerID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "billing_provider_verification_failed", "Stripe credentials could not be verified.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) disableInstallationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.disableBillingProviderForScope(w, r, installationProviderScope())
}

func (s *Server) disableOrganizationBillingProvider(w http.ResponseWriter, r *http.Request) {
	s.disableBillingProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) disableBillingProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE provider_connections pc SET status='disabled',updated_at=now()
WHERE pc.id=$1 AND pc.application_id IS NOT DISTINCT FROM $2::uuid AND pc.organization_id IS NOT DISTINCT FROM $3::uuid
AND NOT EXISTS(SELECT 1 FROM subscriptions s WHERE s.provider_connection_id=pc.id AND s.status IN ('active','trialing','past_due','paused'))`, chi.URLParam(r, "provider_id"), scope.ApplicationID, scope.OrganizationID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "billing_provider_in_use", "The provider was not found or still has active subscriptions.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
