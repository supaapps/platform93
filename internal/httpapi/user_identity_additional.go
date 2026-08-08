package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) authMethods(w http.ResponseWriter, r *http.Request) {
	methods := []string{}
	if s.authFlag(r, "password_enabled") {
		methods = append(methods, "password")
	}
	if s.authFlag(r, "passwordless_enabled") {
		methods = append(methods, "email_code", "magic_link")
	}
	if _, err := s.loadEffectiveAuthProvider(r.Context(), chi.URLParam(r, "application_id"), "google"); err == nil {
		methods = append(methods, "google")
	}
	if _, err := s.loadEffectiveAuthProvider(r.Context(), chi.URLParam(r, "application_id"), "apple"); err == nil {
		methods = append(methods, "apple")
	}
	// Deliberately independent of the supplied email to prevent account discovery.
	config, _ := s.internalApplicationConfig(r)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"methods": methods, "registration_enabled": config.RegistrationMode == "public", "registration_mode": config.RegistrationMode})
}

func (s *Server) logoutCurrentSession(w http.ResponseWriter, r *http.Request) {
	current := actor(r)
	if current.Type != "user" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "session_required", "Logout requires an interactive user session.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE id=$1 AND application_id=$2 AND user_id=$3`, current.SessionID, chi.URLParam(r, "application_id"), current.ID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "inactive_user_session", "The user session is no longer active.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateAddress(w http.ResponseWriter, r *http.Request) {
	subjectType, subjectID, ok := s.addressSubject(w, r)
	if !ok {
		return
	}
	var request struct {
		Name        *string `json:"name,omitempty"`
		Line1       *string `json:"line1,omitempty"`
		Line2       *string `json:"line2,omitempty"`
		City        *string `json:"city,omitempty"`
		Region      *string `json:"region,omitempty"`
		PostalCode  *string `json:"postal_code,omitempty"`
		CountryCode *string `json:"country_code,omitempty"`
		TaxID       *string `json:"tax_id,omitempty"`
		Version     int64   `json:"version"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Version < 1 || request.Line1 != nil && strings.TrimSpace(*request.Line1) == "" ||
		request.City != nil && strings.TrimSpace(*request.City) == "" || request.PostalCode != nil && strings.TrimSpace(*request.PostalCode) == "" ||
		request.CountryCode != nil && len(strings.TrimSpace(*request.CountryCode)) != 2 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_address", "Address fields and the current version are required to be valid.")
		return
	}
	profileID, err := s.ensureBillingProfile(r.Context(), s.app.DB, chi.URLParam(r, "application_id"), subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_profile_not_found", "The billing profile was not found.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The address could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE addresses SET name=COALESCE($1,name),line1=COALESCE($2,line1),
line2=COALESCE($3,line2),city=COALESCE($4,city),region=COALESCE($5,region),postal_code=COALESCE($6,postal_code),
country_code=upper(COALESCE($7,country_code)),version=version+1,updated_at=now()
WHERE id=$8 AND application_id=$9 AND billing_profile_id=$10 AND version=$11`,
		request.Name, request.Line1, request.Line2, request.City, request.Region, request.PostalCode, request.CountryCode,
		chi.URLParam(r, "address_id"), chi.URLParam(r, "application_id"), profileID, request.Version)
	if err == nil && result.RowsAffected() == 1 && request.TaxID != nil {
		_, err = tx.Exec(r.Context(), `UPDATE billing_profiles SET tax_id=NULLIF(trim($1),''),version=version+1,updated_at=now() WHERE id=$2`, request.TaxID, profileID)
	}
	if err != nil || result.RowsAffected() != 1 || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "address_version_conflict", "The address was not found or its version has changed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) activateAddress(w http.ResponseWriter, r *http.Request) {
	subjectType, subjectID, ok := s.addressSubject(w, r)
	if !ok {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The address could not be activated.")
		return
	}
	defer rollback(tx, r.Context())
	profileID, err := s.ensureBillingProfile(r.Context(), tx, chi.URLParam(r, "application_id"), subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_profile_not_found", "The billing profile was not found.")
		return
	}
	var exists bool
	err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM addresses
WHERE id=$1 AND application_id=$2 AND billing_profile_id=$3)`, chi.URLParam(r, "address_id"), chi.URLParam(r, "application_id"), profileID).Scan(&exists)
	if err != nil || !exists {
		kernel.WriteProblem(w, r, http.StatusNotFound, "address_not_found", "The address was not found.")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE addresses SET is_active=false,version=version+1,updated_at=now()
WHERE application_id=$1 AND billing_profile_id=$2 AND is_active AND id<>$3`, chi.URLParam(r, "application_id"), profileID, chi.URLParam(r, "address_id"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE addresses SET is_active=true,version=version+1,updated_at=now()
WHERE id=$1 AND application_id=$2 AND billing_profile_id=$3 AND NOT is_active`, chi.URLParam(r, "address_id"), chi.URLParam(r, "application_id"), profileID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "address_activation_failed", "The address could not be activated.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteAddress(w http.ResponseWriter, r *http.Request) {
	subjectType, subjectID, ok := s.addressSubject(w, r)
	if !ok {
		return
	}
	profileID, err := s.ensureBillingProfile(r.Context(), s.app.DB, chi.URLParam(r, "application_id"), subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_profile_not_found", "The billing profile was not found.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `DELETE FROM addresses
WHERE id=$1 AND application_id=$2 AND billing_profile_id=$3 AND NOT is_active`, chi.URLParam(r, "address_id"),
		chi.URLParam(r, "application_id"), profileID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "address_in_use_or_not_found", "Only an inactive address owned by the current user can be deleted.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
