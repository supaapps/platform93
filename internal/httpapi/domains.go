package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) createApplicationDomain(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Hostname string `json:"hostname"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	hostname := normalizeHostname(request.Hostname)
	if !validDomainHostname(hostname) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_domain", "A valid DNS hostname is required.")
		return
	}
	id := kernel.NewID()
	token, err := secure.RandomToken("p93_domain_", 24)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "domain_creation_failed", "The domain verification token could not be generated.")
		return
	}
	ciphertext, err := s.app.Vault.Encrypt([]byte(token), "domain:"+id.String())
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO application_domains
(id,application_id,hostname,verification_ciphertext) VALUES ($1,$2,$3,$4)`, id, chi.URLParam(r, "application_id"), hostname, ciphertext)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "domain_conflict", "The domain already exists or could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "hostname": hostname, "verified": false,
		"dns_name": "_platform93." + hostname, "dns_type": "TXT", "dns_value": "platform93-verification=" + token})
}

func (s *Server) listApplicationDomains(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,hostname,verified_at,created_at FROM application_domains
WHERE application_id=$1 ORDER BY created_at,id`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Domains could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, hostname string
		var verifiedAt *time.Time
		var createdAt time.Time
		if rows.Scan(&id, &hostname, &verifiedAt, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "hostname": hostname, "origin": "https://" + hostname,
				"verified": verifiedAt != nil, "verified_at": verifiedAt, "created_at": createdAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) verifyApplicationDomain(w http.ResponseWriter, r *http.Request) {
	var hostname, ciphertext string
	err := s.app.DB.QueryRow(r.Context(), `SELECT hostname,verification_ciphertext FROM application_domains
WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "domain_id"), chi.URLParam(r, "application_id")).Scan(&hostname, &ciphertext)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "domain_not_found", "The domain was not found.")
		return
	}
	token, err := s.app.Vault.Decrypt(ciphertext, "domain:"+chi.URLParam(r, "domain_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "domain_verification_failed", "The domain verification state could not be read.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	records, err := net.DefaultResolver.LookupTXT(ctx, "_platform93."+hostname)
	wanted := "platform93-verification=" + string(token)
	verified := false
	for _, record := range records {
		if strings.TrimSpace(record) == wanted {
			verified = true
			break
		}
	}
	if err != nil || !verified {
		kernel.WriteProblem(w, r, http.StatusConflict, "domain_verification_pending", "The expected DNS TXT record was not found.")
		return
	}
	_, err = s.app.DB.Exec(r.Context(), `UPDATE application_domains SET verified_at=COALESCE(verified_at,now())
WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "domain_id"), chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "domain_verification_failed", "The verified domain could not be saved.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteApplicationDomain(w http.ResponseWriter, r *http.Request) {
	var inUse bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM application_domains d JOIN user_authentication_methods m
ON m.application_id=d.application_id AND m.webauthn_rp_id=d.hostname AND m.method_type='webauthn' AND m.status='active'
WHERE d.id=$1 AND d.application_id=$2)`, chi.URLParam(r, "domain_id"), chi.URLParam(r, "application_id")).Scan(&inUse)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The domain usage could not be checked.")
		return
	}
	if inUse {
		kernel.WriteProblem(w, r, http.StatusConflict, "domain_in_use", "Disable passkeys registered for this domain before removing it.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `DELETE FROM application_domains WHERE id=$1 AND application_id=$2`,
		chi.URLParam(r, "domain_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "domain_not_found", "The domain was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func normalizeHostname(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	return strings.TrimSuffix(value, ".")
}

func validDomainHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 || net.ParseIP(hostname) != nil || strings.Contains(hostname, "*") {
		return false
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}
