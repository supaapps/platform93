package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

type smtpProviderRequest struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLSMode     string `json:"tls_mode"`
	SenderEmail string `json:"sender_email"`
	SenderName  string `json:"sender_name"`
	Inheritable bool   `json:"inheritable"`
}

func (s *Server) createNotificationProvider(w http.ResponseWriter, r *http.Request) {
	var request smtpProviderRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	application := chi.URLParam(r, "application_id")
	s.storeSMTPProvider(w, r, request, applicationProviderScope(application))
}

func (s *Server) createInstallationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	var request smtpProviderRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	s.storeSMTPProvider(w, r, request, installationProviderScope())
}

func (s *Server) createOrganizationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	var request smtpProviderRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	s.storeSMTPProvider(w, r, request, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) storeSMTPProvider(w http.ResponseWriter, r *http.Request, request smtpProviderRequest, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	request.Host = strings.TrimSpace(request.Host)
	request.SenderEmail = kernel.NormalizeEmail(request.SenderEmail)
	if request.Name == "" || request.Host == "" || request.Port < 1 || request.Port > 65535 || !strings.Contains(request.SenderEmail, "@") || strings.ContainsAny(request.SenderEmail, "\r\n") || (request.TLSMode != "starttls" && request.TLSMode != "implicit_tls") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_smtp_provider", "Name, host, port, sender email, and a TLS mode are required.")
		return
	}
	id := kernel.NewID()
	config, _ := json.Marshal(map[string]any{"host": request.Host, "port": request.Port, "username": request.Username, "password": request.Password, "tls_mode": request.TLSMode})
	ciphertext, err := s.app.Vault.Encrypt(config, "notification-provider:"+id.String())
	var tx pgx.Tx
	if err == nil {
		tx, err = s.app.DB.Begin(r.Context())
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO notification_providers
(id,application_id,organization_id,provider,name,config_ciphertext,sender_email,sender_name,inheritable) VALUES ($1,$2,$3,'smtp',$4,$5,$6,$7,$8)`,
			id, scope.ApplicationID, scope.OrganizationID, request.Name, ciphertext, request.SenderEmail, request.SenderName, scope.inheritable(request.Inheritable))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO sender_identities
(id,application_id,organization_id,notification_provider_id,email,name,is_default) VALUES($1,$2,$3,$4,$5,$6,true)`,
			kernel.NewID(), scope.ApplicationID, scope.OrganizationID, id, request.SenderEmail, request.SenderName)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "notification_provider_creation_failed", "The SMTP provider could not be stored.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "provider": "smtp", "name": request.Name, "sender_email": request.SenderEmail, "sender_name": request.SenderName, "verified": false, "scope": scope.name(), "inheritable": scope.inheritable(request.Inheritable)})
}

func (s *Server) listInstallationNotificationProviders(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), false) {
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,provider,name,sender_email,sender_name,verified_at,disabled_at,created_at,inheritable,'installation'
FROM notification_providers WHERE application_id IS NULL AND organization_id IS NULL ORDER BY created_at,id`)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Installation notification providers could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, provider, name, senderEmail, senderName string
		var created time.Time
		var inheritable bool
		var scope string
		var verified, disabled *time.Time
		if rows.Scan(&id, &provider, &name, &senderEmail, &senderName, &verified, &disabled, &created, &inheritable, &scope) == nil {
			items = append(items, map[string]any{"id": id, "provider": provider, "name": name, "sender_email": senderEmail, "sender_name": senderName, "verified_at": verified, "disabled_at": disabled, "created_at": created, "inheritable": inheritable, "scope": scope})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) listNotificationProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT np.id,np.provider,np.name,np.sender_email,np.sender_name,np.verified_at,np.disabled_at,np.created_at,np.inheritable,
CASE WHEN np.application_id IS NOT NULL THEN 'application' WHEN np.organization_id IS NOT NULL THEN 'organization' ELSE 'installation' END
FROM notification_providers np JOIN applications a ON a.id=$1
WHERE np.application_id=$1 OR (np.application_id IS NULL AND np.organization_id=a.organization_id AND np.inheritable) OR
(np.application_id IS NULL AND np.organization_id IS NULL AND np.inheritable)
ORDER BY CASE WHEN np.application_id IS NOT NULL THEN 0 WHEN np.organization_id IS NOT NULL THEN 1 ELSE 2 END,np.created_at DESC`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Notification providers could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, provider, name, senderEmail, senderName string
		var created time.Time
		var inheritable bool
		var scope string
		var verified, disabled *time.Time
		if rows.Scan(&id, &provider, &name, &senderEmail, &senderName, &verified, &disabled, &created, &inheritable, &scope) == nil {
			items = append(items, map[string]any{"id": id, "provider": provider, "name": name, "sender_email": senderEmail, "sender_name": senderName, "verified_at": verified, "disabled_at": disabled, "created_at": created, "inheritable": inheritable, "scope": scope, "effective": true})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) listOrganizationNotificationProviders(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if !s.authorizeProviderScope(w, r, organizationProviderScope(organizationID), false) {
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,provider,name,sender_email,sender_name,verified_at,disabled_at,created_at,inheritable,
CASE WHEN organization_id IS NOT NULL THEN 'organization' ELSE 'installation' END
FROM notification_providers WHERE organization_id=$1 OR (application_id IS NULL AND organization_id IS NULL AND inheritable)
ORDER BY organization_id NULLS LAST,created_at DESC`, organizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Organization notification providers could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, provider, name, senderEmail, senderName, scope string
		var created time.Time
		var verified, disabled *time.Time
		var inheritable bool
		if rows.Scan(&id, &provider, &name, &senderEmail, &senderName, &verified, &disabled, &created, &inheritable, &scope) == nil {
			items = append(items, map[string]any{"id": id, "provider": provider, "name": name, "sender_email": senderEmail, "sender_name": senderName, "verified_at": verified, "disabled_at": disabled, "created_at": created, "inheritable": inheritable, "scope": scope, "effective": true})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) listNotifications(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,recipient,status,attempt_count,next_attempt_at,last_error,delivered_at,created_at
FROM notifications WHERE application_id=$1 ORDER BY created_at DESC,id LIMIT 101`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Notifications could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, recipient, status string
		var next, created time.Time
		var attempts int
		var lastError *string
		var delivered *time.Time
		if rows.Scan(&id, &recipient, &status, &attempts, &next, &lastError, &delivered, &created) == nil {
			items = append(items, map[string]any{"id": id, "recipient": recipient, "status": status, "attempt_count": attempts, "next_attempt_at": next, "last_error": lastError, "delivered_at": delivered, "created_at": created})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) retryNotification(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE notifications SET status='queued',next_attempt_at=now(),last_error=NULL
WHERE id=$1 AND application_id=$2 AND status IN ('failed','dead')`, chi.URLParam(r, "notification_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_not_found", "A retryable notification was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
