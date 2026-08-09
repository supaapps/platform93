package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) createSenderIdentity(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ProviderID string `json:"provider_id"`
		Email      string `json:"email"`
		Name       string `json:"name,omitempty"`
		Default    bool   `json:"is_default,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Email = kernel.NormalizeEmail(request.Email)
	if !strings.Contains(request.Email, "@") || strings.ContainsAny(request.Email, "\r\n") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_sender_identity", "A valid sender email is required.")
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil && request.Default {
		_, err = tx.Exec(r.Context(), `UPDATE sender_identities SET is_default=false WHERE application_id=$1`, applicationID)
	}
	id := kernel.NewID()
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO sender_identities(id,application_id,notification_provider_id,email,name,is_default)
SELECT $1,$2,id,$3,$4,$5 FROM notification_providers WHERE id=$6 AND application_id=$2 AND disabled_at IS NULL`,
			id, applicationID, request.Email, request.Name, request.Default, request.ProviderID)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "sender_identity_creation_failed", "The sender identity could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "provider_id": request.ProviderID, "email": request.Email, "name": request.Name, "is_default": request.Default, "verified": false})
}

func (s *Server) listSenderIdentities(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,notification_provider_id,email,name,is_default,verified_at,disabled_at,created_at
FROM sender_identities WHERE application_id=$1 ORDER BY is_default DESC,created_at,id`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Sender identities could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, providerID, email, name string
		var isDefault bool
		var verifiedAt, disabledAt *time.Time
		var createdAt time.Time
		if rows.Scan(&id, &providerID, &email, &name, &isDefault, &verifiedAt, &disabledAt, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "provider_id": providerID, "email": email, "name": name, "is_default": isDefault,
				"verified_at": verifiedAt, "disabled_at": disabledAt, "created_at": createdAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) setDefaultSenderIdentity(w http.ResponseWriter, r *http.Request) {
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE sender_identities SET is_default=false WHERE application_id=$1`, chi.URLParam(r, "application_id"))
	}
	var affected int64
	if err == nil {
		result, updateErr := tx.Exec(r.Context(), `UPDATE sender_identities SET is_default=true WHERE id=$1 AND application_id=$2 AND disabled_at IS NULL`,
			chi.URLParam(r, "sender_id"), chi.URLParam(r, "application_id"))
		err = updateErr
		if err == nil {
			affected = result.RowsAffected()
		}
	}
	if err == nil && affected == 1 {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil || affected != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "sender_identity_not_found", "An active sender identity was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) disableNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.disableNotificationProviderForScope(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) disableInstallationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.disableNotificationProviderForScope(w, r, installationProviderScope())
}

func (s *Server) disableOrganizationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.disableNotificationProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) disableNotificationProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE notification_providers SET disabled_at=now()
WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid AND disabled_at IS NULL`, chi.URLParam(r, "provider_id"), scope.ApplicationID, scope.OrganizationID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_provider_not_found", "An active notification provider was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getNotification(w http.ResponseWriter, r *http.Request) {
	var value []byte
	err := s.app.DB.QueryRow(r.Context(), `SELECT to_jsonb(n)-'payload_ciphertext' FROM notifications n
WHERE n.id=$1 AND n.application_id=$2`, chi.URLParam(r, "notification_id"), chi.URLParam(r, "application_id")).Scan(&value)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_not_found", "The notification was not found.")
		return
	}
	result, _ := decodeAny(value).(map[string]any)
	attempts := []map[string]any{}
	rows, _ := s.app.DB.Query(r.Context(), `SELECT id,notification_provider_id,attempt_number,status,error,started_at,completed_at
FROM notification_attempts WHERE notification_id=$1 ORDER BY attempt_number`, chi.URLParam(r, "notification_id"))
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, status string
			var providerID, attemptError *string
			var number int
			var startedAt time.Time
			var completedAt *time.Time
			if rows.Scan(&id, &providerID, &number, &status, &attemptError, &startedAt, &completedAt) == nil {
				attempts = append(attempts, map[string]any{"id": id, "provider_id": providerID, "attempt_number": number, "status": status,
					"error": attemptError, "started_at": startedAt, "completed_at": completedAt})
			}
		}
	}
	attachments := []map[string]any{}
	attachmentRows, _ := s.app.DB.Query(r.Context(), `SELECT id,filename,content_type,size_bytes,created_at FROM notification_attachments
WHERE notification_id=$1 ORDER BY created_at,id`, chi.URLParam(r, "notification_id"))
	if attachmentRows != nil {
		defer attachmentRows.Close()
		for attachmentRows.Next() {
			var id, filename, contentType string
			var size int
			var createdAt time.Time
			if attachmentRows.Scan(&id, &filename, &contentType, &size, &createdAt) == nil {
				attachments = append(attachments, map[string]any{"id": id, "filename": filename, "content_type": contentType, "size_bytes": size, "created_at": createdAt})
			}
		}
	}
	result["attempts"] = attempts
	result["attachments"] = attachments
	kernel.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) notificationStatistics(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT status,count(*) FROM notifications WHERE application_id=$1 GROUP BY status`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Notification statistics could not be loaded.")
		return
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var status string
		var count int64
		if rows.Scan(&status, &count) == nil {
			counts[status] = count
		}
	}
	var delivered, failed int64
	_ = s.app.DB.QueryRow(r.Context(), `SELECT count(*) FILTER(WHERE status='delivered'),count(*) FILTER(WHERE status='failed')
FROM notification_attempts a JOIN notifications n ON n.id=a.notification_id WHERE n.application_id=$1`, chi.URLParam(r, "application_id")).Scan(&delivered, &failed)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"notification_status_counts": counts, "attempts_delivered": delivered, "attempts_failed": failed})
}
