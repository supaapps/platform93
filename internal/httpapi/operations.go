package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) applicationStatistics(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	var usersTotal, usersActive, usersSuspended, workspaces, products, entitlements, localPending int64
	var subscriptions, notificationFailures, webhookFailures, events24Hours int64
	err := s.app.DB.QueryRow(r.Context(), `SELECT
(SELECT count(*) FROM users WHERE application_id=$1 AND status<>'deleted'),
(SELECT count(*) FROM users WHERE application_id=$1 AND status='active'),
(SELECT count(*) FROM users WHERE application_id=$1 AND status='suspended'),
(SELECT count(*) FROM workspaces WHERE application_id=$1 AND deleted_at IS NULL),
(SELECT count(*) FROM products WHERE application_id=$1 AND status='active'),
(SELECT count(*) FROM entitlement_grants WHERE application_id=$1 AND revoked_at IS NULL AND starts_at<=now() AND (expires_at IS NULL OR expires_at>now())),
(SELECT count(*) FROM local_entitlement_requests WHERE application_id=$1 AND status='pending'),
(SELECT count(*) FROM subscriptions WHERE application_id=$1 AND status IN ('trialing','active','past_due')),
(SELECT count(*) FROM notifications WHERE application_id=$1 AND status IN ('failed','dead')),
(SELECT count(*) FROM webhook_deliveries WHERE application_id=$1 AND status IN ('failed','dead')),
(SELECT count(*) FROM domain_events WHERE application_id=$1 AND occurred_at>=now()-interval '24 hours')`, applicationID).
		Scan(&usersTotal, &usersActive, &usersSuspended, &workspaces, &products, &entitlements, &localPending, &subscriptions, &notificationFailures, &webhookFailures, &events24Hours)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Application statistics could not be loaded.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{
		"users":      map[string]int64{"total": usersTotal, "active": usersActive, "suspended": usersSuspended},
		"workspaces": workspaces, "active_products": products, "active_entitlements": entitlements,
		"pending_local_requests": localPending, "live_subscriptions": subscriptions,
		"notification_failures": notificationFailures, "webhook_failures": webhookFailures, "events_last_24_hours": events24Hours,
	})
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	cursor, err := decodeTimeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_cursor", "The event cursor is invalid.")
		return
	}
	correlationID := r.URL.Query().Get("correlation_id")
	if correlationID != "" {
		if _, err = uuid.Parse(correlationID); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_correlation_id", "The correlation identifier is invalid.")
			return
		}
	}
	limit := pageLimit(r)
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,event_type,schema_version,contract_source,subject,actor,correlation_id,causation_id,data,occurred_at
FROM domain_events WHERE application_id=$1 AND ($2='' OR event_type=$2) AND ($3='' OR subject=$3)
AND ($4='' OR correlation_id=$4::uuid) AND (occurred_at,id)<($5,$6::uuid)
ORDER BY occurred_at DESC,id DESC LIMIT $7`, chi.URLParam(r, "application_id"), r.URL.Query().Get("event_type"),
		r.URL.Query().Get("subject"), correlationID, cursor.Time, cursor.ID, limit+1)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Events could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		item, scanErr := scanEvent(rows, chi.URLParam(r, "application_id"))
		if scanErr == nil {
			items = append(items, item)
		}
	}
	next := any(nil)
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = encodeTimeCursor(last["time"].(time.Time), last["id"].(string))
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	row := s.app.DB.QueryRow(r.Context(), `SELECT id,event_type,schema_version,contract_source,subject,actor,correlation_id,causation_id,data,occurred_at
FROM domain_events WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "event_id"), chi.URLParam(r, "application_id"))
	item, err := scanEvent(row, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "event_not_found", "The event was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, item)
}

type eventRow interface{ Scan(...any) error }

func scanEvent(row eventRow, applicationID string) (map[string]any, error) {
	var id, eventType, schemaVersion, contractSource string
	var occurred time.Time
	var subject, correlation, causation *string
	var actorJSON, dataJSON []byte
	err := row.Scan(&id, &eventType, &schemaVersion, &contractSource, &subject, &actorJSON, &correlation, &causation, &dataJSON, &occurred)
	return map[string]any{"specversion": "1.0", "id": id, "source": "platform93://applications/" + applicationID, "type": eventType,
		"subject": subject, "time": occurred,
		"application_id": applicationID, "schema_version": schemaVersion, "contract_source": contractSource, "actor": decodeMap(actorJSON), "correlation_id": correlation, "causation_id": causation, "data": decodeMap(dataJSON)}, err
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	s.listAuditScope(w, r, chi.URLParam(r, "application_id"), "")
}

func (s *Server) listOrganizationAudit(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if !s.controlUserBelongsToOrganization(r, organizationID) {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
		return
	}
	s.listAuditScope(w, r, "", organizationID)
}

func (s *Server) listAuditScope(w http.ResponseWriter, r *http.Request, applicationID, organizationID string) {
	cursor, err := decodeTimeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_cursor", "The audit cursor is invalid.")
		return
	}
	start, end := r.URL.Query().Get("start"), r.URL.Query().Get("end")
	for _, value := range []string{start, end} {
		if value != "" {
			if _, parseErr := time.Parse(time.RFC3339, value); parseErr != nil {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_audit_time", "Audit start and end must be RFC3339 timestamps.")
				return
			}
		}
	}
	limit := pageLimit(r)
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,actor_type,actor_id,action,target_type,target_id,reason,request_id,changes,created_at
FROM audit_records WHERE ($1='' OR application_id=$1::uuid) AND ($2='' OR organization_id=$2::uuid)
AND ($3='' OR actor_type=$3) AND ($4='' OR action=$4) AND ($5='' OR target_type=$5)
AND ($6='' OR created_at>=$6::timestamptz) AND ($7='' OR created_at<$7::timestamptz)
AND (created_at,id)<($8,$9::uuid) ORDER BY created_at DESC,id DESC LIMIT $10`, applicationID, organizationID,
		r.URL.Query().Get("actor_type"), r.URL.Query().Get("action"), r.URL.Query().Get("target_type"), start, end,
		cursor.Time, cursor.ID, limit+1)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Audit records could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		item, scanErr := scanAudit(rows)
		if scanErr == nil {
			items = append(items, item)
		}
	}
	next := any(nil)
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = encodeTimeCursor(last["created_at"].(time.Time), last["id"].(string))
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	item, err := scanAudit(s.app.DB.QueryRow(r.Context(), `SELECT id,actor_type,actor_id,action,target_type,target_id,reason,request_id,changes,created_at
FROM audit_records WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "audit_id"), chi.URLParam(r, "application_id")))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "audit_record_not_found", "The audit record was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, item)
}

type auditRow interface{ Scan(...any) error }

func scanAudit(row auditRow) (map[string]any, error) {
	var id, actorType, action string
	var created time.Time
	var actorID, targetType, targetID, reason, requestID *string
	var changes []byte
	err := row.Scan(&id, &actorType, &actorID, &action, &targetType, &targetID, &reason, &requestID, &changes, &created)
	return map[string]any{"id": id, "actor_type": actorType, "actor_id": actorID, "action": action, "target_type": targetType,
		"target_id": targetID, "reason": reason, "request_id": requestID, "changes": decodeMap(changes), "created_at": created}, err
}

func (s *Server) createAuditExport(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Start      string `json:"start,omitempty"`
		End        string `json:"end,omitempty"`
		ActorType  string `json:"actor_type,omitempty"`
		Action     string `json:"action,omitempty"`
		TargetType string `json:"target_type,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	for _, value := range []string{request.Start, request.End} {
		if value != "" {
			if _, err := time.Parse(time.RFC3339, value); err != nil {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_audit_time", "Audit start and end must be RFC3339 timestamps.")
				return
			}
		}
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,actor_type,actor_id,action,target_type,target_id,reason,request_id,changes,created_at
FROM audit_records WHERE application_id=$1 AND ($2='' OR actor_type=$2) AND ($3='' OR action=$3) AND ($4='' OR target_type=$4)
AND ($5='' OR created_at>=$5::timestamptz) AND ($6='' OR created_at<$6::timestamptz)
ORDER BY created_at DESC,id DESC LIMIT 10001`, chi.URLParam(r, "application_id"), request.ActorType, request.Action, request.TargetType, request.Start, request.End)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Audit export data could not be loaded.")
		return
	}
	items := []map[string]any{}
	for rows.Next() {
		item, scanErr := scanAudit(rows)
		if scanErr == nil {
			items = append(items, item)
		}
	}
	rows.Close()
	if len(items) > 10_000 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "audit_export_too_large", "Narrow the export filters to at most 10000 records.")
		return
	}
	id := kernel.NewID()
	payload, _ := json.Marshal(map[string]any{"schema_version": "1.0", "records": items})
	ciphertext, err := s.app.Vault.Encrypt(payload, "audit-export:"+id.String())
	filters, _ := json.Marshal(request)
	expiresAt := s.app.Now().Add(time.Hour)
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO audit_exports
(id,application_id,requested_by,filter_snapshot,payload_ciphertext,record_count,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			id, chi.URLParam(r, "application_id"), actor(r).ID, filters, ciphertext, len(items), expiresAt)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "audit_export_failed", "The encrypted audit export could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "record_count": len(items), "expires_at": expiresAt})
}

func (s *Server) getAuditExport(w http.ResponseWriter, r *http.Request) {
	var ciphertext string
	var count int
	var filters []byte
	var expiresAt, createdAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT payload_ciphertext,record_count,filter_snapshot,expires_at,created_at FROM audit_exports
WHERE id=$1 AND application_id=$2 AND expires_at>now()`, chi.URLParam(r, "export_id"), chi.URLParam(r, "application_id")).
		Scan(&ciphertext, &count, &filters, &expiresAt, &createdAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "audit_export_not_found", "The audit export was not found or has expired.")
		return
	}
	payload, err := s.app.Vault.Decrypt(ciphertext, "audit-export:"+chi.URLParam(r, "export_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "audit_export_unavailable", "The audit export could not be decrypted.")
		return
	}
	var data any
	_ = json.Unmarshal(payload, &data)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": chi.URLParam(r, "export_id"), "record_count": count, "filters": decodeMap(filters),
		"expires_at": expiresAt, "created_at": createdAt, "data": data})
}
