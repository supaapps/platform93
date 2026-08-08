package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/outbound"
	"github.com/supaapps/platform93/internal/secure"
)

type createWebhookRequest struct {
	URI          string   `json:"uri"`
	EventFilters []string `json:"event_filters"`
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrganizationSetting(w, r, settingWebhooks) {
		return
	}
	var request createWebhookRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.URI = strings.TrimSpace(request.URI)
	if err := outbound.ValidateHTTPS(r.Context(), request.URI); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_webhook_destination", err.Error())
		return
	}
	request.EventFilters = uniqueStrings(request.EventFilters)
	if len(request.EventFilters) > 100 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_event_filter", "At most 100 event filters are allowed.")
		return
	}
	for _, filter := range request.EventFilters {
		if strings.TrimSpace(filter) == "" || len(filter) > 160 {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_event_filter", "Event filters must be non-empty and at most 160 characters.")
			return
		}
	}
	if !s.validateEventFilters(r, request.EventFilters) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "unknown_event_filter", "Every webhook filter must reference an active event type registered for this application.")
		return
	}
	id := kernel.NewID()
	secret, err := secure.RandomToken("p93_whsec_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The webhook secret could not be generated.")
		return
	}
	ciphertext, err := s.app.Vault.Encrypt([]byte(secret), "webhook-endpoint:"+id.String())
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO webhook_endpoints
(id,application_id,uri,event_filters,secret_ciphertext) VALUES ($1,$2,$3,$4,$5)`, id, chi.URLParam(r, "application_id"), request.URI, request.EventFilters, ciphertext)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "webhook_creation_failed", "The webhook endpoint could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "uri": request.URI, "event_filters": request.EventFilters, "secret": secret, "secret_returned_once": true})
}

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,uri,event_filters,disabled_at,version,created_at
FROM webhook_endpoints WHERE application_id=$1 ORDER BY created_at,id`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Webhook endpoints could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, uri string
		var created time.Time
		var filters []string
		var disabled *time.Time
		var version int64
		if rows.Scan(&id, &uri, &filters, &disabled, &version, &created) == nil {
			items = append(items, map[string]any{"id": id, "uri": uri, "event_filters": filters, "disabled_at": disabled, "version": version, "created_at": created})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getWebhook(w http.ResponseWriter, r *http.Request) {
	var id, uri string
	var filters []string
	var disabledAt *time.Time
	var version int64
	var createdAt time.Time
	var pending, delivered, failed int64
	err := s.app.DB.QueryRow(r.Context(), `SELECT w.id,w.uri,w.event_filters,w.disabled_at,w.version,w.created_at,
count(d.id) FILTER (WHERE d.status IN ('pending','delivering')),
count(d.id) FILTER (WHERE d.status='delivered'),count(d.id) FILTER (WHERE d.status IN ('failed','dead'))
FROM webhook_endpoints w LEFT JOIN webhook_deliveries d ON d.webhook_endpoint_id=w.id
WHERE w.id=$1 AND w.application_id=$2 GROUP BY w.id`, chi.URLParam(r, "webhook_id"), chi.URLParam(r, "application_id")).
		Scan(&id, &uri, &filters, &disabledAt, &version, &createdAt, &pending, &delivered, &failed)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "webhook_not_found", "The webhook endpoint was not found.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version))
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "uri": uri, "event_filters": filters, "disabled_at": disabledAt,
		"version": version, "created_at": createdAt, "delivery_statistics": map[string]any{"pending": pending, "delivered": delivered, "failed": failed}})
}

func (s *Server) updateWebhook(w http.ResponseWriter, r *http.Request) {
	var request struct {
		URI          *string   `json:"uri,omitempty"`
		EventFilters *[]string `json:"event_filters,omitempty"`
		Enabled      *bool     `json:"enabled,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.URI != nil {
		*request.URI = strings.TrimSpace(*request.URI)
		if err := outbound.ValidateHTTPS(r.Context(), *request.URI); err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_webhook_destination", err.Error())
			return
		}
	}
	if request.EventFilters != nil {
		filters := uniqueStrings(*request.EventFilters)
		if len(filters) > 100 {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_event_filter", "At most 100 event filters are allowed.")
			return
		}
		for _, filter := range filters {
			if strings.TrimSpace(filter) == "" || len(filter) > 160 {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_event_filter", "Event filters must be non-empty and at most 160 characters.")
				return
			}
		}
		request.EventFilters = &filters
		if !s.validateEventFilters(r, filters) {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "unknown_event_filter", "Every webhook filter must reference an active event type registered for this application.")
			return
		}
	}
	var version int64
	if err := s.app.DB.QueryRow(r.Context(), `SELECT version FROM webhook_endpoints WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "webhook_id"), chi.URLParam(r, "application_id")).Scan(&version); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "webhook_not_found", "The webhook endpoint was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE webhook_endpoints SET
uri=CASE WHEN $1::text IS NULL THEN uri ELSE $1 END,
event_filters=CASE WHEN $2::text[] IS NULL THEN event_filters ELSE $2 END,
disabled_at=CASE WHEN $3::boolean IS NULL THEN disabled_at WHEN $3 THEN NULL ELSE COALESCE(disabled_at,now()) END,
version=version+1 WHERE id=$4 AND application_id=$5 AND version=$6`, request.URI, request.EventFilters, request.Enabled,
		chi.URLParam(r, "webhook_id"), chi.URLParam(r, "application_id"), version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "webhook_version_conflict", "The webhook endpoint changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	applicationID, webhookID := chi.URLParam(r, "application_id"), chi.URLParam(r, "webhook_id")
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The webhook test could not be queued.")
		return
	}
	defer rollback(tx, r.Context())
	eventID, deliveryID := kernel.NewID(), kernel.NewID()
	actorJSON, _ := json.Marshal(map[string]any{"type": "operator", "id": actor(r).ID})
	dataJSON, _ := json.Marshal(map[string]any{"webhook_endpoint_id": webhookID, "test": true})
	result, err := tx.Exec(r.Context(), `INSERT INTO domain_events(id,application_id,event_type,schema_version,contract_source,subject,actor,data)
SELECT $1,$2,d.name,d.schema_version,'platform93',$3::text,$4,$5 FROM webhook_endpoints w
CROSS JOIN event_type_definitions d
WHERE w.id=$6 AND w.application_id=$2 AND w.disabled_at IS NULL
AND d.application_id IS NULL AND d.name='platform93.webhook.test' AND d.status='active'`, eventID, applicationID, "webhook/"+webhookID,
		actorJSON, dataJSON, webhookID)
	if err == nil && result.RowsAffected() == 1 {
		_, err = tx.Exec(r.Context(), `INSERT INTO webhook_deliveries(id,application_id,webhook_endpoint_id,event_id) VALUES($1,$2,$3,$4)`, deliveryID, applicationID, webhookID, eventID)
	} else if err == nil {
		err = fmt.Errorf("active webhook endpoint not found")
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "webhook_not_found", "An active webhook endpoint was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"event_id": eventID, "delivery_id": deliveryID, "status": "pending"})
}

func (s *Server) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "webhook_id")
	secret, err := secure.RandomToken("p93_whsec_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The webhook secret could not be generated.")
		return
	}
	ciphertext, err := s.app.Vault.Encrypt([]byte(secret), "webhook-endpoint:"+id)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "encryption_failed", "The webhook secret could not be encrypted.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE webhook_endpoints SET
previous_secret_ciphertext=secret_ciphertext,previous_valid_until=now()+interval '24 hours',secret_ciphertext=$1,version=version+1
WHERE id=$2 AND application_id=$3`, ciphertext, id, chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "webhook_not_found", "The webhook endpoint was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"secret": secret, "secret_returned_once": true, "previous_secret_valid_for_seconds": 86400})
}

func (s *Server) disableWebhook(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE webhook_endpoints SET disabled_at=COALESCE(disabled_at,now())
WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "webhook_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "webhook_not_found", "The webhook endpoint was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT d.id,d.webhook_endpoint_id,d.event_id,d.status,d.attempt_count,
d.next_attempt_at,d.response_status,d.response_excerpt,d.delivered_at,d.created_at
FROM webhook_deliveries d WHERE d.application_id=$1 ORDER BY d.created_at DESC,d.id LIMIT 101`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Webhook deliveries could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, endpointID, eventID, status string
		var next, created time.Time
		var attempts int
		var responseStatus *int
		var excerpt *string
		var delivered *time.Time
		if rows.Scan(&id, &endpointID, &eventID, &status, &attempts, &next, &responseStatus, &excerpt, &delivered, &created) == nil {
			items = append(items, map[string]any{"id": id, "webhook_endpoint_id": endpointID, "event_id": eventID, "status": status, "attempt_count": attempts, "next_attempt_at": next, "response_status": responseStatus, "response_excerpt": excerpt, "delivered_at": delivered, "created_at": created})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getWebhookDelivery(w http.ResponseWriter, r *http.Request) {
	var value []byte
	err := s.app.DB.QueryRow(r.Context(), `SELECT to_jsonb(d) FROM webhook_deliveries d
WHERE d.id=$1 AND d.application_id=$2`, chi.URLParam(r, "delivery_id"), chi.URLParam(r, "application_id")).Scan(&value)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "webhook_delivery_not_found", "The webhook delivery was not found.")
		return
	}
	result, _ := decodeAny(value).(map[string]any)
	kernel.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) replayWebhookDelivery(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE webhook_deliveries SET status='pending',attempt_count=0,
next_attempt_at=now(),response_status=NULL,response_excerpt=NULL,delivered_at=NULL
WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "delivery_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "webhook_delivery_not_found", "The webhook delivery was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
