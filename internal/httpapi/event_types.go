package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/supaapps/platform93/internal/kernel"
)

var (
	eventTypeNamePattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$`)
	eventSchemaVersionPattern = regexp.MustCompile(`^[1-9][0-9]*\.[0-9]+$`)
)

type eventTypeRequest struct {
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	SchemaVersion  string         `json:"schema_version"`
	DataSchema     map[string]any `json:"data_schema"`
	ExampleSubject string         `json:"example_subject"`
	ExampleData    map[string]any `json:"example_data"`
}

func (s *Server) createEventType(w http.ResponseWriter, r *http.Request) {
	if !s.requireOrganizationSetting(w, r, settingCustomEvents) {
		return
	}
	var request eventTypeRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	if request.SchemaVersion == "" {
		request.SchemaVersion = "1.0"
	}
	request.ExampleSubject = strings.TrimSpace(request.ExampleSubject)
	if !validEventTypeDefinition(request.Name, request.Description, request.SchemaVersion) || request.ExampleSubject == "" || len(request.ExampleSubject) > 500 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_event_type", "Event type names use lowercase dot-separated segments; descriptions are limited to 500 characters and schema versions use major.minor.")
		return
	}
	if request.DataSchema == nil || request.ExampleData == nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "event_contract_required", "A JSON Schema, example subject, and example data object are required.")
		return
	}
	if err := validateEventData(request.DataSchema, request.ExampleData); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_event_contract", "The example must satisfy a valid object JSON Schema: "+err.Error())
		return
	}
	id := kernel.NewID()
	dataSchema, _ := json.Marshal(request.DataSchema)
	exampleData, _ := json.Marshal(request.ExampleData)
	_, err := s.app.DB.Exec(r.Context(), `INSERT INTO event_type_definitions
(id,application_id,name,description,schema_version,data_schema,example_subject,example_data,source)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,'application'
WHERE NOT EXISTS (SELECT 1 FROM event_type_definitions WHERE application_id IS NULL AND name=$3)`,
		id, chi.URLParam(r, "application_id"), request.Name, request.Description, request.SchemaVersion, dataSchema, request.ExampleSubject, exampleData)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "event_type_conflict", "This event type is reserved by Platform93 or already exists in the application.")
		return
	}
	var inserted bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM event_type_definitions WHERE id=$1)`, id).Scan(&inserted)
	if !inserted {
		kernel.WriteProblem(w, r, http.StatusConflict, "event_type_conflict", "This event type is reserved by Platform93 or already exists in the application.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, eventTypeDefinitionResponse(id.String(), chi.URLParam(r, "application_id"), request.Name, request.Description, request.SchemaVersion, request.DataSchema, request.ExampleSubject, request.ExampleData, "application", "active", 1, time.Now(), time.Now()))
}

func validEventTypeDefinition(name, description, schemaVersion string) bool {
	return len(name) <= 160 && eventTypeNamePattern.MatchString(name) && len(description) <= 500 && eventSchemaVersionPattern.MatchString(schemaVersion)
}

func (s *Server) listEventTypes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT d.id,d.name,d.description,d.schema_version,d.data_schema,d.example_subject,d.example_data,d.source,d.status,d.version,d.created_at,d.updated_at,
COALESCE(stats.event_count,0),stats.last_occurred_at
FROM event_type_definitions d LEFT JOIN LATERAL (
  SELECT count(*) event_count,max(occurred_at) last_occurred_at FROM domain_events
  WHERE application_id=$1 AND event_type=d.name
) stats ON true
WHERE d.application_id IS NULL OR d.application_id=$1
ORDER BY d.source,d.name`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Event types could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, description, schemaVersion, exampleSubject, source, status string
		var schema, example []byte
		var version, count int64
		var createdAt, updatedAt time.Time
		var lastOccurredAt any
		if rows.Scan(&id, &name, &description, &schemaVersion, &schema, &exampleSubject, &example, &source, &status, &version, &createdAt, &updatedAt, &count, &lastOccurredAt) == nil {
			item := eventTypeDefinitionResponse(id, chi.URLParam(r, "application_id"), name, description, schemaVersion, decodeMap(schema), exampleSubject, decodeMap(example), source, status, version, createdAt, updatedAt)
			item["event_count"], item["last_occurred_at"] = count, lastOccurredAt
			items = append(items, item)
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getEventType(w http.ResponseWriter, r *http.Request) {
	var id, name, description, schemaVersion, exampleSubject, source, status string
	var schema, example []byte
	var version int64
	var createdAt, updatedAt time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,name,description,schema_version,data_schema,example_subject,example_data,source,status,version,created_at,updated_at
FROM event_type_definitions WHERE id=$1 AND (application_id IS NULL OR application_id=$2)`, chi.URLParam(r, "event_type_id"), chi.URLParam(r, "application_id")).
		Scan(&id, &name, &description, &schemaVersion, &schema, &exampleSubject, &example, &source, &status, &version, &createdAt, &updatedAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "event_type_not_found", "The event type was not found.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version))
	kernel.WriteJSON(w, http.StatusOK, eventTypeDefinitionResponse(id, chi.URLParam(r, "application_id"), name, description, schemaVersion, decodeMap(schema), exampleSubject, decodeMap(example), source, status, version, createdAt, updatedAt))
}

func (s *Server) updateEventType(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Description    *string         `json:"description"`
		SchemaVersion  *string         `json:"schema_version"`
		DataSchema     *map[string]any `json:"data_schema"`
		ExampleSubject *string         `json:"example_subject"`
		ExampleData    *map[string]any `json:"example_data"`
		Status         *string         `json:"status"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	var version int64
	var name, description, schemaVersion, exampleSubject, status string
	var currentSchemaJSON, currentExampleJSON []byte
	err := s.app.DB.QueryRow(r.Context(), `SELECT name,description,schema_version,data_schema,example_subject,example_data,status,version FROM event_type_definitions
WHERE id=$1 AND application_id=$2 AND source='application'`, chi.URLParam(r, "event_type_id"), chi.URLParam(r, "application_id")).
		Scan(&name, &description, &schemaVersion, &currentSchemaJSON, &exampleSubject, &currentExampleJSON, &status, &version)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "event_type_not_found", "An application-defined event type was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	originalSchemaVersion := schemaVersion
	if request.Description != nil {
		*request.Description = strings.TrimSpace(*request.Description)
		description = *request.Description
	}
	if request.SchemaVersion != nil {
		*request.SchemaVersion = strings.TrimSpace(*request.SchemaVersion)
		if compareEventSchemaVersions(*request.SchemaVersion, schemaVersion) < 0 {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "event_schema_version_regression", "Event schema versions cannot move backwards.")
			return
		}
		schemaVersion = *request.SchemaVersion
	}
	if request.ExampleSubject != nil {
		*request.ExampleSubject = strings.TrimSpace(*request.ExampleSubject)
		exampleSubject = *request.ExampleSubject
	}
	if request.Status != nil {
		status = *request.Status
	}
	if !validEventTypeDefinition(name, description, schemaVersion) || exampleSubject == "" || len(exampleSubject) > 500 || status != "active" && status != "archived" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_event_type", "The event type definition is invalid.")
		return
	}
	currentSchema, currentExample := decodeMap(currentSchemaJSON), decodeMap(currentExampleJSON)
	updatedSchema, updatedExample := currentSchema, currentExample
	if request.DataSchema != nil {
		updatedSchema = *request.DataSchema
	}
	if request.ExampleData != nil {
		updatedExample = *request.ExampleData
	}
	if request.DataSchema != nil && !reflect.DeepEqual(updatedSchema, currentSchema) && (request.SchemaVersion == nil || *request.SchemaVersion == originalSchemaVersion) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "event_schema_version_required", "Change schema_version whenever the event data schema changes; increment the major version for breaking changes.")
		return
	}
	if err := validateEventData(updatedSchema, updatedExample); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_event_contract", "The example must satisfy a valid object JSON Schema: "+err.Error())
		return
	}
	dataSchema, _ := json.Marshal(updatedSchema)
	exampleData, _ := json.Marshal(updatedExample)
	result, err := s.app.DB.Exec(r.Context(), `UPDATE event_type_definitions SET
description=COALESCE($1::text,description),schema_version=COALESCE($2::text,schema_version),data_schema=$3::jsonb,
example_subject=COALESCE($4::text,example_subject),example_data=$5::jsonb,status=COALESCE($6::text,status),version=version+1,updated_at=now()
WHERE id=$7 AND application_id=$8 AND version=$9`, request.Description, request.SchemaVersion, dataSchema, request.ExampleSubject, exampleData, request.Status, chi.URLParam(r, "event_type_id"), chi.URLParam(r, "application_id"), version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "event_type_version_conflict", "The event type changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) archiveEventType(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE event_type_definitions SET status='archived',version=version+1,updated_at=now()
WHERE id=$1 AND application_id=$2 AND source='application' AND status='active'`, chi.URLParam(r, "event_type_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "event_type_not_found", "An active application-defined event type was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publishCustomEvent(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Type          string         `json:"type"`
		Subject       string         `json:"subject"`
		Data          map[string]any `json:"data"`
		CorrelationID *string        `json:"correlation_id"`
		CausationID   *string        `json:"causation_id"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Type, request.Subject = strings.TrimSpace(request.Type), strings.TrimSpace(request.Subject)
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "idempotency_key_required", "Custom event publication requires an Idempotency-Key header.")
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	wanted := "/applications/" + applicationID + "/events/publish"
	if !actorHasPermission(actor(r), wanted) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "event_publish_permission_required", "The application actor requires events:publish permission.")
		return
	}
	if !s.requireOrganizationSetting(w, r, settingCustomEvents) {
		return
	}
	if request.Subject == "" || len(request.Subject) > 500 || request.Data == nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_custom_event", "Custom events require a subject of at most 500 characters and a JSON object data payload.")
		return
	}
	for _, value := range []*string{request.CorrelationID, request.CausationID} {
		if value != nil {
			if _, err := uuid.Parse(*value); err != nil {
				kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_custom_event", "Correlation and causation identifiers must be UUIDs.")
				return
			}
		}
	}
	var schemaVersion string
	var schemaJSON []byte
	err := s.app.DB.QueryRow(r.Context(), `SELECT schema_version,data_schema FROM event_type_definitions
WHERE application_id=$1 AND name=$2 AND source='application' AND status='active'`, applicationID, request.Type).Scan(&schemaVersion, &schemaJSON)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "custom_event_type_unavailable", "Register and activate the custom event type before publishing it.")
		return
	}
	if err = validateEventData(decodeMap(schemaJSON), request.Data); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "custom_event_contract_violation", "The event data does not satisfy the active event contract: "+err.Error())
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The custom event could not be published.")
		return
	}
	defer rollback(tx, r.Context())
	eventID := kernel.NewID()
	eventActor := map[string]any{"type": actor(r).Type, "id": actor(r).ID}
	actorJSON, _ := json.Marshal(eventActor)
	dataJSON, _ := json.Marshal(request.Data)
	occurredAt := s.app.Now().UTC()
	_, err = tx.Exec(r.Context(), `INSERT INTO domain_events
(id,application_id,event_type,schema_version,contract_source,subject,actor,correlation_id,causation_id,data,occurred_at)
VALUES($1,$2,$3,$4,'application',$5,$6,$7,$8,$9,$10)`, eventID, applicationID, request.Type, schemaVersion, request.Subject, actorJSON, request.CorrelationID, request.CausationID, dataJSON, occurredAt)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO outbox(id,event_id) VALUES($1,$2)`, kernel.NewID(), eventID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "custom_event_publish_failed", "The custom event and outbox record could not be committed.")
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"id": eventID, "specversion": "1.0", "source": "platform93://applications/" + applicationID, "type": request.Type, "contract_source": "application", "time": occurredAt, "application_id": applicationID, "subject": request.Subject, "schema_version": schemaVersion, "actor": eventActor, "correlation_id": request.CorrelationID, "causation_id": request.CausationID, "data": request.Data})
}

func validateEventData(schema, data map[string]any) error {
	if schemaType, ok := schema["type"].(string); !ok || schemaType != "object" {
		return fmt.Errorf("the root schema type must be object")
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("event-contract.json", schema); err != nil {
		return err
	}
	compiled, err := compiler.Compile("event-contract.json")
	if err != nil {
		return err
	}
	return compiled.Validate(data)
}

func compareEventSchemaVersions(left, right string) int {
	parse := func(value string) (int, int) {
		parts := strings.SplitN(value, ".", 2)
		if len(parts) != 2 {
			return -1, -1
		}
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		return major, minor
	}
	leftMajor, leftMinor := parse(left)
	rightMajor, rightMinor := parse(right)
	if leftMajor != rightMajor {
		if leftMajor < rightMajor {
			return -1
		}
		return 1
	}
	if leftMinor < rightMinor {
		return -1
	}
	if leftMinor > rightMinor {
		return 1
	}
	return 0
}

func eventTypeDefinitionResponse(id, applicationID, name, description, schemaVersion string, schema map[string]any, exampleSubject string, exampleData map[string]any, source, status string, version int64, createdAt, updatedAt time.Time) map[string]any {
	example := map[string]any{
		"specversion": "1.0", "id": "01900000-0000-7000-8000-000000000099",
		"source": "platform93://applications/" + applicationID, "type": name, "contract_source": source,
		"time": "2026-01-01T00:00:00Z", "application_id": applicationID, "schema_version": schemaVersion,
		"subject": exampleSubject, "actor": map[string]any{"type": "control_user", "id": "01900000-0000-7000-8000-000000000098"},
		"correlation_id": nil, "causation_id": nil, "data": exampleData,
	}
	return map[string]any{"id": id, "name": name, "description": description, "schema_version": schemaVersion,
		"data_schema": schema, "example_subject": exampleSubject, "example_data": exampleData, "example_event": example,
		"source": source, "status": status, "version": version, "created_at": createdAt, "updated_at": updatedAt}
}

func actorHasPermission(current kernel.Actor, wanted string) bool {
	for _, granted := range current.Permissions {
		if permissionMatches(granted, wanted) {
			return true
		}
	}
	return false
}

func (s *Server) validateEventFilters(r *http.Request, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	var count int
	err := s.app.DB.QueryRow(r.Context(), `SELECT count(DISTINCT name) FROM event_type_definitions
WHERE status='active' AND (application_id IS NULL OR application_id=$1) AND name=ANY($2)`, chi.URLParam(r, "application_id"), filters).Scan(&count)
	return err == nil && count == len(filters)
}
