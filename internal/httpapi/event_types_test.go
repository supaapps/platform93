package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestEventTypeNameValidation(t *testing.T) {
	for _, name := range []string{"vehicle.created", "vehicle.status_changed", "fleet.vehicle.created"} {
		if !validEventTypeDefinition(name, "", "1.0") {
			t.Fatalf("expected valid event type %q", name)
		}
	}
	for _, name := range []string{"vehicle", "Vehicle.Created", "vehicle created", "vehicle..created", "platform93"} {
		if validEventTypeDefinition(name, "", "1.0") {
			t.Fatalf("expected invalid event type %q", name)
		}
	}
}

func TestEventContractValidationAndVersionOrdering(t *testing.T) {
	schema := map[string]any{
		"type": "object", "required": []any{"vehicle_id"},
		"properties":           map[string]any{"vehicle_id": map[string]any{"type": "string"}},
		"additionalProperties": false,
	}
	if err := validateEventData(schema, map[string]any{"vehicle_id": "veh_123"}); err != nil {
		t.Fatalf("valid event example was rejected: %v", err)
	}
	if err := validateEventData(schema, map[string]any{"vehicle_id": 42}); err == nil {
		t.Fatal("invalid event example was accepted")
	}
	if compareEventSchemaVersions("2.0", "1.9") <= 0 || compareEventSchemaVersions("1.10", "1.9") <= 0 || compareEventSchemaVersions("1.0", "1.0") != 0 {
		t.Fatal("event schema version ordering is incorrect")
	}
}

func TestPlatformEventCatalogExamplesMatchContracts(t *testing.T) {
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query(context.Background(), `SELECT name,data_schema,example_data
FROM event_type_definitions WHERE application_id IS NULL AND source='platform93' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var name string
		var rawSchema, rawExample []byte
		if err = rows.Scan(&name, &rawSchema, &rawExample); err != nil {
			t.Fatal(err)
		}
		var schema, example map[string]any
		if err = json.Unmarshal(rawSchema, &schema); err != nil {
			t.Fatalf("%s has invalid schema JSON: %v", name, err)
		}
		if err = json.Unmarshal(rawExample, &example); err != nil {
			t.Fatalf("%s has invalid example JSON: %v", name, err)
		}
		if err = validateEventData(schema, example); err != nil {
			t.Fatalf("%s example violates its contract: %v", name, err)
		}
		count++
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 34 {
		t.Fatalf("expected 34 built-in event contracts, got %d", count)
	}
}

func TestCustomEventRequiresPublishPermission(t *testing.T) {
	server := &Server{}
	request := requestWithRoute(t, http.MethodPost, "/", map[string]any{"type": "vehicle.created", "subject": "vehicle/1", "data": map[string]any{}}, map[string]string{"application_id": "01900000-0000-7000-8000-000000000001"}, kernel.Actor{Type: "user"})
	request.Header.Set("Idempotency-Key", "event-permission-test")
	response := httptest.NewRecorder()
	server.publishCustomEvent(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden publication, got %d: %s", response.Code, response.Body.String())
	}
}

func TestRegisteredCustomEventCreatesTransactionalOutboxRecord(t *testing.T) {
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := secure.NewVault(make([]byte, 32))
	server := &Server{app: platform.New(db, vault, "https://platform93.test")}

	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	if _, err = db.Exec(context.Background(), `INSERT INTO organizations(id,name,slug) VALUES($1,'Events',$2)`, organizationID, "events-"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Events',$3)`, applicationID, organizationID, "events-"+suffix); err != nil {
		t.Fatal(err)
	}
	clientDatabaseID := kernel.NewID()
	clientID := "event-publisher-" + suffix
	if _, err = db.Exec(context.Background(), `INSERT INTO clients(id,application_id,client_id,name,client_type,allowed_grants) VALUES($1,$2,$3,'Event publisher','machine',ARRAY['client_credentials'])`, clientDatabaseID, applicationID, clientID); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = server.app.EnsureSigningKey(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	kid, privateKey, err := server.app.ActiveSigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	machineToken, err := identity.Sign(privateKey, kid, identity.Claims{
		Issuer: server.app.Issuer(), Subject: clientID, Audience: []string{server.app.ApplicationAudience(applicationID)},
		ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(), NotBefore: now.Add(-time.Second).Unix(),
		JWTID: kernel.NewID().String(), ApplicationID: applicationID.String(), ClientID: clientID,
		TokenKind: "machine", ActorType: "client", Scope: "/applications/" + applicationID.String() + "/events/publish",
	})
	if err != nil {
		t.Fatal(err)
	}
	middlewareCalled := false
	middleware := server.requireApplicationActor(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		current := actor(request)
		middlewareCalled = current.Type == "client" && current.ID == clientDatabaseID.String()
		w.WriteHeader(http.StatusNoContent)
	}))
	middlewareRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{})
	middlewareRequest.Header.Set("Authorization", "Bearer "+machineToken)
	middlewareResponse := httptest.NewRecorder()
	middleware.ServeHTTP(middlewareResponse, middlewareRequest)
	if middlewareResponse.Code != http.StatusNoContent || !middlewareCalled {
		t.Fatalf("machine client was not authenticated for application publishing: %d %s", middlewareResponse.Code, middlewareResponse.Body.String())
	}
	definitionID := kernel.NewID()
	if _, err = db.Exec(context.Background(), `INSERT INTO event_type_definitions(id,application_id,name,description,schema_version,data_schema,example_subject,example_data,source)
VALUES($1,$2,'vehicle.created','A vehicle was created.','2.1','{"type":"object","required":["make"],"properties":{"make":{"type":"string"}},"additionalProperties":false}','vehicle/veh_123','{"make":"Volvo"}','application')`, definitionID, applicationID); err != nil {
		t.Fatal(err)
	}
	invalidRequest := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"type": "vehicle.created", "subject": "vehicle/veh_123", "data": map[string]any{"make": 42},
	}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "client", ID: kernel.NewID().String(), Permissions: []string{"/applications/" + applicationID.String() + "/events/publish"}})
	invalidRequest.Header.Set("Idempotency-Key", "vehicle-created-invalid")
	invalidResponse := httptest.NewRecorder()
	server.publishCustomEvent(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusUnprocessableEntity || !strings.Contains(invalidResponse.Body.String(), "custom_event_contract_violation") {
		t.Fatalf("invalid custom event data was accepted: %d %s", invalidResponse.Code, invalidResponse.Body.String())
	}

	current := kernel.Actor{Type: "client", ID: kernel.NewID().String(), Permissions: []string{"/applications/" + applicationID.String() + "/events/publish"}}
	request := requestWithRoute(t, http.MethodPost, "/", map[string]any{
		"type": "vehicle.created", "subject": "vehicle/veh_123", "data": map[string]any{"make": "Volvo"},
	}, map[string]string{"application_id": applicationID.String()}, current)
	request.Header.Set("Idempotency-Key", "vehicle-created-123")
	response := httptest.NewRecorder()
	server.publishCustomEvent(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("custom event publication failed: %d %s", response.Code, response.Body.String())
	}
	var published struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	var eventType, schemaVersion, contractSource, subject string
	var data []byte
	var outboxCount int
	err = db.QueryRow(context.Background(), `SELECT event_type,schema_version,contract_source,subject,data FROM domain_events WHERE id=$1`, published.ID).Scan(&eventType, &schemaVersion, &contractSource, &subject, &data)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE event_id=$1`, published.ID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if eventType != "vehicle.created" || schemaVersion != "2.1" || contractSource != "application" || subject != "vehicle/veh_123" || outboxCount != 1 || !json.Valid(data) {
		t.Fatalf("unexpected stored event: type=%s schema=%s subject=%s outbox=%d data=%s", eventType, schemaVersion, subject, outboxCount, data)
	}

	filterRequest := requestWithRoute(t, http.MethodGet, "/", nil, map[string]string{"application_id": applicationID.String()}, current)
	if !server.validateEventFilters(filterRequest, []string{"vehicle.created", "user.created"}) {
		t.Fatal("registered custom and Platform93 event filters should be accepted")
	}
	if server.validateEventFilters(filterRequest, []string{"vehicle.cretaed"}) {
		t.Fatal("unknown event filter should be rejected")
	}
	listResponse := httptest.NewRecorder()
	server.listEventTypes(listResponse, filterRequest)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), `"name":"vehicle.created"`) || !strings.Contains(listResponse.Body.String(), `"name":"user.created"`) || !strings.Contains(listResponse.Body.String(), `"example_event"`) {
		t.Fatalf("event type registry did not list custom and Platform93 definitions: %d %s", listResponse.Code, listResponse.Body.String())
	}
}
