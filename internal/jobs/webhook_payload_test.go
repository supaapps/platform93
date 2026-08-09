package jobs

import (
	"encoding/json"
	"testing"
)

func TestWebhookEventPayloadPreservesCustomEventContext(t *testing.T) {
	subject, correlation, causation := "vehicle/veh_123", "01900000-0000-7000-8000-000000000001", "01900000-0000-7000-8000-000000000002"
	payload := webhookEventPayload(
		"01900000-0000-7000-8000-000000000003", "01900000-0000-7000-8000-000000000004",
		"vehicle.created", "2.1", "application", "2026-08-08T00:00:00Z", &subject,
		[]byte(`{"type":"client","id":"01900000-0000-7000-8000-000000000005"}`), &correlation, &causation,
		[]byte(`{"make":"Volvo"}`),
	)
	var event map[string]any
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	if event["type"] != "vehicle.created" || event["schema_version"] != "2.1" || event["contract_source"] != "application" || event["subject"] != subject || event["correlation_id"] != correlation || event["causation_id"] != causation {
		t.Fatalf("custom event context was lost: %#v", event)
	}
	actor, _ := event["actor"].(map[string]any)
	data, _ := event["data"].(map[string]any)
	if actor["type"] != "client" || data["make"] != "Volvo" {
		t.Fatalf("actor or data was lost: %#v", event)
	}
}
