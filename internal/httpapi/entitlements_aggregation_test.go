package httpapi

import "testing"

func TestAggregateGrantsPreservesExplicitZeroAndFalse(t *testing.T) {
	grants := []map[string]any{{
		"id":             "grant-1",
		"source_type":    "subscription",
		"feature_values": map[string]any{"enabled": false, "limit": float64(0)},
	}}

	effective := aggregateGrants(grants)
	if enabled, exists := effective["enabled"]; !exists || enabled != false {
		t.Fatalf("expected explicit false, got %#v", effective)
	}
	if limit, exists := effective["limit"]; !exists || limit != float64(0) {
		t.Fatalf("expected explicit zero, got %#v", effective)
	}
	provenance := entitlementProvenance(grants, effective)
	if len(provenance["enabled"]) != 1 || len(provenance["limit"]) != 1 {
		t.Fatalf("expected provenance for explicit boundary values, got %#v", provenance)
	}
}

func TestAggregateGrantsUsesAdditiveBooleanAndMaximumQuantity(t *testing.T) {
	grants := []map[string]any{
		{"feature_values": map[string]any{"enabled": false, "limit": float64(5)}},
		{"feature_values": map[string]any{"enabled": true, "limit": float64(25)}},
	}

	effective := aggregateGrants(grants)
	if effective["enabled"] != true {
		t.Fatalf("expected true to win additive boolean aggregation, got %#v", effective)
	}
	if effective["limit"] != float64(25) {
		t.Fatalf("expected maximum quantity, got %#v", effective)
	}
}
