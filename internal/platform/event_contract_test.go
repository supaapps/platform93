package platform

import "testing"

func TestValidateEventContract(t *testing.T) {
	schema := []byte(`{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"string"}},"additionalProperties":false}`)
	if err := validateEventContract(schema, []byte(`{"user_id":"01900000-0000-7000-8000-000000000001"}`)); err != nil {
		t.Fatalf("valid platform event was rejected: %v", err)
	}
	if err := validateEventContract(schema, []byte(`{"user_id":42}`)); err == nil {
		t.Fatal("invalid platform event was accepted")
	}
}
