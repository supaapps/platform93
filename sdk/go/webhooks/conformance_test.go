package webhooks

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSharedConformanceFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../conformance/webhook.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Body      string `json:"raw_body"`
		Secret    string `json:"secret"`
		Timestamp int64  `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid shared fixture")
	}
	if err := Verify([]byte(fixture.Body), fixture.Signature, fixture.Secret, time.Unix(fixture.Timestamp, 0), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	event, err := VerifyAndDecode([]byte(fixture.Body), fixture.Signature, fixture.Secret, time.Unix(fixture.Timestamp, 0), 5*time.Minute)
	if err != nil || !event.IsPlatform() || !event.SupportsKnownVersion() {
		t.Fatalf("structured webhook contract failed: %#v %v", event, err)
	}
	data, err := DecodeData[UserCreatedData](event)
	if err != nil || data.UserID != "01900000-0000-7000-8000-000000000002" {
		t.Fatalf("typed event data failed: %#v %v", data, err)
	}
}
