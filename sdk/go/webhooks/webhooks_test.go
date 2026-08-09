package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"id":"event"}`)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(fmt.Sprintf("%d.", now.Unix())))
	_, _ = mac.Write(body)
	header := fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil)))
	if err := Verify(body, header, "secret", now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := Verify(append(body, 'x'), header, "secret", now, 5*time.Minute); err == nil {
		t.Fatal("tampered body accepted")
	}
}

func TestStorageEventsAreVersionedPlatformContracts(t *testing.T) {
	for _, eventType := range []string{
		"storage.object.upload_requested", "storage.object.ready", "storage.object.deleted",
		"storage.provider.verified", "storage.provider.disabled",
	} {
		event := Event{Type: eventType, ContractSource: "platform93", SchemaVersion: "1.1"}
		if !event.SupportsKnownVersion() {
			t.Errorf("storage event %q is not recognized", eventType)
		}
	}
}
