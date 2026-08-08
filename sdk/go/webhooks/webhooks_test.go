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
