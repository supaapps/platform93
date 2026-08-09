package identity

import (
	"testing"
	"time"
)

func TestTOTPMatchesRFCVector(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // gitleaks:allow -- Public RFC 6238 test vector.
	code, err := totpAt(secret, time.Unix(59, 0).Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 6238's first SHA-1 vector is 94287082; the six-digit profile keeps its suffix.
	if code != "287082" || !VerifyTOTP(secret, code, time.Unix(59, 0)) {
		t.Fatalf("unexpected TOTP code %q", code)
	}
}

func TestTOTPRejectsMalformedCode(t *testing.T) {
	if VerifyTOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "123", time.Now()) {
		t.Fatal("short code accepted")
	}
}
