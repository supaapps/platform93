package outbound

import (
	"context"
	"net/netip"
	"testing"
)

func TestBlockedAddressRanges(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.2.1", "198.18.0.1", "203.0.113.1", "::1", "fc00::1", "2001:db8::1"} {
		if !blockedAddress(netip.MustParseAddr(value)) {
			t.Errorf("address %s was not blocked", value)
		}
	}
	if blockedAddress(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address was blocked")
	}
}

func TestValidateHTTPSRejectsUnsafeDestinations(t *testing.T) {
	for _, destination := range []string{"http://example.com", "https://user@example.com", "https://127.0.0.1/hook", "https://[::1]/hook"} {
		if ValidateHTTPS(context.Background(), destination) == nil {
			t.Errorf("unsafe destination %s was accepted", destination)
		}
	}
}
