package httpapi

import (
	"net/url"
	"testing"
)

func TestAllowedApplicationRedirectSupportsNativeSchemes(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://app.example/auth/callback",
		"http://localhost:8081/auth/callback",
		"http://127.0.0.1:8081/auth/callback",
		"sampleapp://auth/callback",
		"com.example.app://oauth/callback?source=p93",
	} {
		value, err := url.Parse(raw)
		if err != nil || !allowedApplicationRedirect(value) {
			t.Fatalf("expected %q to be allowed", raw)
		}
	}
}

func TestAllowedApplicationRedirectRejectsUnsafeSchemesAndOrigins(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"http://example.com/auth/callback",
		"javascript://auth/callback",
		"data://auth/callback",
		"file://auth/callback",
		"https://user@example.com/auth/callback",
		"https://example.com/auth/callback#token",
		"/auth/callback",
	} {
		value, _ := url.Parse(raw)
		if allowedApplicationRedirect(value) {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}

func TestValidateClientRedirectURIsRestrictsNativeSchemesToPublicClients(t *testing.T) {
	t.Parallel()
	if err := validateClientRedirectURIs("public", []string{"sampleapp://auth/callback"}); err != nil {
		t.Fatalf("public native redirect should be accepted: %v", err)
	}
	if err := validateClientRedirectURIs("confidential", []string{"sampleapp://auth/callback"}); err == nil {
		t.Fatal("confidential native redirect should be rejected")
	}
	if err := validateClientRedirectURIs("machine", []string{"https://app.example/callback"}); err == nil {
		t.Fatal("machine redirect should be rejected")
	}
	if err := validateClientRedirectURIs("public", []string{"sampleapp://auth/callback", "sampleapp://auth/callback"}); err == nil {
		t.Fatal("duplicate redirects should be rejected")
	}
}
