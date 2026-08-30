package httpapi

import (
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeMicrosoftTenant(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"":                                     "common",
		" Organizations ":                      "organizations",
		"CONSUMERS":                            "consumers",
		"9188040D-6C67-4C5B-B112-36A304B66DAD": "9188040d-6c67-4c5b-b112-36a304b66dad",
	}
	for input, expected := range tests {
		actual, err := normalizeMicrosoftTenant(input)
		if err != nil || actual != expected {
			t.Fatalf("normalizeMicrosoftTenant(%q) = %q, %v; want %q", input, actual, err, expected)
		}
	}
	for _, invalid := range []string{"tenant.example", "*", "common \\ consumers", "00000000-0000-0000-0000-000000000000"} {
		if _, err := normalizeMicrosoftTenant(invalid); err == nil {
			t.Fatalf("normalizeMicrosoftTenant(%q) accepted an invalid tenant", invalid)
		}
	}
}

func TestMicrosoftIssuerAllowed(t *testing.T) {
	t.Parallel()
	organizationTenant := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	organizationIssuer := "https://login.microsoftonline.com/" + organizationTenant + "/v2.0"
	consumerIssuer := "https://login.microsoftonline.com/" + microsoftConsumerTenantID + "/v2.0"
	if !microsoftIssuerAllowed("common", organizationTenant, organizationIssuer) {
		t.Fatal("common should accept a valid organization tenant issuer")
	}
	if !microsoftIssuerAllowed("organizations", organizationTenant, organizationIssuer) {
		t.Fatal("organizations should accept an organization tenant issuer")
	}
	if microsoftIssuerAllowed("organizations", microsoftConsumerTenantID, consumerIssuer) {
		t.Fatal("organizations accepted the consumer tenant")
	}
	if !microsoftIssuerAllowed("consumers", microsoftConsumerTenantID, consumerIssuer) {
		t.Fatal("consumers should accept the consumer tenant")
	}
	if microsoftIssuerAllowed(organizationTenant, organizationTenant, "https://attacker.example/v2.0") {
		t.Fatal("an exact tenant accepted a mismatched issuer")
	}
}

func TestProviderUsesPKCE(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"google", "microsoft", "linkedin"} {
		if !providerUsesPKCE(provider) {
			t.Fatalf("%s must use provider PKCE", provider)
		}
	}
	for _, provider := range []string{"apple", "facebook"} {
		if providerUsesPKCE(provider) {
			t.Fatalf("%s unexpectedly uses provider PKCE", provider)
		}
	}
}

func TestValidExternalAuthProvider(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"google", "apple", "microsoft", "facebook", "linkedin"} {
		if !validExternalAuthProvider(provider) {
			t.Fatalf("%s should be supported", provider)
		}
	}
	for _, provider := range []string{"", "Google", "github", "microsoft "} {
		if validExternalAuthProvider(provider) {
			t.Fatalf("%q should not be supported", provider)
		}
	}
}

func TestProviderAuthorizationURLs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		provider string
		tenant   string
		host     string
		scopes   []string
	}{
		{provider: "microsoft", tenant: "organizations", host: "login.microsoftonline.com", scopes: []string{"openid", "profile", "email"}},
		{provider: "linkedin", host: "www.linkedin.com", scopes: []string{"openid", "profile", "email"}},
		{provider: "facebook", host: "www.facebook.com", scopes: []string{"public_profile", "email"}},
	}
	for _, test := range tests {
		config := externalAuthProviderConfig{Provider: test.provider, ClientID: "client", Credentials: map[string]string{"client_secret": "secret", "tenant": test.tenant}}
		authorization, err := providerAuthorizationURL(config, "https://platform.example/v1/auth/providers/"+test.provider+"/callback", "state", "nonce", strings.Repeat("v", 43), "person@example.test")
		if err != nil {
			t.Fatalf("%s authorization URL failed: %v", test.provider, err)
		}
		parsed, err := url.Parse(authorization)
		if err != nil || parsed.Host != test.host || parsed.Query().Get("client_id") != "client" || parsed.Query().Get("state") != "state" {
			t.Fatalf("unexpected %s authorization URL: %s", test.provider, authorization)
		}
		for _, scope := range test.scopes {
			if !strings.Contains(" "+parsed.Query().Get("scope")+" ", " "+scope+" ") {
				t.Fatalf("%s authorization URL is missing scope %s", test.provider, scope)
			}
		}
		if test.provider != "facebook" && parsed.Query().Get("nonce") != "nonce" {
			t.Fatalf("%s authorization URL is missing the nonce", test.provider)
		}
	}
}
