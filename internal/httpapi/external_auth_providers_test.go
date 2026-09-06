package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFacebookDebugRequestKeepsAppAccessTokenOutOfURL(t *testing.T) {
	t.Parallel()
	const (
		inputToken     = "facebook-user-token"
		appAccessToken = "facebook-client|facebook-secret"
	)
	request, err := newFacebookDebugRequest(context.Background(), inputToken, appAccessToken)
	if err != nil {
		t.Fatalf("newFacebookDebugRequest returned an error: %v", err)
	}
	if strings.Contains(request.URL.String(), appAccessToken) || strings.Contains(request.URL.String(), "facebook-secret") {
		t.Fatalf("Facebook debug URL contains the app access token: %s", request.URL.Redacted())
	}
	if request.URL.Query().Get("input_token") != inputToken {
		t.Fatalf("Facebook debug URL has the wrong input token")
	}
	if got := request.Header.Get("Authorization"); got != "Bearer "+appAccessToken {
		t.Fatalf("Authorization header = %q, want a bearer app access token", got)
	}
}

func TestFacebookProfileRequestKeepsUserAccessTokenOutOfURL(t *testing.T) {
	t.Parallel()
	const (
		accessToken    = "facebook-user-token"
		appSecretProof = "signed-token-proof"
	)
	request, err := newFacebookProfileRequest(context.Background(), accessToken, appSecretProof)
	if err != nil {
		t.Fatalf("newFacebookProfileRequest returned an error: %v", err)
	}
	if strings.Contains(request.URL.String(), accessToken) || request.URL.Query().Has("access_token") {
		t.Fatalf("Facebook profile URL contains the user access token: %s", request.URL.Redacted())
	}
	if request.URL.Query().Get("appsecret_proof") != appSecretProof {
		t.Fatal("Facebook profile URL has the wrong app-secret proof")
	}
	if got := request.Header.Get("Authorization"); got != "Bearer "+accessToken {
		t.Fatalf("Authorization header = %q, want a bearer user access token", got)
	}
}

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

func TestProviderVerifierValue(t *testing.T) {
	const verifier = "generated-verifier"
	for _, provider := range []string{"google", "microsoft", "linkedin"} {
		if value := providerVerifierValue(provider, verifier); value != verifier {
			t.Fatalf("expected %s to retain its PKCE verifier, got %q", provider, value)
		}
	}
	for _, provider := range []string{"apple", "facebook"} {
		if value := providerVerifierValue(provider, verifier); value != provider {
			t.Fatalf("expected %s placeholder, got %q", provider, value)
		}
	}
}

func TestExternalAuthRequiresPKCE(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		publicClient bool
		flow         string
		want         bool
	}{
		{name: "public sign in", publicClient: true, flow: "sign_in", want: true},
		{name: "confidential sign in", flow: "sign_in", want: false},
		{name: "confidential sign up", flow: "sign_up", want: true},
		{name: "confidential automatic", flow: "automatic", want: true},
		{name: "confidential link", flow: "link", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := externalAuthRequiresPKCE(test.publicClient, test.flow); got != test.want {
				t.Fatalf("externalAuthRequiresPKCE(%v, %q) = %v, want %v", test.publicClient, test.flow, got, test.want)
			}
		})
	}
}

func TestChallengeProviderMatches(t *testing.T) {
	t.Parallel()
	configured := "provider-config"
	other := "other-provider-config"
	if !challengeProviderMatches(nil, configured) {
		t.Fatal("a challenge created before provider pinning should remain valid")
	}
	if !challengeProviderMatches(&configured, configured) {
		t.Fatal("a challenge pinned to the active provider should remain valid")
	}
	if challengeProviderMatches(&other, configured) {
		t.Fatal("a challenge pinned to another provider must be rejected")
	}
}

func TestExternalEmailVerificationRejectsMultipleCredentials(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, "/v1/applications/application/auth/external-email/verify",
		strings.NewReader(`{"enrollment":"enrollment:secret","code":"ABCD2345","link_token":"link-secret"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	(&Server{}).verifyExternalEmailEnrollment(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("verification returned %d, want %d: %s", response.Code, http.StatusUnprocessableEntity, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "exactly one email verification credential") {
		t.Fatalf("verification returned an unclear problem: %s", response.Body.String())
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
