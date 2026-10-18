package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResourceOAuthMetadataValidation(t *testing.T) {
	const clientID = "https://client.example.test/oauth-client.json"
	valid := func() resourceClientMetadata {
		return resourceClientMetadata{ClientID: clientID, ClientName: "Published client", RedirectURIs: []string{"https://client.example.test/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none"}
	}
	for _, redirect := range []string{"https://client.example.test/callback", "http://127.0.0.1:49152/callback", "http://[::1]:49152/callback"} {
		t.Run("valid/"+redirect, func(t *testing.T) {
			metadata := valid()
			metadata.RedirectURIs = []string{redirect}
			if err := validateResourceClientMetadata(clientID, metadata); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, redirect := range []string{"http://client.example.test/callback", "http://localhost/callback", "javascript:alert(1)", "https://user:password@client.example.test/callback", "https://client.example.test/callback#fragment", "/callback", "https://client.example.test/" + strings.Repeat("x", 2048)} {
		t.Run("invalid redirect/"+redirect[:min(len(redirect), 80)], func(t *testing.T) {
			metadata := valid()
			metadata.RedirectURIs = []string{redirect}
			if validateResourceClientMetadata(clientID, metadata) == nil {
				t.Fatal("unsafe redirect accepted")
			}
		})
	}
	for _, expected := range []string{"http://client.example.test/metadata", "https://user@client.example.test/metadata", "https://client.example.test/metadata?secret=1", "https://client.example.test/metadata#fragment", "/metadata"} {
		t.Run("invalid identity/"+expected, func(t *testing.T) {
			metadata := valid()
			metadata.ClientID = expected
			if validateResourceClientMetadata(expected, metadata) == nil {
				t.Fatal("unsafe metadata identity accepted")
			}
		})
	}
	cases := map[string]func(*resourceClientMetadata){
		"missing name":            func(m *resourceClientMetadata) { m.ClientName = "" },
		"published secret":        func(m *resourceClientMetadata) { m.ClientSecret = json.RawMessage(`"not-a-credential"`) },
		"published secret expiry": func(m *resourceClientMetadata) { m.ClientSecretExpiresAt = json.RawMessage(`0`) },
		"identity mismatch":       func(m *resourceClientMetadata) { m.ClientID = "https://other.example.test/client.json" },
		"confidential auth":       func(m *resourceClientMetadata) { m.TokenEndpointAuthMethod = "client_secret_basic" },
		"missing auth":            func(m *resourceClientMetadata) { m.TokenEndpointAuthMethod = "" },
		"machine grant":           func(m *resourceClientMetadata) { m.GrantTypes = []string{"client_credentials"} },
		"implicit response":       func(m *resourceClientMetadata) { m.ResponseTypes = []string{"token"} },
		"missing redirects":       func(m *resourceClientMetadata) { m.RedirectURIs = nil },
		"too many redirects":      func(m *resourceClientMetadata) { m.RedirectURIs = make([]string, 17) },
		"long name":               func(m *resourceClientMetadata) { m.ClientName = strings.Repeat("x", 201) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			metadata := valid()
			mutate(&metadata)
			if validateResourceClientMetadata(clientID, metadata) == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	for _, suffix := range []string{"", "/a/../client.json", "/%2e/client.json"} {
		metadata := valid()
		metadata.ClientID = "https://client.example.test" + suffix
		if validateResourceClientMetadata(metadata.ClientID, metadata) == nil {
			t.Fatalf("accepted invalid metadata identity path %q", suffix)
		}
	}
}
