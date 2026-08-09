package httpapi

import "testing"

func TestValidDomainHostname(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"example.com":          true,
		"login.example.com":    true,
		"EXAMPLE.com":          false,
		"localhost":            false,
		"127.0.0.1":            false,
		"*.example.com":        false,
		"-bad.example.com":     false,
		"bad-.example.com":     false,
		"bad_name.example.com": false,
	}
	for hostname, expected := range tests {
		if actual := validDomainHostname(hostname); actual != expected {
			t.Errorf("validDomainHostname(%q) = %v, want %v", hostname, actual, expected)
		}
	}
}

func TestNormalizeHostname(t *testing.T) {
	t.Parallel()
	if got := normalizeHostname(" HTTPS://Login.Example.COM/path "); got != "login.example.com" {
		t.Fatalf("normalizeHostname() = %q", got)
	}
}
