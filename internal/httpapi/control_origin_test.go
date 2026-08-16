package httpapi

import "testing"

func TestAllowedControlOrigin(t *testing.T) {
	tests := []struct {
		origin, publicURL string
		allowed           bool
	}{
		{"https://platform93.example", "https://platform93.example", true},
		{"http://127.0.0.1:8093", "http://localhost:8093", true},
		{"http://[::1]:8093", "http://localhost:8093", true},
		{"http://127.0.0.1:8094", "http://localhost:8093", false},
		{"https://127.0.0.1:8093", "http://localhost:8093", false},
		{"https://other.example", "https://platform93.example", false},
	}
	for _, test := range tests {
		if actual := allowedControlOrigin(test.origin, test.publicURL); actual != test.allowed {
			t.Errorf("allowedControlOrigin(%q, %q) = %v, want %v", test.origin, test.publicURL, actual, test.allowed)
		}
	}
}
