package httpapi

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestValidateEmailHTML(t *testing.T) {
	managedID := "01900000-0000-7000-8000-000000000020"
	assets, err := validateEmailHTML(`<h2>Hello {{first_name}}</h2><img src="https://assets.example.test/logo.png" data-p93-object-id="` + managedID + `"><a href="{{sign_in_url}}">Sign in</a>`)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(assets, []string{managedID}) {
		t.Fatalf("unexpected managed assets: %#v", assets)
	}

	unsafe := []string{
		`<script>alert(1)</script>`,
		`<img src="http://assets.example.test/logo.png">`,
		`<img src="https://assets.example.test/logo.png" onerror="alert(1)">`,
		`<a href="javascript:alert(1)">Open</a>`,
		`<div style="background:url(https://tracker.example/pixel)">Tracked</div>`,
		`<img src="https://assets.example.test/logo.png" data-p93-object-id="not-a-uuid">`,
	}
	for _, value := range unsafe {
		if _, err = validateEmailHTML(value); err == nil {
			t.Errorf("unsafe HTML accepted: %s", value)
		}
	}
}

func TestBuiltInEmailTemplatesUseSafeDesignedFrames(t *testing.T) {
	migration, err := os.ReadFile("../../migrations/00001_foundation.sql")
	if err != nil {
		t.Fatal(err)
	}
	templates := regexp.MustCompile(`(?s)\$email\$(.*?)\$email\$`).FindAllStringSubmatch(string(migration), -1)
	if len(templates) != 9 {
		t.Fatalf("found %d designed system templates, want 9", len(templates))
	}
	for index, match := range templates {
		html := match[1]
		if _, err = validateEmailHTML(html); err != nil {
			t.Fatalf("system template %d contains unsafe HTML: %v", index+1, err)
		}
		for _, required := range []string{"role=\"presentation\"", "max-width:600px", "border-top:6px solid #d9ff43"} {
			if !strings.Contains(html, required) {
				t.Fatalf("system template %d is missing frame marker %q", index+1, required)
			}
		}
	}
}
