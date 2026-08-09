package httpapi

import (
	"slices"
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
