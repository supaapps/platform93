package httpapi

import (
	"strings"
	"testing"
)

func TestNotificationConditionalDelivery(t *testing.T) {
	const source = `{{#if code}}Code: {{code}}{{/if}}{{#if magic_link}}<a href="{{magic_link}}">Continue</a>{{/if}}`
	for _, tc := range []struct{ name, code, link, want string }{
		{"code", "AB12CD34", "", "Code: AB12CD34"},
		{"link", "", "https://app.example/callback?a=1&b=2", `<a href="https://app.example/callback?a=1&amp;b=2">Continue</a>`},
		{"both", "AB12CD34", "https://app.example/callback", `Code: AB12CD34<a href="https://app.example/callback">Continue</a>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderNotificationTemplate(source, map[string]any{"code": tc.code, "magic_link": tc.link}, true)
			if err != nil || got != tc.want {
				t.Fatalf("render: %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	got, err := renderNotificationTemplate(`{{#if outer}}a{{#if inner}}b{{/if}}c{{/if}}!`, map[string]any{"outer": false, "inner": true}, false)
	if err != nil || got != "!" {
		t.Fatalf("nested: %q, %v", got, err)
	}
	got, err = renderNotificationTemplate(source, map[string]any{"code": `{{#if absent}}<script>x</script>{{/if}}`, "magic_link": ""}, true)
	if err != nil || !strings.Contains(got, "&lt;script&gt;") || !strings.Contains(got, "{{#if absent}}") {
		t.Fatalf("substituted values became instructions or active HTML: %q %v", got, err)
	}
}

func TestNotificationConditionalValidation(t *testing.T) {
	schema := map[string]any{"properties": map[string]any{"code": map[string]any{"type": "string"}}}
	for _, source := range []string{`{{/if}}`, `{{#if code}}`, `{{#if unknown}}x{{/if}}`, `{{#if code other}}x{{/if}}`, strings.Repeat("{{#if code}}", 17) + strings.Repeat("{{/if}}", 17)} {
		if err := validateTemplatePlaceholders(source, schema); err == nil {
			t.Fatalf("invalid conditional accepted: %q", source)
		}
	}
	if err := validateTemplatePlaceholders(`{{#if code}}{{code}}{{/if}}`, schema); err != nil {
		t.Fatal(err)
	}
}
