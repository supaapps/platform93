package httpapi

import (
	"net/url"
	"reflect"
	"testing"
)

func TestNotificationLocaleNormalizationAndFallbacks(t *testing.T) {
	for input, expected := range map[string]string{"de_ch": "de-CH", "EN-gb": "en-GB", "pt-br": "pt-BR", "": ""} {
		actual, err := normalizeNotificationLocale(input)
		if err != nil || actual != expected {
			t.Fatalf("normalize %q: got %q, %v; want %q", input, actual, err, expected)
		}
	}
	if _, err := normalizeNotificationLocale("not a locale"); err == nil {
		t.Fatal("invalid locale was accepted")
	}
	if actual := notificationLocaleFallbacks("zh-Hant-TW"); !reflect.DeepEqual(actual, []string{"zh-Hant-TW", "zh-Hant", "zh", "en"}) {
		t.Fatalf("unexpected locale fallback chain: %#v", actual)
	}
}

func TestNotificationTemplateRenderingEscapesHTMLVariables(t *testing.T) {
	schema := map[string]any{"properties": map[string]any{"name": map[string]any{"type": "string"}}}
	if err := validateTemplatePlaceholders("Hello {{ name }}", schema); err != nil {
		t.Fatal(err)
	}
	rendered, err := renderNotificationTemplate("<p>Hello {{name}}</p>", map[string]any{"name": `<img src=x onerror="alert(1)">`}, true)
	if err != nil {
		t.Fatal(err)
	}
	if rendered != "<p>Hello &lt;img src=x onerror=&#34;alert(1)&#34;&gt;</p>" {
		t.Fatalf("unexpected rendered HTML: %s", rendered)
	}
	if !unsafeEmailHTML(`<a href="javascript:alert(1)">x</a>`) || !unsafeEmailHTML("<script>x</script>") {
		t.Fatal("unsafe HTML was accepted")
	}
}

func TestNotificationTemplateVariablesEnforceDeclaredTypes(t *testing.T) {
	schema := map[string]any{
		"properties": map[string]any{
			"name":  map[string]any{"type": "string"},
			"count": map[string]any{"type": "integer"},
			"paid":  map[string]any{"type": "boolean"},
		},
		"required": []any{"name"},
	}
	if err := validateTemplatePlaceholders("Hello {{name}}, count {{count}}", schema); err != nil {
		t.Fatal(err)
	}
	if err := validateTemplateVariables(schema, map[string]any{"name": "Ada", "count": float64(2), "paid": true}); err != nil {
		t.Fatal(err)
	}
	for _, variables := range []map[string]any{
		{"count": float64(2)},
		{"name": "Ada", "count": 2.5},
		{"name": "Ada", "unknown": "value"},
	} {
		if err := validateTemplateVariables(schema, variables); err == nil {
			t.Fatalf("invalid variables were accepted: %#v", variables)
		}
	}
}

func TestNotificationTemplateSchemaRejectsUnsupportedTypes(t *testing.T) {
	schema := map[string]any{"properties": map[string]any{"user": map[string]any{"type": "object"}}}
	if err := validateTemplatePlaceholders("Hello {{user}}", schema); err == nil {
		t.Fatal("object template variable was accepted")
	}
}

func TestNotificationTemplateBuiltInsDoNotNeedSchemaDeclarations(t *testing.T) {
	if err := validateTemplatePlaceholders("Hello {{first_name}} from {{application_name}}", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	variables := map[string]any{"first_name": "Ada", "application_name": "Analytical Engine"}
	if err := validateTemplateVariables(map[string]any{}, variables); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationTemplateBuiltInsCannotBeRedeclaredOrSpoofed(t *testing.T) {
	schema := map[string]any{"properties": map[string]any{"first_name": map[string]any{"type": "string"}}}
	if err := validateTemplatePlaceholders("Hello {{first_name}}", schema); err == nil {
		t.Fatal("built-in variable redeclaration was accepted")
	}
	merged := mergeNotificationTemplateVariables(
		map[string]any{"first_name": "Mallory", "order_number": "A-1"},
		map[string]any{"first_name": "Ada", "email": "ada@example.com"},
	)
	if merged["first_name"] != "Ada" || merged["order_number"] != "A-1" {
		t.Fatalf("unexpected merged variables: %#v", merged)
	}
	withoutUser := mergeNotificationTemplateVariables(map[string]any{"last_name": "Spoofed"}, map[string]any{"application_name": "Engine"})
	if _, exists := withoutUser["last_name"]; exists {
		t.Fatalf("unresolved built-in variable was accepted: %#v", withoutUser)
	}
}

func TestNotificationTemplateCatalogSamplesMatchDeclaredTypes(t *testing.T) {
	variables := map[string]any{}
	for _, definition := range notificationTemplateVariableCatalog() {
		variables[definition.Key] = definition.Sample
	}
	if err := validateTemplateVariables(map[string]any{}, variables); err != nil {
		t.Fatal(err)
	}
	rendered, err := renderNotificationTemplate("Copyright {{current_year}}", variables, false)
	if err != nil || rendered != "Copyright 2026" {
		t.Fatalf("unexpected built-in rendering: %q, %v", rendered, err)
	}
}

func TestCredentialLinkPreservesApplicationQuery(t *testing.T) {
	value := appendCredentialQuery("https://app.example/auth/callback?source=email", map[string]string{
		"challenge_id": "challenge", "link_token": "secret token",
	})
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("source") != "email" || parsed.Query().Get("challenge_id") != "challenge" || parsed.Query().Get("link_token") != "secret token" {
		t.Fatalf("unexpected credential URL: %s", value)
	}
}

func TestApplicationFlowConfigRequiresCompletePKCEBoundary(t *testing.T) {
	config, err := parseApplicationFlowConfig([]byte(`{"oauth_client_id":"web","sign_in_redirect_uri":"https://app.example/auth/callback","invitation_redirect_uri":"https://app.example/invitations/accept"}`))
	if err != nil || config.OAuthClientID != "web" {
		t.Fatalf("valid flow config was rejected: %#v %v", config, err)
	}
	if _, err = parseApplicationFlowConfig([]byte(`{"sign_in_redirect_uri":"https://app.example/auth/callback"}`)); err == nil {
		t.Fatal("partial flow config was accepted")
	}
}
