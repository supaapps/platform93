package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/supaapps/platform93/internal/kernel"
)

func TestCreateFeatureDistinguishesMissingAndUnsupportedValueType(t *testing.T) {
	tests := []struct {
		name       string
		body       map[string]any
		code       string
		detailPart string
	}{
		{
			name:       "missing value type",
			body:       map[string]any{"key": "tokens", "name": "Tokens"},
			code:       "invalid_feature",
			detailPart: "value_type are required",
		},
		{
			name:       "unsupported numeric alias",
			body:       map[string]any{"key": "tokens", "name": "Tokens", "value_type": "number"},
			code:       "invalid_feature_value_type",
			detailPart: "boolean, quantity, free_form",
		},
		{
			name:       "free form without format",
			body:       map[string]any{"key": "rules", "name": "Rules", "value_type": "free_form"},
			code:       "invalid_free_form_format",
			detailPart: "text, csv, json",
		},
		{
			name:       "format on boolean feature",
			body:       map[string]any{"key": "export", "name": "Export", "value_type": "boolean", "free_form_format": "json"},
			code:       "unexpected_free_form_format",
			detailPart: "only for free-form features",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{}
			request := requestWithRoute(t, http.MethodPost, "/v1/control/applications/application/features", test.body, map[string]string{"application_id": "application"}, kernel.Actor{})
			response := httptest.NewRecorder()

			server.createFeature(response, request)

			if response.Code != http.StatusUnprocessableEntity {
				t.Fatalf("expected 422, got %d: %s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) || !strings.Contains(response.Body.String(), test.detailPart) {
				t.Fatalf("unexpected problem response: %s", response.Body.String())
			}
		})
	}
}

func TestValidateFreeFormValue(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		value   any
		wantErr bool
	}{
		{name: "raw text", format: "text", value: "anything goes"},
		{name: "text rejects objects", format: "text", value: map[string]any{"invalid": true}, wantErr: true},
		{name: "consistent CSV", format: "csv", value: "name,limit\nBasic,5"},
		{name: "inconsistent CSV", format: "csv", value: "name,limit\nBasic", wantErr: true},
		{name: "JSON object", format: "json", value: map[string]any{"regions": []string{"CH", "DE"}}},
		{name: "JSON scalar", format: "json", value: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			err = validateFreeFormValue(test.format, raw)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateFreeFormValue() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
