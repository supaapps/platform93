package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
)

func (f *workspaceHTTPFixture) controlJSON(method, path string, body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.optionalJSON(method, "/v1/control/applications/"+f.application+path, body, true)
}

func (f *workspaceHTTPFixture) optionalJSON(method, path string, body map[string]any, control bool) *httptest.ResponseRecorder {
	f.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", kernel.NewID().String())
	if method == http.MethodPatch {
		r.Header.Set("If-Match", kernel.ETag(1))
	}
	if control {
		r.Header.Set("Origin", f.app.PublicURL)
		r.AddCookie(&http.Cookie{Name: "p93_control_access", Value: f.controlToken})
	} else {
		r.Header.Set("Authorization", "Bearer "+f.accessToken(false))
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func TestOptionalClientArraysPostgres(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	for _, mode := range []string{"omitted", "null", "empty", "supplied"} {
		t.Run(mode, func(t *testing.T) {
			body := map[string]any{"client_id": "optional-" + mode, "name": "Optional arrays", "client_type": "public"}
			want := map[string][]string{"redirect_uris": {}, "allowed_grants": {}, "allowed_scopes": {}}
			for field := range want {
				switch mode {
				case "null":
					body[field] = nil
				case "empty":
					body[field] = []string{}
				case "supplied":
					values := map[string][]string{"redirect_uris": {"https://client.example.test/callback"}, "allowed_grants": {"authorization_code"}, "allowed_scopes": {"openid"}}
					body[field], want[field] = values[field], values[field]
				}
			}
			w := f.controlJSON("POST", "/clients", body)
			if w.Code != 201 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			var redirects, grants, scopes []string
			if err := f.app.DB.QueryRow(context.Background(), `SELECT redirect_uris,allowed_grants,allowed_scopes FROM clients WHERE application_id=$1 AND client_id=$2`, f.application, body["client_id"]).Scan(&redirects, &grants, &scopes); err != nil {
				t.Fatal(err)
			}
			for key, got := range map[string][]string{"redirect_uris": redirects, "allowed_grants": grants, "allowed_scopes": scopes} {
				if !reflect.DeepEqual(got, want[key]) {
					t.Fatalf("%s: %#v", key, got)
				}
			}
		})
	}
}

func TestOptionalObjectDefaultsPostgres(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	product := kernel.NewID().String()
	f.exec(`INSERT INTO products(id,application_id,key,name,status) VALUES($1,$2,'price-parent','Parent','active')`, product, f.application)
	for _, resource := range []struct {
		path, table, field string
		base               map[string]any
	}{
		{"/features", "features", "metadata", map[string]any{"key": "feature", "name": "Feature", "value_type": "boolean"}},
		{"/products", "products", "metadata", map[string]any{"key": "product", "name": "Product"}},
		{"/products/" + product + "/prices", "prices", "checkout_config", map[string]any{"key": "price", "mode": "one_time", "amount_minor": 100, "currency": "EUR"}},
		{"/users", "users", "custom_attributes", map[string]any{"email": "user@example.test"}},
		{"/notification-templates", "notification_templates", "variable_schema", map[string]any{"key": "optional_template", "category": "transactional", "subject_template": "Hello", "text_template": "Hello"}},
	} {
		for _, mode := range []string{"omitted", "null", "empty", "supplied"} {
			t.Run(resource.table+"/"+mode, func(t *testing.T) {
				body := map[string]any{}
				for key, value := range resource.base {
					body[key] = value
				}
				if value, ok := body["key"].(string); ok {
					body["key"] = value + "_" + mode
				}
				if resource.table == "users" {
					body["email"] = mode + "@example.test"
				}
				want := map[string]any{}
				switch mode {
				case "null":
					body[resource.field] = nil
				case "empty":
					body[resource.field] = map[string]any{}
				case "supplied":
					want = map[string]any{"enabled": true, "nested": map[string]any{"value": "preserved"}}
					if resource.field == "checkout_config" {
						want = map[string]any{"automatic_tax": true}
					}
					if resource.field == "variable_schema" {
						want = map[string]any{"type": "object", "properties": map[string]any{}}
					}
					body[resource.field] = want
				}
				w := f.controlJSON("POST", resource.path, body)
				if w.Code != 201 {
					t.Fatalf("%d %s", w.Code, w.Body.String())
				}
				var result map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				var raw []byte
				query := fmt.Sprintf("SELECT %s FROM %s WHERE id=$1 AND application_id=$2", resource.field, resource.table)
				if err := f.app.DB.QueryRow(context.Background(), query, result["id"], f.application).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var got map[string]any
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("stored %s: %s", resource.field, raw)
				}
				if value, exists := result[resource.field]; exists && !reflect.DeepEqual(value, want) {
					t.Fatalf("response %s: %#v", resource.field, value)
				}
			})
		}
	}
}

type optionalCheckoutTransport func(*http.Request) (*http.Response, error)

func (f optionalCheckoutTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCheckoutProviderDefaultMethodsPostgres(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	product, price, provider := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	f.exec(`INSERT INTO products(id,application_id,key,name,status) VALUES($1,$2,'checkout','Checkout','active')`, product, f.application)
	f.exec(`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency) VALUES($1,$2,$3,'checkout','one_time',100,'CHF')`, price, f.application, product)
	secret, err := f.app.Vault.Encrypt([]byte("fixture-provider-secret"), "billing-provider:"+provider+":secret")
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO provider_connections(id,application_id,provider,public_id,api_version,secret_ciphertext) VALUES($1,$2,'stripe',$1::uuid::text,$3,$4)`, provider, f.application, stripeAPIVersion, secret)
	f.exec(`INSERT INTO provider_mappings(id,application_id,provider_connection_id,object_type,internal_id,provider_id) VALUES($1,$2,$3,'price',$4,'price_fixture')`, kernel.NewID(), f.application, provider, price)
	f.exec(`INSERT INTO billing_customers(id,application_id,subject_type,subject_id,provider_connection_id,provider_customer_id) VALUES($1,$2,'user',$3,$4,'cus_fixture')`, kernel.NewID(), f.application, f.user, provider)
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	for _, mode := range []string{"omitted", "null", "empty", "card", "twint", "price_default"} {
		t.Run(mode, func(t *testing.T) {
			config := `{}`
			if mode == "price_default" {
				config = `{"payment_methods":["card"]}`
			}
			f.exec(`UPDATE prices SET checkout_config=$1 WHERE id=$2`, []byte(config), price)
			body := map[string]any{"price_id": price, "success_uri": "https://client.example.test/callback", "cancel_uri": "https://client.example.test/callback"}
			want := []string{}
			switch mode {
			case "null":
				body["payment_methods"] = nil
			case "empty":
				body["payment_methods"] = []string{}
			case "card", "twint":
				want = []string{mode}
				body["payment_methods"] = want
			case "price_default":
				want = []string{"card"}
			}
			calls := 0
			http.DefaultTransport = optionalCheckoutTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "https" || r.URL.Host != "api.stripe.com" || r.URL.Path != "/v1/checkout/sessions" {
					return nil, fmt.Errorf("unexpected provider request")
				}
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				for i, method := range want {
					if r.Form.Get(fmt.Sprintf("payment_method_types[%d]", i)) != method {
						t.Errorf("wrong provider methods: %v", r.Form)
					}
				}
				if len(want) == 0 {
					for key := range r.Form {
						if strings.HasPrefix(key, "payment_method_types") {
							t.Error("provider-default flow forced payment methods")
						}
					}
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"cs_` + mode + `","url":"https://checkout.stripe.com/fixture"}`))}, nil
			})
			w := f.optionalJSON("POST", "/v1/applications/"+f.application+"/billing/checkout-sessions", body, false)
			if w.Code != 201 {
				t.Fatalf("%d %s (provider calls=%d)", w.Code, w.Body.String(), calls)
			}
			if calls != 1 {
				t.Fatalf("provider calls=%d", calls)
			}
			var methods []string
			var policy []byte
			if err := f.app.DB.QueryRow(context.Background(), `SELECT payment_methods,policy_snapshot FROM checkout_sessions WHERE provider_session_id=$1`, "cs_"+mode).Scan(&methods, &policy); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(methods, want) {
				t.Fatalf("stored methods: %#v", methods)
			}
			var snapshot map[string]any
			if err := json.Unmarshal(policy, &snapshot); err != nil {
				t.Fatal(err)
			}
			wantPolicy := make([]any, len(want))
			for index, method := range want {
				wantPolicy[index] = method
			}
			if !reflect.DeepEqual(snapshot["payment_methods"], wantPolicy) {
				t.Fatalf("policy snapshot methods: %#v", snapshot["payment_methods"])
			}
		})
	}
}

func TestCreationErrorClassificationPostgres(t *testing.T) {
	for _, resource := range []struct {
		path, table, conflict string
		body                  map[string]any
	}{
		{"/clients", "clients", "client_conflict", map[string]any{"client_id": "conflict-client", "name": "Client", "client_type": "public"}},
		{"/features", "features", "feature_conflict", map[string]any{"key": "conflict-feature", "name": "Feature", "value_type": "boolean"}},
		{"/products", "products", "product_conflict", map[string]any{"key": "conflict-product", "name": "Product"}},
		{"/prices", "prices", "price_conflict", map[string]any{"key": "conflict-price", "mode": "one_time", "currency": "EUR", "amount_minor": 100}},
		{"/roles", "roles", "role_conflict", map[string]any{"key": "conflict-role", "name": "Role", "scope": "application", "permissions": []string{"billing:read"}}},
		{"/users", "users", "user_creation_failed", map[string]any{"email": "created@example.test"}},
		{"/notification-templates", "notification_templates", "", map[string]any{"key": "conflict_template", "category": "transactional", "subject_template": "Hello", "text_template": "Hello"}},
		{"/invitations", "application_invitations", "invitation_conflict", map[string]any{"email": "invited@example.test", "send_email": false}},
	} {
		t.Run(resource.table, func(t *testing.T) {
			f := newWorkspaceHTTPFixture(t)
			path := resource.path
			if resource.table == "prices" {
				product := kernel.NewID().String()
				f.exec(`INSERT INTO products(id,application_id,key,name) VALUES($1,$2,'parent','Parent')`, product, f.application)
				path = "/products/" + product + "/prices"
			}
			if resource.table == "application_invitations" {
				flow, _ := json.Marshal(map[string]any{"flows": map[string]any{"oauth_client_id": f.client, "sign_in_redirect_uri": "https://client.example.test/callback", "invitation_redirect_uri": "https://client.example.test/callback"}})
				f.exec(`UPDATE applications SET auth_config=$1 WHERE id=$2`, flow, f.application)
			}
			w := f.controlJSON("POST", path, resource.body)
			if w.Code != 201 {
				t.Fatalf("initial creation: %d %s", w.Code, w.Body.String())
			}
			if resource.conflict != "" {
				w = f.controlJSON("POST", path, resource.body)
				if w.Code != 409 || !strings.Contains(w.Body.String(), resource.conflict) {
					t.Fatalf("duplicate: %d %s", w.Code, w.Body.String())
				}
			}
			var before int
			count := fmt.Sprintf("SELECT count(*) FROM %s WHERE application_id=$1", resource.table)
			if err := f.app.DB.QueryRow(context.Background(), count, f.application).Scan(&before); err != nil {
				t.Fatal(err)
			}
			f.exec(`CREATE FUNCTION reject_test_creation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23505', CONSTRAINT='unrelated_unique_key', MESSAGE='private-value-must-not-be-returned'; END $$`)
			f.exec(fmt.Sprintf(`CREATE TRIGGER reject_test_creation BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_test_creation()`, resource.table))
			w = f.controlJSON("POST", path, resource.body)
			if w.Code != 500 || strings.Contains(w.Body.String(), "private-value-must-not-be-returned") {
				t.Fatalf("unrelated failure: %d %s", w.Code, w.Body.String())
			}
			var after int
			if err := f.app.DB.QueryRow(context.Background(), count, f.application).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatal("failed creation changed resource count")
			}
		})
	}
}

func TestOptionalUpdatesPreserveExistingValuesPostgres(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	for _, resource := range []struct {
		path, field    string
		create, update map[string]any
	}{
		{"/products", "metadata", map[string]any{"key": "preserve", "name": "Product"}, map[string]any{"name": "Updated"}},
		{"/users", "custom_attributes", map[string]any{"email": "preserve@example.test"}, map[string]any{"first_name": "Updated"}},
		{"/notification-templates", "variable_schema", map[string]any{"key": "preserve_template", "category": "transactional", "subject_template": "Hello", "text_template": "Hello"}, map[string]any{"subject_template": "Updated"}},
	} {
		t.Run(resource.path, func(t *testing.T) {
			value := map[string]any{"preserved": true}
			resource.create[resource.field] = value
			w := f.controlJSON("POST", resource.path, resource.create)
			if w.Code != 201 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			var result map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			path := resource.path + "/" + result["id"].(string)
			w = f.controlJSON("PATCH", path, resource.update)
			if w.Code < 200 || w.Code >= 300 {
				t.Fatalf("patch: %d %s", w.Code, w.Body.String())
			}
			w = f.controlJSON("GET", path, nil)
			if w.Code != 200 {
				t.Fatalf("get: %d %s", w.Code, w.Body.String())
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result[resource.field], value) {
				t.Fatalf("omission cleared %s: %#v", resource.field, result[resource.field])
			}
		})
	}
}

func TestOptionalObjectMigrationPostgres(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	dsn := f.app.DB.Config().ConnString()
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := goose.DownTo(sqlDB, ".", 5); err != nil {
		t.Fatal(err)
	}
	product, price, feature, template := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	f.exec(`INSERT INTO products(id,application_id,key,name,metadata) VALUES($1,$2,'legacy','Legacy','null'::jsonb)`, product, f.application)
	f.exec(`INSERT INTO products(id,application_id,key,name,metadata) VALUES($1,$2,'preserved','Preserved','{"preserved":true}'::jsonb)`, kernel.NewID(), f.application)
	f.exec(`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency,checkout_config) VALUES($1,$2,$3,'legacy','one_time',100,'EUR','null'::jsonb)`, price, f.application, product)
	f.exec(`INSERT INTO features(id,application_id,key,name,value_type,metadata) VALUES($1,$2,'legacy','Legacy','boolean','null'::jsonb)`, feature, f.application)
	f.exec(`UPDATE users SET custom_attributes='null'::jsonb WHERE id=$1`, f.user)
	f.exec(`INSERT INTO notification_templates(id,application_id,key,locale,category,version,subject_template,text_template,variable_schema) VALUES($1,$2,'legacy','en','transactional',1,'Hello','Hello','null'::jsonb)`, template, f.application)
	if err := database.Migrate(dsn); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`SELECT metadata FROM features WHERE key='legacy' AND application_id=$1`,
		`SELECT metadata FROM products WHERE key='legacy' AND application_id=$1`,
		`SELECT checkout_config FROM prices WHERE key='legacy' AND application_id=$1`,
		`SELECT custom_attributes FROM users WHERE application_id=$1`,
		`SELECT variable_schema FROM notification_templates WHERE key='legacy' AND application_id=$1`,
	} {
		var raw []byte
		if err := f.app.DB.QueryRow(context.Background(), query, f.application).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if string(raw) != "{}" {
			t.Fatalf("migration left %s", raw)
		}
	}
	var preserved []byte
	if err := f.app.DB.QueryRow(context.Background(), `SELECT metadata FROM products WHERE key='preserved' AND application_id=$1`, f.application).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(preserved, &value); err != nil || value["preserved"] != true {
		t.Fatalf("migration changed supplied metadata: %s", preserved)
	}
	if err := goose.DownTo(sqlDB, ".", 5); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(dsn); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogFeatureCreationErrorsPostgres(t *testing.T) {
	for _, owner := range []string{"product", "price"} {
		t.Run(owner, func(t *testing.T) {
			f := newWorkspaceHTTPFixture(t)
			feature, parent := kernel.NewID().String(), kernel.NewID().String()
			f.exec(`INSERT INTO features(id,application_id,key,name,value_type) VALUES($1,$2,'flag','Flag','boolean')`, feature, f.application)
			f.exec(`INSERT INTO products(id,application_id,key,name) VALUES($1,$2,'parent','Parent')`, parent, f.application)
			path := "/products"
			body := func(key string, features []map[string]any) map[string]any {
				b := map[string]any{"key": key, "name": "Feature errors", "features": features}
				if owner == "price" {
					delete(b, "name")
					b["mode"] = "one_time"
					b["amount_minor"] = 100
					b["currency"] = "EUR"
				}
				return b
			}
			if owner == "price" {
				path = "/products/" + parent + "/prices"
			}
			for _, test := range []struct {
				key      string
				features []map[string]any
			}{
				{"malformed", []map[string]any{{"feature_id": "not-a-uuid", "boolean_value": true}}},
				{"missing", []map[string]any{{"feature_id": kernel.NewID().String(), "boolean_value": true}}},
				{"wrong_type", []map[string]any{{"feature_id": feature, "quantity_value": 3}}},
				{"duplicate", []map[string]any{{"feature_id": feature, "boolean_value": true}, {"feature_id": feature, "boolean_value": true}}},
			} {
				w := f.controlJSON("POST", path, body(test.key, test.features))
				if w.Code != 422 {
					t.Fatalf("%s: %d %s", test.key, w.Code, w.Body.String())
				}
			}
			features := []map[string]any{{"feature_id": feature, "boolean_value": true}}
			f.exec(`ALTER TABLE features RENAME TO temporarily_unavailable_features`)
			w := f.controlJSON("POST", path, body("lookup_failure", features))
			if w.Code != 500 {
				t.Fatalf("lookup error disguised as input: %d %s", w.Code, w.Body.String())
			}
			f.exec(`ALTER TABLE temporarily_unavailable_features RENAME TO features`)
			f.exec(`CREATE FUNCTION reject_test_feature() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23505', CONSTRAINT='unrelated_unique_key', MESSAGE='invalid feature private-provider-detail'; END $$`)
			f.exec(fmt.Sprintf(`CREATE TRIGGER reject_test_feature BEFORE INSERT ON %s_features FOR EACH ROW EXECUTE FUNCTION reject_test_feature()`, owner))
			w = f.controlJSON("POST", path, body("storage_failure", features))
			if w.Code != 500 || strings.Contains(w.Body.String(), "private-provider-detail") {
				t.Fatalf("storage error disguised as input: %d %s", w.Code, w.Body.String())
			}
			if owner == "product" {
				w = f.controlJSON("PATCH", "/products/"+parent, map[string]any{"features": features})
				if w.Code != 500 {
					t.Fatalf("update storage failure disguised as version conflict: %d %s", w.Code, w.Body.String())
				}
				var version int
				if err := f.app.DB.QueryRow(context.Background(), `SELECT version FROM products WHERE id=$1`, parent).Scan(&version); err != nil {
					t.Fatal(err)
				}
				if version != 1 {
					t.Fatal("failed product update was not rolled back")
				}
			}
			var partial int
			if err := f.app.DB.QueryRow(context.Background(), fmt.Sprintf(`SELECT count(*) FROM %ss WHERE application_id=$1 AND key!='parent'`, owner), f.application).Scan(&partial); err != nil {
				t.Fatal(err)
			}
			if partial != 0 {
				t.Fatal("failed feature creation left partial catalog records")
			}
		})
	}
}
