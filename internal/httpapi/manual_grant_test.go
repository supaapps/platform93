package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestGrantFeatureValidation(t *testing.T) {
	text, csv, jsonFormat := "text", "csv", "json"
	for _, test := range []struct {
		kind   string
		format *string
		value  any
		valid  bool
	}{
		{"boolean", nil, false, true}, {"boolean", nil, "true", false},
		{"quantity", nil, float64(0), true}, {"quantity", nil, float64(-1), false},
		{"quantity", nil, 1.5, false}, {"quantity", nil, math.Exp2(63), false},
		{"free_form", &text, "hello", true}, {"free_form", &text, map[string]any{}, false},
		{"free_form", &csv, "a,b\n1,2", true}, {"free_form", &csv, "\"broken", false},
		{"free_form", &jsonFormat, map[string]any{"nested": true}, true},
	} {
		if err := validateGrantFeature(test.kind, test.format, test.value); (err == nil) != test.valid {
			t.Fatalf("%s %v: %v", test.kind, test.value, err)
		}
	}
}

func TestReferenceSearchValidation(t *testing.T) {
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=wrong", "?cursor=not-a-uuid"} {
		w := httptest.NewRecorder()
		_, _, _, ok := referenceSearch(w, httptest.NewRequest("GET", "/"+query, nil), "SELECT id FROM users WHERE application_id=$1", []any{"app"}, "id", "email")
		if ok || w.Code != 422 {
			t.Fatalf("%s was accepted", query)
		}
	}
	items, cursor := referencePage([]string{"one", "two", "three"}, 2, func(value string) string { return value })
	if len(items) != 2 || cursor != "two" {
		t.Fatalf("bad page: %v %v", items, cursor)
	}
}

func TestManualGrantSnapshotsAndSearchIntegration(t *testing.T) {
	url := os.Getenv("PLATFORM93_DATABASE_URL")
	if url == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(url); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := secure.NewVault(make([]byte, 32))
	s := &Server{app: platform.New(db, vault, "https://platform93.test")}
	org, app, otherApp := kernel.NewID(), kernel.NewID(), kernel.NewID()
	user, user2, foreignUser, workspace := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	product, price, feature, role, client := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	foreignProduct, foreignPrice := kernel.NewID(), kernel.NewID()
	ctx := context.Background()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Search',$2)`, []any{org, org.String()}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Search',$1::uuid::text),($3,$2,'Other',$3::uuid::text)`, []any{app, org, otherApp}},
		{`INSERT INTO users(id,application_id,email,normalized_email,first_name) VALUES($1,$2,'first@example.test','first@example.test','Same'),($3,$2,'second@example.test','second@example.test','Same'),($4,$5,'foreign@example.test','foreign@example.test','Same')`, []any{user, app, user2, foreignUser, otherApp}},
		{`INSERT INTO workspaces(id,application_id,owner_user_id,key,name) VALUES($1,$2,$3,'shared','Shared')`, []any{workspace, app, user}},
		{`INSERT INTO roles(id,application_id,key,name,scope,permissions) VALUES($1,$2,'reader','Reader','application',ARRAY['invoices:read'])`, []any{role, app}},
		{`INSERT INTO clients(id,application_id,client_id,name,client_type) VALUES($1,$2,$1::uuid::text,'Service','machine')`, []any{client, app}},
		{`INSERT INTO features(id,application_id,key,name,value_type) VALUES($1,$2,'projects','Projects','quantity')`, []any{feature, app}},
		{`INSERT INTO products(id,application_id,key,name,status,entitlement_config) VALUES($1,$2,'standard','Standard','active','{"support":"basic"}')`, []any{product, app}},
		{`INSERT INTO product_features(product_id,feature_id,quantity_value) VALUES($1,$2,5)`, []any{product, feature}},
		{`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency,entitlement_config) VALUES($1,$2,$3,'monthly','recurring',1000,'EUR','{"support":"priority"}')`, []any{price, app, product}},
		{`INSERT INTO price_features(price_id,feature_id,quantity_value) VALUES($1,$2,10)`, []any{price, feature}},
		{`INSERT INTO products(id,application_id,key,name,status) VALUES($1,$2,'other','Other','active')`, []any{foreignProduct, otherApp}},
		{`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency) VALUES($1,$2,$3,'other','local',0,'EUR')`, []any{foreignPrice, otherApp, foreignProduct}},
	}
	for _, statement := range statements {
		if _, err := db.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	expires := time.Now().UTC().Add(time.Hour)
	t.Run("idempotent replay", func(t *testing.T) {
		body := map[string]any{"subject_type": "user", "subject_id": user, "product_id": product, "expires_at": expires}
		current := kernel.Actor{Type: "control_user", ID: kernel.NewID().String()}
		key := kernel.NewID().String()
		handler := s.idempotent(http.HandlerFunc(s.createEntitlement))
		var original string
		for attempt := range 2 {
			request := requestWithRoute(t, "POST", "/", body, map[string]string{"application_id": app.String()}, current)
			request.Header.Set("Idempotency-Key", key)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusCreated {
				t.Fatalf("grant replay: %d %s", response.Code, response.Body.String())
			}
			if attempt == 0 {
				original = response.Body.String()
			} else if original != response.Body.String() || response.Header().Get("Idempotent-Replayed") != "true" {
				t.Fatal("replay did not return the original grant")
			}
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM entitlement_grants WHERE application_id=$1`, app).Scan(&count); err != nil || count != 1 {
			t.Fatalf("duplicate grant: count=%d err=%v", count, err)
		}
		body["subject_id"] = user2
		request := requestWithRoute(t, "POST", "/", body, map[string]string{"application_id": app.String()}, current)
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusConflict {
			t.Fatalf("changed body reused key: %d", response.Code)
		}
	})
	t.Run("currency exponents", func(t *testing.T) {
		for _, exponent := range []int{-1, 0, 6, 101} {
			response := httptest.NewRecorder()
			request := requestWithRoute(t, "POST", "/", map[string]any{"key": fmt.Sprintf("exponent-%d", exponent), "mode": "local", "currency": "JPY", "amount_minor": 1000, "currency_exponent": exponent}, map[string]string{"application_id": app.String(), "product_id": product.String()}, kernel.Actor{Type: "control_user"})
			s.createPrice(response, request)
			if exponent < 0 || exponent > 6 {
				if response.Code != 422 {
					t.Fatalf("invalid exponent accepted: %d %s", response.Code, response.Body.String())
				}
			} else {
				var result struct {
					Exponent int `json:"currency_exponent"`
				}
				if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Exponent != exponent {
					t.Fatalf("exponent not preserved: %d %s", response.Code, response.Body.String())
				}
			}
		}
	})
	for _, test := range []struct {
		name     string
		extra    map[string]any
		expected float64
		config   string
		status   int
	}{
		{"product defaults", nil, 5, "basic", 201},
		{"price defaults", map[string]any{"price_id": price}, 10, "priority", 201},
		{"workspace", map[string]any{"subject_type": "workspace", "subject_id": workspace}, 5, "basic", 201},
		{"override", map[string]any{"feature_values": map[string]any{"projects": float64(42)}, "configuration": map[string]any{"support": "custom"}}, 42, "custom", 201},
		{"empty maps", map[string]any{"feature_values": map[string]any{}, "configuration": map[string]any{}}, 0, "", 201},
		{"foreign subject", map[string]any{"subject_id": foreignUser}, 0, "", 422},
		{"foreign product", map[string]any{"product_id": foreignProduct}, 0, "", 422},
		{"foreign price", map[string]any{"price_id": foreignPrice}, 0, "", 422},
		{"unknown feature", map[string]any{"feature_values": map[string]any{"unknown": true}}, 0, "", 422},
		{"invalid type", map[string]any{"feature_values": map[string]any{"projects": true}}, 0, "", 422},
		{"invalid expiry", map[string]any{"expires_at": time.Now().Add(-time.Hour)}, 0, "", 422},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := map[string]any{"subject_type": "user", "subject_id": user, "product_id": product, "expires_at": expires}
			for key, value := range test.extra {
				body[key] = value
			}
			w := httptest.NewRecorder()
			request := requestWithRoute(t, "POST", "/", body, map[string]string{"application_id": app.String()}, kernel.Actor{Type: "control_user", ID: kernel.NewID().String()})
			request.Header.Set("Idempotency-Key", kernel.NewID().String())
			s.createEntitlement(w, request)
			if w.Code != test.status {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if w.Code != 201 {
				return
			}
			var result struct {
				ID            string
				FeatureValues map[string]any `json:"feature_values"`
				Configuration map[string]any `json:"configuration"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if test.expected == 0 {
				if len(result.FeatureValues) != 0 || len(result.Configuration) != 0 {
					t.Fatal("explicit empty maps were replaced")
				}
			} else if result.FeatureValues["projects"] != test.expected || result.Configuration["support"] != test.config {
				t.Fatalf("unexpected snapshot: %+v", result)
			}
			if _, err := db.Exec(ctx, `UPDATE products SET entitlement_config='{"support":"changed"}' WHERE id=$1`, product); err != nil {
				t.Fatal(err)
			}
			var persisted []byte
			if err := db.QueryRow(ctx, `SELECT configuration FROM entitlement_grants WHERE id=$1`, result.ID).Scan(&persisted); err != nil {
				t.Fatal(err)
			}
			var snapshot map[string]any
			_ = json.Unmarshal(persisted, &snapshot)
			if test.config != "" && snapshot["support"] != test.config {
				t.Fatal("grant changed with catalog")
			}
			_, _ = db.Exec(ctx, `UPDATE products SET entitlement_config='{"support":"basic"}' WHERE id=$1`, product)
		})
	}
	for _, lookup := range []struct {
		name, id string
		handler  http.HandlerFunc
	}{
		{"users", user.String(), s.adminListUsers}, {"workspaces", workspace.String(), s.listWorkspaces}, {"roles", role.String(), s.listRoles}, {"clients", client.String(), s.listClients}, {"products", product.String(), s.listProducts},
	} {
		t.Run("search "+lookup.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			lookup.handler(w, requestWithRoute(t, "GET", "/?query="+lookup.id+"&limit=1", nil, map[string]string{"application_id": app.String()}, kernel.Actor{Type: "control_user"}))
			var page struct {
				Items []map[string]any `json:"items"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &page)
			if w.Code != 200 || len(page.Items) != 1 || page.Items[0]["id"] != lookup.id {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
		})
	}
	first := httptest.NewRecorder()
	s.adminListUsers(first, requestWithRoute(t, "GET", "/?query=Same&limit=1", nil, map[string]string{"application_id": app.String()}, kernel.Actor{Type: "control_user"}))
	var page struct {
		Items  []map[string]any `json:"items"`
		Cursor string           `json:"next_cursor"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &page)
	if len(page.Items) != 1 || page.Cursor == "" {
		t.Fatal("missing search cursor")
	}
	second := httptest.NewRecorder()
	s.adminListUsers(second, requestWithRoute(t, "GET", "/?query=Same&limit=1&cursor="+page.Cursor, nil, map[string]string{"application_id": app.String()}, kernel.Actor{Type: "control_user"}))
	var next struct {
		Items  []map[string]any `json:"items"`
		Cursor any              `json:"next_cursor"`
	}
	_ = json.Unmarshal(second.Body.Bytes(), &next)
	if len(next.Items) != 1 || next.Cursor != nil || next.Items[0]["id"] == page.Items[0]["id"] || next.Items[0]["application_id"] != app.String() {
		t.Fatalf("bad second page: %s", second.Body.String())
	}
	for _, test := range []struct {
		name, sql string
		target    any
		extra     map[string]any
	}{
		{"archived product", `UPDATE products SET status='archived' WHERE id=$1`, product, nil},
		{"disabled price", `UPDATE prices SET active=false WHERE id=$1`, price, map[string]any{"price_id": price}},
		{"suspended user", `UPDATE users SET status='suspended' WHERE id=$1`, user2, map[string]any{"subject_id": user2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := db.Exec(ctx, test.sql, test.target); err != nil {
				t.Fatal(err)
			}
			body := map[string]any{"subject_type": "user", "subject_id": user, "product_id": product, "expires_at": expires}
			for key, value := range test.extra {
				body[key] = value
			}
			w := httptest.NewRecorder()
			request := requestWithRoute(t, "POST", "/", body, map[string]string{"application_id": app.String()}, kernel.Actor{Type: "control_user"})
			request.Header.Set("Idempotency-Key", kernel.NewID().String())
			s.createEntitlement(w, request)
			if w.Code != 422 {
				t.Fatalf("inactive resource granted: %d %s", w.Code, w.Body.String())
			}
			_, _ = db.Exec(ctx, `UPDATE products SET status='active' WHERE id=$1`, product)
			_, _ = db.Exec(ctx, `UPDATE prices SET active=true WHERE id=$1`, price)
			_, _ = db.Exec(ctx, `UPDATE users SET status='active' WHERE id=$1 OR id=$2`, user, user2)
		})
	}
}
