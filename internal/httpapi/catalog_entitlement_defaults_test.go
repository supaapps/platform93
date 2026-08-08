package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestPriceSnapshotsProductEntitlementDefaults(t *testing.T) {
	databaseURL := os.Getenv("PLATFORM93_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PLATFORM93_DATABASE_URL is not configured")
	}
	if err := database.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := secure.NewVault(make([]byte, 32))
	server := &Server{app: platform.New(db, vault, "https://platform93.test")}

	organizationID, applicationID := kernel.NewID(), kernel.NewID()
	productID, featureID, freeFormFeatureID := kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Test',$2)`, []any{organizationID, "catalog-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Test',$3)`, []any{applicationID, organizationID, "catalog-" + suffix}},
		{`INSERT INTO products(id,application_id,key,name,status,entitlement_config) VALUES($1,$2,$3,'Standard','active','{"support_level":"standard"}')`, []any{productID, applicationID, "product-" + suffix}},
		{`INSERT INTO features(id,application_id,key,name,value_type) VALUES($1,$2,$3,'Projects','quantity')`, []any{featureID, applicationID, "projects-" + suffix}},
		{`INSERT INTO features(id,application_id,key,name,value_type,free_form_format) VALUES($1,$2,$3,'Regions','free_form','json')`, []any{freeFormFeatureID, applicationID, "regions-" + suffix}},
		{`INSERT INTO product_features(product_id,feature_id,quantity_value) VALUES($1,$2,5)`, []any{productID, featureID}},
		{`INSERT INTO product_features(product_id,feature_id,free_form_value) VALUES($1,$2,'{"allowed":["CH"]}')`, []any{productID, freeFormFeatureID}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	request := requestWithRoute(t, "POST", "/", map[string]any{
		"key": "monthly-" + suffix, "mode": "recurring", "amount_minor": 1900, "currency": "EUR",
	}, map[string]string{"application_id": applicationID.String(), "product_id": productID.String()}, kernel.Actor{Type: "operator", ID: kernel.NewID().String()})
	response := httptest.NewRecorder()
	server.createPrice(response, request)
	if response.Code != 201 {
		t.Fatalf("price creation failed: %d %s", response.Code, response.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	if _, err = db.Exec(context.Background(), `UPDATE products SET entitlement_config='{"support_level":"premium"}' WHERE id=$1`, productID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `UPDATE product_features SET quantity_value=25 WHERE product_id=$1 AND feature_id=$2`, productID, featureID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `UPDATE product_features SET free_form_value='{"allowed":["DE"]}' WHERE product_id=$1 AND feature_id=$2`, productID, freeFormFeatureID); err != nil {
		t.Fatal(err)
	}

	var entitlement []byte
	var quantity int64
	var freeForm []byte
	if err = db.QueryRow(context.Background(), `SELECT entitlement_config FROM prices WHERE id=$1`, created.ID).Scan(&entitlement); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT quantity_value FROM price_features WHERE price_id=$1 AND feature_id=$2`, created.ID, featureID).Scan(&quantity); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT free_form_value FROM price_features WHERE price_id=$1 AND feature_id=$2`, created.ID, freeFormFeatureID).Scan(&freeForm); err != nil {
		t.Fatal(err)
	}
	var entitlementSnapshot map[string]any
	if err = json.Unmarshal(entitlement, &entitlementSnapshot); err != nil {
		t.Fatal(err)
	}
	if entitlementSnapshot["support_level"] != "standard" {
		t.Fatalf("price entitlement configuration changed with product: %#v", entitlementSnapshot)
	}
	if quantity != 5 {
		t.Fatalf("price feature changed with product: got %d, want 5", quantity)
	}
	var freeFormSnapshot map[string]any
	if err = json.Unmarshal(freeForm, &freeFormSnapshot); err != nil {
		t.Fatal(err)
	}
	allowed, _ := freeFormSnapshot["allowed"].([]any)
	if len(allowed) != 1 || allowed[0] != "CH" {
		t.Fatalf("price free-form feature changed with product: %#v", freeFormSnapshot)
	}
}
