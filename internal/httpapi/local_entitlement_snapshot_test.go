package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestLocalEntitlementApprovalUsesCheckoutFeatureSnapshot(t *testing.T) {
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
	userID, controlUserID, productID, priceID, featureID := kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID(), kernel.NewID()
	suffix := applicationID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Test',$2)`, []any{organizationID, "snapshot-" + suffix}},
		{`INSERT INTO applications(id,organization_id,name,slug) VALUES($1,$2,'Test',$3)`, []any{applicationID, organizationID, "snapshot-" + suffix}},
		{`INSERT INTO control_users(id,email,normalized_email) VALUES($1,$2,$2)`, []any{controlUserID, "control_user-" + suffix + "@example.test"}},
		{`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,$3,$3)`, []any{userID, applicationID, "user-" + suffix + "@example.test"}},
		{`INSERT INTO products(id,application_id,key,name,status) VALUES($1,$2,$3,'Local','active')`, []any{productID, applicationID, "product-" + suffix}},
		{`INSERT INTO prices(id,application_id,product_id,key,mode,amount_minor,currency,validity_seconds) VALUES($1,$2,$3,$4,'local',1000,'CHF',3600)`, []any{priceID, applicationID, productID, "price-" + suffix}},
		{`INSERT INTO features(id,application_id,key,name,value_type) VALUES($1,$2,$3,'Access','boolean')`, []any{featureID, applicationID, "access-" + suffix}},
		{`INSERT INTO price_features(price_id,feature_id,boolean_value) VALUES($1,$2,true)`, []any{priceID, featureID}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	externalReference := "local-order-" + suffix
	checkoutRequest := requestWithRoute(t, "POST", `/`, map[string]any{"price_id": priceID, "external_reference": externalReference}, map[string]string{"application_id": applicationID.String()}, kernel.Actor{Type: "user", ID: userID.String()})
	checkoutResponse := httptest.NewRecorder()
	server.createLocalCheckout(checkoutResponse, checkoutRequest)
	if checkoutResponse.Code != 201 {
		t.Fatalf("checkout failed: %d %s", checkoutResponse.Code, checkoutResponse.Body.String())
	}
	var checkout struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(checkoutResponse.Body.Bytes(), &checkout); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), `UPDATE price_features SET boolean_value=false WHERE price_id=$1 AND feature_id=$2`, priceID, featureID); err != nil {
		t.Fatal(err)
	}

	approveRequest := requestWithRoute(t, "POST", `/`, map[string]any{"reason": "verified"}, map[string]string{
		"application_id": applicationID.String(), "request_id": checkout.ID,
	}, kernel.Actor{Type: "control_user", ID: controlUserID.String()})
	approveResponse := httptest.NewRecorder()
	server.approveLocalRequest(approveResponse, approveRequest)
	if approveResponse.Code != 200 {
		t.Fatalf("approval failed: %d %s", approveResponse.Code, approveResponse.Body.String())
	}
	var features map[string]any
	var encoded []byte
	if err = db.QueryRow(context.Background(), `SELECT feature_values FROM entitlement_grants WHERE source_type='local_request' AND source_id=$1`, checkout.ID).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(encoded, &features); err != nil {
		t.Fatal(err)
	}
	if value, ok := features["access-"+suffix].(bool); !ok || !value {
		t.Fatalf("approval used mutable catalog state: %#v", features)
	}
	var requestReference, grantReference string
	if err = db.QueryRow(context.Background(), `SELECT r.external_reference,g.external_reference
FROM local_entitlement_requests r JOIN entitlement_grants g ON g.source_id=r.id AND g.source_type='local_request'
WHERE r.id=$1`, checkout.ID).Scan(&requestReference, &grantReference); err != nil {
		t.Fatal(err)
	}
	if requestReference != externalReference || grantReference != externalReference {
		t.Fatalf("external reference was not preserved: request=%q grant=%q", requestReference, grantReference)
	}
	var createdEventReference, approvedEventReference string
	if err = db.QueryRow(context.Background(), `SELECT
(SELECT data->>'external_reference' FROM domain_events WHERE application_id=$1 AND event_type='local_entitlement_request.created' AND subject=$2),
(SELECT data->>'external_reference' FROM domain_events WHERE application_id=$1 AND event_type='local_entitlement_request.approved' AND subject=$2)`,
		applicationID, "local_entitlement_request/"+checkout.ID).Scan(&createdEventReference, &approvedEventReference); err != nil {
		t.Fatal(err)
	}
	if createdEventReference != externalReference || approvedEventReference != externalReference {
		t.Fatalf("external reference was omitted from local lifecycle events: created=%q approved=%q", createdEventReference, approvedEventReference)
	}
}

func requestWithRoute(t *testing.T, method, target string, body any, params map[string]string, current kernel.Actor) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	route := chi.NewRouteContext()
	for key, value := range params {
		route.URLParams.Add(key, value)
	}
	ctx := context.WithValue(request.Context(), chi.RouteCtxKey, route)
	ctx = kernel.WithActor(ctx, current)
	return request.WithContext(ctx)
}
