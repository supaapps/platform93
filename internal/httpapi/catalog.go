package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) createFeature(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Key            string         `json:"key"`
		Name           string         `json:"name"`
		ValueType      string         `json:"value_type"`
		FreeFormFormat string         `json:"free_form_format"`
		Metadata       map[string]any `json:"metadata"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Key == "" || request.Name == "" || request.ValueType == "" {
		kernel.WriteProblem(w, r, 422, "invalid_feature", "Feature key, name, and value_type are required.")
		return
	}
	if request.ValueType != "boolean" && request.ValueType != "quantity" && request.ValueType != "free_form" {
		kernel.WriteProblem(w, r, 422, "invalid_feature_value_type", "Feature value_type must be one of: boolean, quantity, free_form.")
		return
	}
	if request.ValueType == "free_form" && !validFreeFormFormat(request.FreeFormFormat) {
		kernel.WriteProblem(w, r, 422, "invalid_free_form_format", "Free-form features require free_form_format to be one of: text, csv, json.")
		return
	}
	if request.ValueType != "free_form" && request.FreeFormFormat != "" {
		kernel.WriteProblem(w, r, 422, "unexpected_free_form_format", "free_form_format is available only for free-form features.")
		return
	}
	id := kernel.NewID()
	metadata, _ := json.Marshal(request.Metadata)
	_, err := s.app.DB.Exec(r.Context(), `INSERT INTO features (id,application_id,key,name,value_type,free_form_format,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, chi.URLParam(r, "application_id"), request.Key, request.Name, request.ValueType, nullableString(request.FreeFormFormat), metadata)
	if err != nil {
		kernel.WriteProblem(w, r, 409, "feature_conflict", "A feature with this key already exists.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "key": request.Key, "name": request.Name, "value_type": request.ValueType, "free_form_format": nullableString(request.FreeFormFormat), "metadata": request.Metadata})
}

func (s *Server) listFeatures(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,key,name,value_type,free_form_format,metadata,created_at FROM features WHERE application_id=$1 ORDER BY created_at,id`, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Features could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, key, name, valueType string
		var freeFormFormat *string
		var created time.Time
		var raw []byte
		if rows.Scan(&id, &key, &name, &valueType, &freeFormFormat, &raw, &created) == nil {
			items = append(items, map[string]any{"id": id, "key": key, "name": name, "value_type": valueType, "free_form_format": freeFormFormat, "metadata": decodeMap(raw), "created_at": created})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

type catalogFeatureValueRequest struct {
	FeatureID     string          `json:"feature_id"`
	BooleanValue  *bool           `json:"boolean_value"`
	QuantityValue *int64          `json:"quantity_value"`
	FreeFormValue json.RawMessage `json:"free_form_value"`
}

type productRequest struct {
	Name              string                        `json:"name"`
	Key               string                        `json:"key"`
	Description       *string                       `json:"description"`
	Listable          *bool                         `json:"listable"`
	Status            string                        `json:"status"`
	Metadata          map[string]any                `json:"metadata"`
	EntitlementConfig *map[string]any               `json:"entitlement_config"`
	Features          *[]catalogFeatureValueRequest `json:"features"`
}

func (s *Server) createProduct(w http.ResponseWriter, r *http.Request) {
	var request productRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Name == "" || request.Key == "" {
		kernel.WriteProblem(w, r, 422, "invalid_product", "Product name and key are required.")
		return
	}
	if request.Status == "" {
		request.Status = "draft"
	}
	listable := true
	if request.Listable != nil {
		listable = *request.Listable
	}
	metadata, _ := json.Marshal(request.Metadata)
	description := ""
	if request.Description != nil {
		description = *request.Description
	}
	entitlementConfig := map[string]any{}
	if request.EntitlementConfig != nil {
		entitlementConfig = *request.EntitlementConfig
	}
	entitlement, _ := json.Marshal(entitlementConfig)
	id := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The product could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO products (id,application_id,key,name,description,listable,status,metadata,entitlement_config) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, chi.URLParam(r, "application_id"), request.Key, request.Name, description, listable, request.Status, metadata, entitlement)
	if err == nil && request.Features != nil {
		err = insertCatalogFeatureValues(r.Context(), tx, chi.URLParam(r, "application_id"), "product", id.String(), *request.Features)
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), "invalid feature") {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_product_features", err.Error())
			return
		}
		kernel.WriteProblem(w, r, 409, "product_conflict", "A product with this key already exists.")
		return
	}
	if tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "product_creation_failed", "The product could not be committed.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "key": request.Key, "name": request.Name, "description": description, "listable": listable, "status": request.Status, "metadata": request.Metadata, "entitlement_config": entitlementConfig, "features": catalogFeatureValues(r.Context(), s.app.DB, "product", id.String()), "version": 1})
}

func (s *Server) listProducts(w http.ResponseWriter, r *http.Request)  { s.products(w, r, false) }
func (s *Server) publicCatalog(w http.ResponseWriter, r *http.Request) { s.products(w, r, true) }
func (s *Server) products(w http.ResponseWriter, r *http.Request, public bool) {
	query := `SELECT p.id,p.key,p.name,p.description,p.listable,p.status,p.metadata,p.entitlement_config,p.version,p.created_at,p.updated_at FROM products p WHERE p.application_id=$1`
	if public {
		query += ` AND p.status='active' AND p.listable=true`
	}
	query += ` ORDER BY p.created_at,p.id`
	rows, err := s.app.DB.Query(r.Context(), query, chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Products could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, key, name, description, status string
		var created, updated time.Time
		var listable bool
		var metadata, entitlementConfig []byte
		var version int64
		if rows.Scan(&id, &key, &name, &description, &listable, &status, &metadata, &entitlementConfig, &version, &created, &updated) == nil {
			items = append(items, map[string]any{"id": id, "key": key, "name": name, "description": description, "listable": listable, "status": status, "metadata": decodeMap(metadata), "entitlement_config": decodeMap(entitlementConfig), "version": version, "created_at": created, "updated_at": updated})
		}
	}
	rows.Close()
	for _, product := range items {
		id := product["id"].(string)
		product["features"] = catalogFeatureValues(r.Context(), s.app.DB, "product", id)
		product["prices"] = s.priceList(r, id, public)
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getProduct(w http.ResponseWriter, r *http.Request) {
	var id, key, name, description, status string
	var created, updated time.Time
	var listable bool
	var metadata, entitlementConfig []byte
	var version int64
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,key,name,description,listable,status,metadata,entitlement_config,version,created_at,updated_at FROM products WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "product_id"), chi.URLParam(r, "application_id")).Scan(&id, &key, &name, &description, &listable, &status, &metadata, &entitlementConfig, &version, &created, &updated)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "product_not_found", "The product was not found.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version))
	kernel.WriteJSON(w, 200, map[string]any{"id": id, "key": key, "name": name, "description": description, "listable": listable, "status": status, "metadata": decodeMap(metadata), "entitlement_config": decodeMap(entitlementConfig), "features": catalogFeatureValues(r.Context(), s.app.DB, "product", id), "version": version, "prices": s.priceList(r, id, false), "created_at": created, "updated_at": updated})
}

func (s *Server) updateProduct(w http.ResponseWriter, r *http.Request) {
	var request productRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Status != "" && request.Status != "draft" && request.Status != "active" && request.Status != "archived" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_product_status", "Product status must be draft, active, or archived.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The product could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	var version int64
	if err := tx.QueryRow(r.Context(), `SELECT version FROM products WHERE id=$1 AND application_id=$2 FOR UPDATE`, chi.URLParam(r, "product_id"), chi.URLParam(r, "application_id")).Scan(&version); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "product_not_found", "The product was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	metadata, _ := json.Marshal(request.Metadata)
	var entitlement any
	if request.EntitlementConfig != nil {
		encoded, _ := json.Marshal(*request.EntitlementConfig)
		entitlement = encoded
	}
	result, err := tx.Exec(r.Context(), `UPDATE products SET name=CASE WHEN $1='' THEN name ELSE $1 END,description=COALESCE($2,description),listable=COALESCE($3,listable),status=CASE WHEN $4='' THEN status ELSE $4 END,metadata=CASE WHEN $5::jsonb IS NULL THEN metadata ELSE $5 END,entitlement_config=CASE WHEN $6::jsonb IS NULL THEN entitlement_config ELSE $6 END,version=version+1,updated_at=now() WHERE id=$7 AND application_id=$8 AND version=$9`, request.Name, request.Description, request.Listable, request.Status, nullableMap(request.Metadata, metadata), entitlement, chi.URLParam(r, "product_id"), chi.URLParam(r, "application_id"), version)
	if err == nil && request.Features != nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM product_features WHERE product_id=$1`, chi.URLParam(r, "product_id"))
		if err == nil {
			err = insertCatalogFeatureValues(r.Context(), tx, chi.URLParam(r, "application_id"), "product", chi.URLParam(r, "product_id"), *request.Features)
		}
	}
	if err != nil && strings.HasPrefix(err.Error(), "invalid feature") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_product_features", err.Error())
		return
	}
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "product_version_conflict", "The product changed concurrently.")
		return
	}
	if tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "product_update_failed", "The product update could not be committed.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(204)
}

type priceRequest struct {
	Key               string                        `json:"key"`
	Mode              string                        `json:"mode"`
	AmountMinor       int64                         `json:"amount_minor"`
	Currency          string                        `json:"currency"`
	CurrencyExponent  int16                         `json:"currency_exponent"`
	IntervalUnit      *string                       `json:"interval_unit"`
	IntervalCount     *int                          `json:"interval_count"`
	ValiditySeconds   *int64                        `json:"validity_seconds"`
	GraceSeconds      int64                         `json:"grace_seconds"`
	TaxBehavior       string                        `json:"tax_behavior"`
	CheckoutConfig    map[string]any                `json:"checkout_config"`
	EntitlementConfig *map[string]any               `json:"entitlement_config"`
	Features          *[]catalogFeatureValueRequest `json:"features"`
}

func (s *Server) createPrice(w http.ResponseWriter, r *http.Request) {
	var request priceRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Currency = strings.ToUpper(request.Currency)
	if request.Key == "" || (request.Mode != "recurring" && request.Mode != "one_time" && request.Mode != "local") || len(request.Currency) != 3 || request.AmountMinor < 0 {
		kernel.WriteProblem(w, r, 422, "invalid_price", "Price key, mode, currency, and amount are invalid.")
		return
	}
	if request.CurrencyExponent == 0 {
		request.CurrencyExponent = 2
	}
	if request.TaxBehavior == "" {
		if request.Currency == "EUR" {
			request.TaxBehavior = "inclusive"
		} else {
			request.TaxBehavior = "unspecified"
		}
	}
	if err := validateCheckoutPolicy(request.Mode, request.Currency, request.CheckoutConfig); err != nil {
		kernel.WriteProblem(w, r, 422, "invalid_checkout_policy", err.Error())
		return
	}
	checkout, _ := json.Marshal(request.CheckoutConfig)
	id := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return
	}
	defer rollback(tx, r.Context())
	var entitlement []byte
	if err = tx.QueryRow(r.Context(), `SELECT entitlement_config FROM products WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "product_id"), chi.URLParam(r, "application_id")).Scan(&entitlement); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "product_not_found", "The product was not found.")
		return
	}
	if request.EntitlementConfig != nil {
		entitlement, _ = json.Marshal(*request.EntitlementConfig)
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO prices
(id,application_id,product_id,key,mode,amount_minor,currency,currency_exponent,interval_unit,interval_count,validity_seconds,grace_seconds,tax_behavior,checkout_config,entitlement_config)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, id, chi.URLParam(r, "application_id"), chi.URLParam(r, "product_id"), request.Key, request.Mode, request.AmountMinor, request.Currency, request.CurrencyExponent, request.IntervalUnit, request.IntervalCount, request.ValiditySeconds, request.GraceSeconds, request.TaxBehavior, checkout, entitlement)
	if err == nil && request.Features == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO price_features(price_id,feature_id,boolean_value,quantity_value,free_form_value)
SELECT $1,feature_id,boolean_value,quantity_value,free_form_value FROM product_features WHERE product_id=$2`, id, chi.URLParam(r, "product_id"))
	} else if err == nil {
		err = insertCatalogFeatureValues(r.Context(), tx, chi.URLParam(r, "application_id"), "price", id.String(), *request.Features)
	}
	if err != nil && strings.HasPrefix(err.Error(), "invalid feature") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_price_features", err.Error())
		return
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 409, "price_creation_failed", "The immutable price could not be created.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "key": request.Key, "mode": request.Mode, "amount_minor": request.AmountMinor, "currency": request.Currency, "currency_exponent": request.CurrencyExponent, "tax_behavior": request.TaxBehavior, "checkout_config": request.CheckoutConfig, "entitlement_config": decodeMap(entitlement), "features": catalogFeatureValues(r.Context(), s.app.DB, "price", id.String())})
}

func (s *Server) listPrices(w http.ResponseWriter, r *http.Request) {
	kernel.WriteJSON(w, 200, map[string]any{"items": s.priceList(r, chi.URLParam(r, "product_id"), false), "next_cursor": nil})
}
func (s *Server) priceList(r *http.Request, productID string, public bool) []map[string]any {
	query := `SELECT id,key,mode,amount_minor,currency,currency_exponent,interval_unit,interval_count,validity_seconds,grace_seconds,tax_behavior,checkout_config,entitlement_config,active,created_at FROM prices WHERE application_id=$1 AND product_id=$2`
	if public {
		query += ` AND active=true`
	}
	query += ` ORDER BY created_at,id`
	rows, err := s.app.DB.Query(r.Context(), query, chi.URLParam(r, "application_id"), productID)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, key, mode, currency, tax string
		var created time.Time
		var amount int64
		var exponent int16
		var interval *string
		var intervalCount *int
		var validity *int64
		var grace int64
		var checkout, entitlement []byte
		var active bool
		if rows.Scan(&id, &key, &mode, &amount, &currency, &exponent, &interval, &intervalCount, &validity, &grace, &tax, &checkout, &entitlement, &active, &created) == nil {
			items = append(items, map[string]any{"id": id, "key": key, "mode": mode, "amount_minor": amount, "currency": currency, "currency_exponent": exponent, "interval_unit": interval, "interval_count": intervalCount, "validity_seconds": validity, "grace_seconds": grace, "tax_behavior": tax, "checkout_config": decodeMap(checkout), "entitlement_config": decodeMap(entitlement), "active": active, "created_at": created})
		}
	}
	rows.Close()
	for _, price := range items {
		price["features"] = catalogFeatureValues(r.Context(), s.app.DB, "price", price["id"].(string))
	}
	return items
}

type catalogFeatureQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func catalogFeatureValues(ctx context.Context, queryer catalogFeatureQuerier, ownerType, ownerID string) []map[string]any {
	table, ownerColumn := "product_features", "product_id"
	if ownerType == "price" {
		table, ownerColumn = "price_features", "price_id"
	}
	rows, err := queryer.Query(ctx, fmt.Sprintf(`SELECT f.id,f.key,f.name,f.value_type,f.free_form_format,v.boolean_value,v.quantity_value,v.free_form_value
FROM %s v JOIN features f ON f.id=v.feature_id WHERE v.%s=$1 ORDER BY f.created_at,f.id`, table, ownerColumn), ownerID)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, key, name, valueType string
		var freeFormFormat *string
		var booleanValue *bool
		var quantityValue *int64
		var freeFormValue []byte
		if rows.Scan(&id, &key, &name, &valueType, &freeFormFormat, &booleanValue, &quantityValue, &freeFormValue) != nil {
			continue
		}
		item := map[string]any{"feature_id": id, "key": key, "name": name, "value_type": valueType}
		if booleanValue != nil {
			item["boolean_value"], item["value"] = *booleanValue, *booleanValue
		} else if quantityValue != nil {
			item["quantity_value"], item["value"] = *quantityValue, *quantityValue
		} else {
			value := decodeJSONValue(freeFormValue)
			item["free_form_format"], item["free_form_value"], item["value"] = freeFormFormat, value, value
		}
		items = append(items, item)
	}
	return items
}

func insertCatalogFeatureValues(ctx context.Context, tx pgx.Tx, applicationID, ownerType, ownerID string, values []catalogFeatureValueRequest) error {
	table, ownerColumn := "product_features", "product_id"
	if ownerType == "price" {
		table, ownerColumn = "price_features", "price_id"
	}
	for _, feature := range values {
		var valueType string
		var freeFormFormat *string
		if err := tx.QueryRow(ctx, `SELECT value_type,free_form_format FROM features WHERE id=$1 AND application_id=$2`, feature.FeatureID, applicationID).Scan(&valueType, &freeFormFormat); err != nil {
			return fmt.Errorf("invalid feature %q: it does not belong to this application", feature.FeatureID)
		}
		valid := false
		switch valueType {
		case "boolean":
			valid = feature.BooleanValue != nil && feature.QuantityValue == nil && feature.FreeFormValue == nil
		case "quantity":
			valid = feature.BooleanValue == nil && feature.QuantityValue != nil && *feature.QuantityValue >= 0 && feature.FreeFormValue == nil
		case "free_form":
			valid = feature.BooleanValue == nil && feature.QuantityValue == nil && feature.FreeFormValue != nil && freeFormFormat != nil && validateFreeFormValue(*freeFormFormat, feature.FreeFormValue) == nil
		}
		if !valid {
			return fmt.Errorf("invalid feature %q: expected a %s value", feature.FeatureID, valueType)
		}
		var freeFormValue any
		if feature.FreeFormValue != nil {
			freeFormValue = string(feature.FreeFormValue)
		}
		_, err := tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(%s,feature_id,boolean_value,quantity_value,free_form_value)
VALUES($1,$2,$3,$4,$5)`, table, ownerColumn), ownerID, feature.FeatureID, feature.BooleanValue, feature.QuantityValue, freeFormValue)
		if err != nil {
			return fmt.Errorf("invalid feature %q: it is duplicated or malformed", feature.FeatureID)
		}
	}
	return nil
}

func validFreeFormFormat(value string) bool {
	return value == "text" || value == "csv" || value == "json"
}

func validateFreeFormValue(format string, raw json.RawMessage) error {
	if format == "json" {
		return nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%s free-form values must be strings", format)
	}
	if format == "csv" {
		reader := csv.NewReader(strings.NewReader(value))
		reader.FieldsPerRecord = 0
		if _, err := reader.ReadAll(); err != nil {
			return fmt.Errorf("invalid CSV: %w", err)
		}
	}
	return nil
}

func validateCheckoutPolicy(mode, currency string, config map[string]any) error {
	trialDays := int64Number(config["trial_period_days"])
	if trialDays < 0 || trialDays > 730 || trialDays > 0 && mode != "recurring" {
		return fmt.Errorf("trial_period_days must be between 1 and 730 for recurring prices")
	}
	methods, ok := config["payment_methods"].([]any)
	if !ok {
		return nil
	}
	for _, raw := range methods {
		method, _ := raw.(string)
		if method != "card" && method != "twint" {
			return fmt.Errorf("unsupported payment method %q", method)
		}
		if method == "twint" && (mode != "one_time" || currency != "CHF") {
			return fmt.Errorf("TWINT is supported only for CHF one-time checkout")
		}
	}
	return nil
}
func nullableMap(value map[string]any, encoded []byte) any {
	if value == nil {
		return nil
	}
	return encoded
}
