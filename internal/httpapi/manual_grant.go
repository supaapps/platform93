package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"

	"github.com/jackc/pgx/v5"
)

var errInvalidGrantValues = errors.New("invalid grant values")

func resolveManualGrant(r *http.Request, tx pgx.Tx, grant *grantRequest) error {
	appID, _ := applicationID(r)
	if grant.ProductID != nil {
		table, column, owner := "product_features", "product_id", *grant.ProductID
		configQuery := `SELECT entitlement_config FROM products WHERE id=$1 AND application_id=$2`
		if grant.PriceID != nil {
			table, column, owner = "price_features", "price_id", *grant.PriceID
			configQuery = `SELECT entitlement_config FROM prices WHERE id=$1 AND application_id=$2`
		}
		if grant.Configuration == nil {
			var raw []byte
			if err := tx.QueryRow(r.Context(), configQuery, owner, appID).Scan(&raw); err != nil {
				return fmt.Errorf("load catalog configuration: %w", err)
			}
			if err := json.Unmarshal(raw, &grant.Configuration); err != nil {
				return fmt.Errorf("decode catalog configuration: %w", err)
			}
		}
		if grant.FeatureValues == nil {
			var raw []byte
			query := fmt.Sprintf(`SELECT COALESCE(jsonb_object_agg(f.key, CASE
WHEN v.boolean_value IS NOT NULL THEN to_jsonb(v.boolean_value)
WHEN v.quantity_value IS NOT NULL THEN to_jsonb(v.quantity_value) ELSE v.free_form_value END),'{}'::jsonb)
FROM %s v JOIN features f ON f.id=v.feature_id WHERE v.%s=$1 AND f.application_id=$2`, table, column)
			if err := tx.QueryRow(r.Context(), query, owner, appID).Scan(&raw); err != nil {
				return fmt.Errorf("load catalog features: %w", err)
			}
			if err := json.Unmarshal(raw, &grant.FeatureValues); err != nil {
				return fmt.Errorf("decode catalog features: %w", err)
			}
		}
	}
	if grant.Configuration == nil {
		grant.Configuration = map[string]any{}
	}
	if grant.FeatureValues == nil {
		grant.FeatureValues = map[string]any{}
	}
	for key, value := range grant.FeatureValues {
		var kind string
		var format *string
		if err := tx.QueryRow(r.Context(), `SELECT value_type,free_form_format FROM features WHERE application_id=$1 AND key=$2`, appID, key).Scan(&kind, &format); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: Feature %q is not defined in this application.", errInvalidGrantValues, key)
			}
			return fmt.Errorf("load feature definition: %w", err)
		}
		if err := validateGrantFeature(kind, format, value); err != nil {
			return fmt.Errorf("%w: Feature %q: %v", errInvalidGrantValues, key, err)
		}
	}
	return nil
}

func validateGrantFeature(kind string, format *string, value any) error {
	switch kind {
	case "boolean":
		if _, ok := value.(bool); ok {
			return nil
		}
	case "quantity":
		if number, ok := value.(float64); ok && number >= 0 && number < math.Exp2(63) && math.Trunc(number) == number {
			return nil
		}
	case "free_form":
		raw, err := json.Marshal(value)
		if err == nil && format != nil {
			return validateFreeFormValue(*format, raw)
		}
	}
	return fmt.Errorf("expected a valid %s value", kind)
}
