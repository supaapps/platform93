package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) ensureStripePrice(ctx context.Context, applicationID, connectionID, priceID, secret, version string) (string, error) {
	if mapped := s.providerMapping(ctx, connectionID, "price", priceID); mapped != "" {
		return mapped, nil
	}
	var productID, productName, productDescription, priceKey, mode, currency, taxBehavior string
	var amount int64
	var interval *string
	var intervalCount *int
	err := s.app.DB.QueryRow(ctx, `SELECT p.id,p.name,p.description,pr.key,pr.mode,pr.amount_minor,pr.currency,pr.tax_behavior,
pr.interval_unit,pr.interval_count FROM prices pr JOIN products p ON p.id=pr.product_id
WHERE pr.id=$1 AND pr.application_id=$2 AND pr.active=true AND p.status='active' AND pr.mode IN('recurring','one_time')`, priceID, applicationID).
		Scan(&productID, &productName, &productDescription, &priceKey, &mode, &amount, &currency, &taxBehavior, &interval, &intervalCount)
	if err != nil {
		return "", err
	}
	providerProductID := s.providerMapping(ctx, connectionID, "product", productID)
	if providerProductID == "" {
		form := url.Values{
			"name":                                {productName},
			"description":                         {productDescription},
			"metadata[platform93_application_id]": {applicationID},
			"metadata[platform93_product_id]":     {productID},
		}
		body, requestErr := stripeRequest(ctx, http.MethodPost, "https://api.stripe.com/v1/products", secret, version,
			"platform93-product-"+connectionID+"-"+productID, form)
		var product struct {
			ID string `json:"id"`
		}
		if requestErr != nil {
			return "", fmt.Errorf("create Stripe product: %w", requestErr)
		}
		if decodeErr := json.Unmarshal(body, &product); decodeErr != nil {
			return "", fmt.Errorf("decode Stripe product: %w", decodeErr)
		}
		if product.ID == "" {
			return "", fmt.Errorf("create Stripe product: response has no product ID")
		}
		providerProductID, err = s.storeProviderMapping(ctx, applicationID, connectionID, "product", productID, product.ID)
		if err != nil {
			return "", err
		}
	}
	form := url.Values{
		"product":                             {providerProductID},
		"currency":                            {strings.ToLower(currency)},
		"unit_amount":                         {strconv.FormatInt(amount, 10)},
		"tax_behavior":                        {taxBehavior},
		"lookup_key":                          {"platform93_" + strings.ReplaceAll(priceID, "-", "")},
		"metadata[platform93_application_id]": {applicationID},
		"metadata[platform93_price_id]":       {priceID},
		"metadata[platform93_price_key]":      {priceKey},
	}
	if mode == "recurring" && interval != nil {
		form.Set("recurring[interval]", *interval)
		if intervalCount != nil {
			form.Set("recurring[interval_count]", strconv.Itoa(*intervalCount))
		}
	}
	body, err := stripeRequest(ctx, http.MethodPost, "https://api.stripe.com/v1/prices", secret, version,
		"platform93-price-"+connectionID+"-"+priceID, form)
	var price struct {
		ID string `json:"id"`
	}
	if err != nil {
		return "", fmt.Errorf("create Stripe price: %w", err)
	}
	if decodeErr := json.Unmarshal(body, &price); decodeErr != nil {
		return "", fmt.Errorf("decode Stripe price: %w", decodeErr)
	}
	if price.ID == "" {
		return "", fmt.Errorf("create Stripe price: response has no price ID")
	}
	return s.storeProviderMapping(ctx, applicationID, connectionID, "price", priceID, price.ID)
}

func (s *Server) providerMapping(ctx context.Context, connectionID, objectType, internalID string) string {
	var providerID string
	_ = s.app.DB.QueryRow(ctx, `SELECT provider_id FROM provider_mappings
WHERE provider_connection_id=$1 AND object_type=$2 AND internal_id=$3`, connectionID, objectType, internalID).Scan(&providerID)
	return providerID
}

func (s *Server) internalProviderMapping(ctx context.Context, connectionID, objectType, providerID string) string {
	var internalID string
	_ = s.app.DB.QueryRow(ctx, `SELECT internal_id FROM provider_mappings
WHERE provider_connection_id=$1 AND object_type=$2 AND provider_id=$3`, connectionID, objectType, providerID).Scan(&internalID)
	return internalID
}

func (s *Server) storeProviderMapping(ctx context.Context, applicationID, connectionID, objectType, internalID, providerID string) (string, error) {
	_, err := s.app.DB.Exec(ctx, `INSERT INTO provider_mappings(id,application_id,provider_connection_id,object_type,internal_id,provider_id)
VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(provider_connection_id,object_type,internal_id) DO NOTHING`,
		kernel.NewID(), applicationID, connectionID, objectType, internalID, providerID)
	if err != nil {
		return "", err
	}
	mapped := s.providerMapping(ctx, connectionID, objectType, internalID)
	if mapped == "" {
		return "", fmt.Errorf("provider mapping was not stored")
	}
	return mapped, nil
}

func applyStripeTrialPolicy(form url.Values, policy map[string]any) {
	days := int64Number(policy["trial_period_days"])
	if days > 0 {
		form.Set("subscription_data[trial_period_days]", strconv.FormatInt(days, 10))
	}
}
