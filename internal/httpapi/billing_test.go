package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestPaymentMethodCompatibility(t *testing.T) {
	cases := []struct {
		mode, currency string
		methods        []string
		valid          bool
	}{{"one_time", "CHF", []string{"twint"}, true}, {"one_time", "CHF", []string{"card", "twint"}, true}, {"recurring", "CHF", []string{"twint"}, false}, {"one_time", "EUR", []string{"twint"}, false}, {"recurring", "EUR", []string{"card"}, true}}
	for _, test := range cases {
		err := validatePaymentMethods(test.mode, test.currency, test.methods)
		if (err == nil) != test.valid {
			t.Errorf("%s %s %v: %v", test.mode, test.currency, test.methods, err)
		}
	}
}
func TestStripeSignature(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"id":"evt"}`)
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = mac.Write([]byte(fmt.Sprintf("%d.", now.Unix())))
	_, _ = mac.Write(body)
	header := fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil)))
	if !verifyStripeSignature(header, body, "whsec_test", now) {
		t.Fatal("valid signature rejected")
	}
	if verifyStripeSignature(header, append(body, 'x'), "whsec_test", now) {
		t.Fatal("tampered body accepted")
	}
}
func TestRedirectPolicy(t *testing.T) {
	if !safeRedirect("https://app.example/callback") || !safeRedirect("http://localhost:3000/callback") {
		t.Fatal("valid redirects rejected")
	}
	if safeRedirect("http://169.254.169.254/latest") || safeRedirect("javascript:alert(1)") {
		t.Fatal("unsafe redirect accepted")
	}
}

func TestCheckoutTrialPolicy(t *testing.T) {
	if err := validateCheckoutPolicy("recurring", "CHF", map[string]any{"trial_period_days": float64(14)}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode string
		days float64
	}{{"one_time", 14}, {"recurring", -1}, {"recurring", 731}} {
		if err := validateCheckoutPolicy(test.mode, "CHF", map[string]any{"trial_period_days": test.days}); err == nil {
			t.Fatalf("accepted invalid trial policy: %s %.0f", test.mode, test.days)
		}
	}
}

func TestStripeEventApplicationID(t *testing.T) {
	applicationID := "019f0000-0000-7000-8000-000000000001"
	for name, object := range map[string]map[string]any{
		"direct":                       {"metadata": map[string]any{"platform93_application_id": applicationID}},
		"invoice subscription details": {"invoice": map[string]any{"subscription_details": map[string]any{"metadata": map[string]any{"platform93_application_id": applicationID}}}},
		"customer":                     {"customer": map[string]any{"metadata": map[string]any{"platform93_application_id": applicationID}}},
	} {
		if got := stripeEventApplicationID(object); got != applicationID {
			t.Errorf("%s: got %q", name, got)
		}
	}
	if got := stripeEventApplicationID(map[string]any{"metadata": map[string]any{"unrelated": "value"}}); got != "" {
		t.Fatalf("unexpected application id: %q", got)
	}
}
