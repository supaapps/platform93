package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClientCachesAndInvalidatesMachineToken(t *testing.T) {
	t.Parallel()
	var tokenRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oidc/token":
			tokenRequests.Add(1)
			clientID, secret, ok := r.BasicAuth()
			if !ok || clientID != "machine" || secret != "secret" && secret != "rotated" {
				http.Error(w, "invalid", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
		case "/v1/applications/app/users":
			if r.Header.Get("Authorization") != "Bearer token" {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}, "next_cursor": nil})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, ApplicationID: "app", ClientID: "machine", ClientSecret: "secret"}
	if _, err := client.ListUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokenRequests.Load() != 1 {
		t.Fatalf("expected one token exchange, got %d", tokenRequests.Load())
	}
	client.UpdateSecret("rotated")
	if _, err := client.ListUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokenRequests.Load() != 2 {
		t.Fatalf("expected token cache invalidation after rotation, got %d exchanges", tokenRequests.Load())
	}
}

func TestBillingSummaryAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oidc/token":
			_, _ = w.Write([]byte(`{"access_token":"machine","expires_in":300}`))
		case "/v1/applications/app/subjects/workspace/workspace/billing":
			_, _ = w.Write([]byte(`{"subscriptions":[{"provider_subscription_id":"sub_fixture","past_due_since":"2026-10-01T00:00:00Z"}]}`))
		case "/v1/applications/app/subjects/workspace/workspace/billing/cancel":
			var input struct {
				AtPeriodEnd bool `json:"at_period_end"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.AtPeriodEnd || r.Header.Get("Idempotency-Key") != "cancel-key" {
				t.Error("cancellation payload/key mismatch")
			}
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c := &Client{BaseURL: server.URL, ApplicationID: "app", ClientID: "machine", ClientSecret: "fixture"}
	summary, err := c.SubjectBilling(context.Background(), "workspace", "workspace")
	if err != nil || len(summary.Subscriptions) != 1 || summary.Subscriptions[0].ProviderSubscriptionID != "sub_fixture" || summary.Subscriptions[0].PastDueSince == nil {
		t.Fatalf("typed summary: %+v %v", summary, err)
	}
	if err = c.CancelWorkspaceBilling(context.Background(), "workspace", "cancel-key", false); err != nil {
		t.Fatal(err)
	}
}
