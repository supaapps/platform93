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
