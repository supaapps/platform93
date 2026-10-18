package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/supaapps/platform93/sdk/go/client"
)

func TestResourceAuthorization(t *testing.T) {
	const app = "01900000-0000-7000-8000-000000000093"
	const id = "01900000-0000-7000-8000-000000000094"
	const resource = "https://resource.example/api"
	var fixture struct {
		Claims map[string]any `json:"claims"`
		Cases  []struct {
			Name    string         `json:"name"`
			Changes map[string]any `json:"changes"`
			Omit    []string       `json:"omit"`
			Accept  bool           `json:"accept"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile("../../../conformance/resource-jwt.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	checks, exchanges := 0, 0
	decision := any(map[string]any{"allowed": true, "reason": "allowed", "user_id": id, "connection_id": id})
	status := 200
	var last client.ResourceAccessCheckRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk("primary", &key.PublicKey)}})
		case "/oidc/token":
			exchanges++
			if user, secret, ok := r.BasicAuth(); !ok || user != "backend" || secret != "test" {
				t.Error("missing machine credentials")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "machine", "expires_in": 300})
		case "/v1/applications/" + app + "/service/resource-access/check":
			checks++
			if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer machine" {
				t.Error("incorrect live check authentication")
			}
			if err := json.NewDecoder(r.Body).Decode(&last); err != nil {
				t.Error(err)
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(decision)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	v := &Verifier{Issuer: server.URL, Audience: resource, ApplicationID: app}
	a := ResourceAuthorizer{Verifier: v, Resource: resource, MachineClient: &client.Client{BaseURL: server.URL, ApplicationID: app, ClientID: "backend", ClientSecret: "test"}}
	scope, _ := CapabilityScope(app, "documents:read")
	makeToken := func(changes map[string]any, omit ...string) string {
		now := time.Now().Unix()
		claims := map[string]any{"iss": server.URL, "exp": now + 300, "iat": now, "nbf": now - 1}
		for k, value := range fixture.Claims {
			claims[k] = value
		}
		for k, value := range changes {
			claims[k] = value
		}
		for _, k := range omit {
			delete(claims, k)
		}
		return signFixtureToken(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "primary"}, claims, key)
	}
	ctx := context.Background()
	for _, entry := range fixture.Cases {
		t.Run("shared resource JWT conformance/"+entry.Name, func(t *testing.T) {
			before := checks
			_, err := a.Authorize(ctx, makeToken(entry.Changes, entry.Omit...), "documents:read", "")
			if (err == nil) != entry.Accept {
				t.Fatalf("accept=%v error=%v", entry.Accept, err)
			}
			wanted := 0
			if entry.Accept {
				wanted = 1
			}
			if checks-before != wanted {
				t.Fatal("incorrect number of live checks")
			}
		})
	}
	checks = 0
	token := makeToken(nil)
	for range 2 {
		if claims, err := a.Authorize(ctx, token, "documents:read", ""); err != nil || claims.ConnectionID != id {
			t.Fatalf("resource authorization failed: %v", err)
		}
	}
	if checks != 2 || exchanges != 1 || last.Token != token || last.Resource != resource || last.Capability != "documents:read" {
		t.Fatal("live check was cached or request incorrect")
	}
	if _, err := v.Verify(ctx, token); err == nil {
		t.Fatal("ordinary verifier accepted resource token")
	}
	decision = map[string]any{"allowed": true, "reason": "allowed", "workspace_id": id}
	if _, err := a.Authorize(ctx, token, "documents:read", id); err != nil || last.WorkspaceID != id {
		t.Fatalf("explicit workspace failed: %v", err)
	}
	invalid := map[string]map[string]any{
		"application": {"application_id": id}, "audience": {"aud": resource + "/other"}, "multi audience": {"aud": []string{resource, server.URL}},
		"duplicate audience": {"aud": []string{resource, resource}}, "actor": {"actor_type": "client"}, "kind": {"token_kind": "access"},
		"session": {"sid": "bad"}, "connection": {"connection_id": "bad"}, "client": {"client_id": ""}, "expired": {"exp": 1},
		"future iat": {"iat": time.Now().Unix() + 1000}, "future nbf": {"nbf": time.Now().Unix() + 1000},
		"roles":                 {"roles": map[string]any{"application": []string{"member"}, "workspaces": map[string]any{}}},
		"extra roles":           {"roles": map[string]any{"application": []string{}, "workspaces": map[string]any{}, "extra": true}},
		"workspace enumeration": {"workspace_ids": []string{id}}, "workspace": {"workspace_id": id}, "delegated": {"act": nil},
		"scope empty": {"scope": ""}, "scope duplicate": {"scope": scope + " " + scope}, "scope injection": {"scope": scope + "\t" + scope},
		"scope wildcard": {"scope": "/applications/" + app + "/*"}, "unknown protocol": {"scope": scope + " admin"}, "only protocol": {"scope": "openid offline_access"},
		"role scope":      {"scope": scope + " /applications/" + app + "/roles/member"},
		"workspace scope": {"scope": scope + " /applications/" + app + "/workspaces/" + id + "/read"},
	}
	for name, changes := range invalid {
		t.Run(name, func(t *testing.T) {
			before := checks
			if _, err := a.Authorize(ctx, makeToken(changes), "documents:read", ""); err == nil {
				t.Fatal("invalid token authorized")
			}
			if checks != before {
				t.Fatal("live check before local validation")
			}
		})
	}
	for _, claim := range []string{"sub", "sid", "client_id", "connection_id", "scope", "roles", "exp", "iat", "nbf"} {
		t.Run("missing "+claim, func(t *testing.T) {
			before := checks
			if _, err := a.Authorize(ctx, makeToken(nil, claim), "documents:read", ""); err == nil {
				t.Fatal("missing claim accepted")
			}
			if checks != before {
				t.Fatal("live check before local validation")
			}
		})
	}
	for _, response := range []any{nil, map[string]any{}, map[string]any{"allowed": false, "reason": "revoked"}, map[string]any{"allowed": true}, map[string]any{"allowed": true, "reason": nil}, map[string]any{"allowed": "true", "reason": "ok"}, map[string]any{"allowed": true, "reason": "ok", "user_id": app}, map[string]any{"allowed": true, "reason": "ok", "connection_id": nil}, map[string]any{"allowed": true, "reason": "ok", "workspace_id": id}} {
		decision = response
		if _, err := a.Authorize(ctx, token, "documents:read", ""); err == nil {
			t.Fatalf("malformed/denied decision authorized: %v", response)
		}
	}
	before := checks
	if _, err := a.Authorize(ctx, makeToken(map[string]any{"padding": strings.Repeat("a", 16*1024)}), "documents:read", ""); err == nil || !strings.Contains(err.Error(), "16 KiB") {
		t.Fatal("oversized token accepted")
	}
	if checks != before {
		t.Fatal("oversized token reached live check")
	}
	status = 503
	if _, err := a.Authorize(ctx, token, "documents:read", ""); err == nil {
		t.Fatal("HTTP failure authorized")
	}
	server.Close()
	if _, err := a.Authorize(ctx, token, "documents:read", ""); err == nil {
		t.Fatal("offline check authorized")
	}
}

func TestResourceMetadata(t *testing.T) {
	const app = "01900000-0000-7000-8000-000000000093"
	m, err := ResourceMetadata("https://resource.example", "https://issuer.example", app, []string{"documents:read", "documents:read"})
	if err != nil || len(m.ScopesSupported) != 1 || m.ScopesSupported[0] != "/applications/"+app+"/documents/read" {
		t.Fatalf("invalid metadata: %v", err)
	}
	challenge, err := ResourceChallenge("https://resource.example/metadata", "invalid_token", `a"b\c`)
	if err != nil || !strings.Contains(challenge, `error_description="a\"b\\c"`) {
		t.Fatalf("invalid challenge: %s %v", challenge, err)
	}
	if _, err := ResourceChallenge("https://resource.example", "invalid_token", "bad\r\nheader"); err == nil {
		t.Fatal("header injection accepted")
	}
	for _, uri := range []string{"http://resource.example", "https://user@resource.example", "https://resource.example/#fragment", "https://resource.example/?query=1", "https://resource.example/\n"} {
		if _, err := ResourceMetadata(uri, "https://issuer.example", app, nil); err == nil {
			t.Fatal("invalid URI accepted")
		}
	}
	for _, key := range []string{"*", "a:*", "a::b", "../read", "a%20b", "a b", "roles:member", "workspaces:read"} {
		if _, err := CapabilityScope(app, key); err == nil {
			t.Fatal("invalid capability accepted")
		}
	}
}
