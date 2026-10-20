package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestApplicationAdministrationForwardsUserToken(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer user-token" {
			t.Error("caller token not forwarded")
		}
		switch r.Method {
		case "PATCH":
			if r.Header.Get("If-Match") != `"v1"` {
				t.Error("version missing")
			}
			w.WriteHeader(204)
		default:
			if r.URL.Path != "/v1/applications/application/users" || r.Header.Get("Idempotency-Key") != "onboarding-key" {
				t.Error("wrong application operation")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"created","version":1}`))
		}
	}))
	defer server.Close()
	c := Client{BaseURL: server.URL, ApplicationID: "application", AccessToken: func(context.Context) (string, error) { return "user-token", nil }}
	a := c.Administration()
	user, err := a.CreateUser(t.Context(), ManagedUserCreate{Email: "person@example.test", Reason: "Onboard"}, "onboarding-key")
	if err != nil || user.ID != "created" {
		t.Fatal(user, err)
	}
	name := "Person"
	if err = a.UpdateUser(t.Context(), "created", ManagedUserUpdate{FirstName: &name, Reason: "Correct profile"}, `"v1"`); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("unexpected OAuth or control request")
	}
}

func TestAdministrationSearchPreservesRecipient(t *testing.T) {
	u, err := url.Parse(administrationSearch("/role-assignments?user_id=recipient", []AdministrationSearch{{Query: "reader & owner", Cursor: "next", Limit: 15}}))
	if err != nil || u.Query().Get("user_id") != "recipient" || u.Query().Get("query") != "reader & owner" || u.Query().Get("cursor") != "next" || u.Query().Get("limit") != "15" {
		t.Fatal("administration pagination lost query or recipient", u, err)
	}
}
