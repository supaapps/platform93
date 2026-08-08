package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestIdempotencySupportsInstallationScope(t *testing.T) {
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
	calls := 0
	handler := server.idempotent(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"call": calls})
	}))
	key := "installation-" + kernel.NewID().String()
	for attempt := 0; attempt < 2; attempt++ {
		request := requestWithRoute(t, "POST", "/v1/installation/test", map[string]any{"value": true}, nil, kernel.Actor{Type: "operator", ID: kernel.NewID().String()})
		request = request.WithContext(kernel.WithActor(request.Context(), kernel.Actor{Type: "operator", ID: "stable-operator"}))
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("attempt %d returned %d: %s", attempt+1, response.Code, response.Body.String())
		}
		if attempt == 1 && response.Header().Get("Idempotent-Replayed") != "true" {
			t.Fatal("second installation-scoped request was not replayed")
		}
	}
	if calls != 1 {
		t.Fatalf("handler executed %d times", calls)
	}
}
