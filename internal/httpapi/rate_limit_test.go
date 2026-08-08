package httpapi

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func TestAuthRateLimitIsSharedThroughPostgres(t *testing.T) {
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
	flow := "test_" + kernel.NewID().String()
	for attempt := 1; attempt <= 3; attempt++ {
		request := httptest.NewRequest("POST", "/", nil)
		request.RemoteAddr = "203.0.113.10:12345"
		response := httptest.NewRecorder()
		allowed := server.allowAuthAttempt(response, request, flow, "subject@example.test", 2, time.Minute)
		if attempt <= 2 && !allowed {
			t.Fatalf("attempt %d was unexpectedly denied: %s", attempt, response.Body.String())
		}
		if attempt == 3 && (allowed || response.Code != 429 || response.Header().Get("Retry-After") == "") {
			t.Fatalf("third attempt was not rate limited: allowed=%v status=%d headers=%v", allowed, response.Code, response.Header())
		}
	}
}
