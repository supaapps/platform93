package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPutDoesNotLeakPlatformAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("Platform93 authorization leaked to object provider")
		}
		if r.Header.Get("Content-Type") != "text/plain" {
			t.Errorf("signed header missing: %q", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "hello" {
			t.Errorf("unexpected body: %q", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := Client{HTTPClient: server.Client()}
	err := client.Put(context.Background(), UploadAuthorization{
		UploadURL: server.URL, RequiredHeaders: map[string]string{"Content-Type": "text/plain", "Authorization": "Bearer should-not-leak"},
	}, strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
}
