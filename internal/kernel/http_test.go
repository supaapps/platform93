package kernel

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestDecodeJSONRejectsTrailingValue(t *testing.T) {
	request := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"value":true}{"value":false}`))
	response := httptest.NewRecorder()
	var body struct {
		Value bool `json:"value"`
	}
	if DecodeJSON(response, request, &body) || response.Code != 400 {
		t.Fatalf("trailing JSON was accepted: status=%d", response.Code)
	}
}

func TestETagUsesFullVersion(t *testing.T) {
	if ETag(1) == ETag(257) {
		t.Fatal("ETag collided after 256 versions")
	}
}

func TestCheckIfMatchRejectsStaleVersion(t *testing.T) {
	request := httptest.NewRequest("PATCH", "/", nil)
	request.Header.Set("If-Match", ETag(3))
	response := httptest.NewRecorder()
	if CheckIfMatch(response, request, 4) || response.Code != 412 {
		t.Fatalf("stale ETag was accepted: status=%d", response.Code)
	}
}
