package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminHTMLCSPAllowsOnlyExportedInlineScripts(t *testing.T) {
	directory := t.TempDir()
	html := `<!doctype html><script src="/app.js"></script><script>self.__next_f=[]</script>`
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte(html), 0o600); err != nil {
		t.Fatal(err)
	}
	server := &Server{adminAssets: directory}
	response := httptest.NewRecorder()
	server.adminHandler().ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	digest := sha256.Sum256([]byte("self.__next_f=[]"))
	wanted := "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	policy := response.Header().Get("Content-Security-Policy")
	if response.Code != 200 || !strings.Contains(policy, wanted) || strings.Contains(policy, "'unsafe-inline'") && strings.Contains(strings.Split(policy, ";")[1], "'unsafe-inline'") {
		t.Fatalf("unexpected admin CSP: status=%d policy=%q", response.Code, policy)
	}
}
