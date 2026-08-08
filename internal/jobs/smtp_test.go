package jobs

import (
	"strings"
	"testing"
)

func TestBuildMIMEMessageIncludesAlternativeAndAttachment(t *testing.T) {
	message, err := buildMIMEMessage("sender@example.test", "Platform93", "user@example.test", "Invoice ready", "Plain body", "<p>HTML body</p>", []emailAttachment{{
		Filename: "invoice.pdf", ContentType: "application/pdf", Content: []byte("pdf-content"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	value := string(message)
	for _, expected := range []string{"multipart/mixed", "multipart/alternative", "Plain body", "<p>HTML body</p>", `filename="invoice.pdf"`, "cGRmLWNvbnRlbnQ="} {
		if !strings.Contains(value, expected) {
			t.Fatalf("MIME message does not contain %q", expected)
		}
	}
}
