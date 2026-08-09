package objectstorage

import (
	"context"
	"strings"
	"testing"
)

func TestValidateRejectsUnsafeConfiguration(t *testing.T) {
	base := Config{Endpoint: "http://127.0.0.1:9000", Region: "local", AccessKeyID: "access", SecretAccessKey: "secret", PrivateBucket: "private"}
	if err := Validate(context.Background(), base); err == nil {
		t.Fatal("private HTTP endpoint accepted without explicit installation allowance")
	}
	base.AllowPrivateEndpoint = true
	if err := Validate(context.Background(), base); err != nil {
		t.Fatalf("explicit private endpoint rejected: %v", err)
	}
	base.PublicBucket = "private"
	if err := Validate(context.Background(), base); err == nil {
		t.Fatal("same public and private bucket accepted")
	}
}

func TestPublicURLUsesProviderAddressing(t *testing.T) {
	client, err := New(context.Background(), Config{
		Endpoint: "http://127.0.0.1:9000", Region: "local", AccessKeyID: "access", SecretAccessKey: "secret",
		PublicBucket: "public", AllowPrivateEndpoint: true, ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	value := client.PublicURL("public", "organizations/org/applications/app/file name.png")
	if !strings.Contains(value, "/public/organizations/org/applications/app/file%20name.png") || strings.Contains(value, "%2520") {
		t.Fatalf("unexpected public URL: %s", value)
	}
}
