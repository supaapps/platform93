package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateAppleClientSecret(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	secret, err := createAppleClientSecret(externalAuthProviderConfig{
		ClientID: "com.example.web",
		Credentials: map[string]string{
			"team_id":         "TEAM123",
			"key_id":          "KEY123",
			"private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})),
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Parse(secret, func(token *jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithAudience("https://appleid.apple.com"), jwt.WithIssuer("TEAM123"), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !token.Valid {
		t.Fatalf("generated Apple client secret is invalid: %v", err)
	}
	if token.Header["kid"] != "KEY123" {
		t.Fatalf("unexpected Apple key id: %v", token.Header["kid"])
	}
	claims := token.Claims.(jwt.MapClaims)
	if claims["sub"] != "com.example.web" {
		t.Fatalf("unexpected Apple client id: %v", claims["sub"])
	}
}

func TestAppleProviderHelpers(t *testing.T) {
	first, last := appleCallbackName(`{"name":{"firstName":"Ada","lastName":"Lovelace"}}`)
	if first != "Ada" || last != "Lovelace" {
		t.Fatalf("unexpected Apple name: %q %q", first, last)
	}
	if !appleEmailVerified(true) || !appleEmailVerified("true") || appleEmailVerified("false") {
		t.Fatal("Apple email verification variants were handled incorrectly")
	}
}
