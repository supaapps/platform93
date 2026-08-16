package identity

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestRS256ClaimsAreStrictlyBound(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	applicationID := "01900000-0000-7000-8000-000000000001"
	audience := "platform93:application:" + applicationID
	claims := Claims{Issuer: "https://issuer.example/oidc", Subject: "01900000-0000-7000-8000-000000000002", Audience: []string{audience}, ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(), NotBefore: now.Add(-time.Second).Unix(), JWTID: "01900000-0000-7000-8000-000000000003", ApplicationID: applicationID, TokenKind: "access", ActorType: "user", Roles: RoleClaims{Application: []string{}, Workspaces: map[string][]string{}}, Scope: "/applications/" + applicationID + "/profile/read"}
	token, err := Sign(pair.PrivatePEM, pair.KID, claims)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pair.PrivatePEM)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	verified, err := Verify(token, func(kid string) (*rsa.PublicKey, error) {
		if kid != pair.KID {
			t.Fatalf("unexpected kid %s", kid)
		}
		return &key.PublicKey, nil
	}, claims.Issuer, audience, now)
	if err != nil || verified.Subject != claims.Subject {
		t.Fatalf("valid token rejected: %v", err)
	}
	if _, err := Verify(token, func(string) (*rsa.PublicKey, error) { return &key.PublicKey, nil }, claims.Issuer, "wrong-audience", now); err == nil {
		t.Fatal("wrong audience accepted")
	}
}
