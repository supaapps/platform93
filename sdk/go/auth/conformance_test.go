package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type jwtFixture struct {
	Audience      string `json:"audience"`
	ApplicationID string `json:"application_id"`
	Cases         []struct {
		Name     string `json:"name"`
		Mutation string `json:"mutation"`
		Accept   bool   `json:"accept"`
	} `json:"cases"`
}

func TestJWTConformance(t *testing.T) {
	raw, err := os.ReadFile("../../../conformance/jwt.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture jwtFixture
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid JWT conformance fixture")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk("primary", &key.PublicKey)}})
	}))
	defer server.Close()
	verifier := &Verifier{Issuer: server.URL, Audience: fixture.Audience, ApplicationID: fixture.ApplicationID}

	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			token := fixtureToken(t, testCase.Mutation, server.URL, fixture, key, wrongKey)
			_, verifyErr := verifier.Verify(context.Background(), token)
			if (verifyErr == nil) != testCase.Accept {
				t.Fatalf("accept=%v, error=%v", testCase.Accept, verifyErr)
			}
		})
	}
	if !(Claims{Scope: "/applications/app/*"}).HasPermission("/applications/app/billing/refund") {
		t.Fatal("global wildcard permission was not honored")
	}
}

func fixtureToken(t *testing.T, mutation, issuer string, fixture jwtFixture, key, wrongKey *rsa.PrivateKey) string {
	t.Helper()
	now := time.Now().Unix()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "primary"}
	claims := map[string]any{"iss": issuer, "sub": "user-1", "aud": []string{fixture.Audience}, "exp": now + 300, "iat": now, "nbf": now - 1,
		"application_id": fixture.ApplicationID, "token_kind": "access", "actor_type": "user", "scope": "/applications/app/profile/read"}
	signingKey := key
	switch mutation {
	case "machine":
		claims["token_kind"] = "machine"
		claims["actor_type"] = "client"
	case "delegated":
		claims["act"] = map[string]any{"sub": "operator-1", "type": "operator"}
	case "wrong_issuer":
		claims["iss"] = "https://wrong.example"
	case "wrong_audience":
		claims["aud"] = []string{"wrong-api"}
	case "wrong_application":
		claims["application_id"] = "01900000-0000-7000-8000-000000000000"
	case "expired":
		claims["exp"] = now - 60
	case "future_nbf":
		claims["nbf"] = now + 300
	case "future_iat":
		claims["iat"] = now + 300
	case "missing_sub":
		delete(claims, "sub")
	case "missing_application":
		delete(claims, "application_id")
	case "missing_token_kind":
		delete(claims, "token_kind")
	case "missing_actor_type":
		delete(claims, "actor_type")
	case "operator_actor":
		claims["actor_type"] = "operator"
	case "wrong_algorithm":
		header["alg"] = "HS256"
	case "missing_kid":
		delete(header, "kid")
	case "unknown_kid":
		header["kid"] = "unknown"
	case "wrong_signature":
		signingKey = wrongKey
	case "delegated_wrong_actor_type":
		claims["act"] = map[string]any{"sub": "operator-1", "type": "user"}
	}
	return signFixtureToken(t, header, claims, signingKey)
}

func signFixtureToken(t *testing.T, header, claims map[string]any, key *rsa.PrivateKey) string {
	t.Helper()
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func jwk(kid string, key *rsa.PublicKey) map[string]any {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent)}
}
