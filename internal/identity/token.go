package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
)

type RoleClaims struct {
	Application []string            `json:"application"`
	Workspaces  map[string][]string `json:"workspaces"`
}

type Claims struct {
	Issuer        string         `json:"iss"`
	Subject       string         `json:"sub"`
	Audience      []string       `json:"aud"`
	ExpiresAt     int64          `json:"exp"`
	IssuedAt      int64          `json:"iat"`
	NotBefore     int64          `json:"nbf"`
	JWTID         string         `json:"jti"`
	SessionID     string         `json:"sid,omitempty"`
	ApplicationID string         `json:"application_id,omitempty"`
	ClientID      string         `json:"client_id,omitempty"`
	TokenKind     string         `json:"token_kind"`
	ActorType     string         `json:"actor_type"`
	Scope         string         `json:"scope,omitempty"`
	Roles         RoleClaims     `json:"roles"`
	Email         string         `json:"email,omitempty"`
	Locale        string         `json:"locale,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	IsOrgVerified bool           `json:"is_org_verified,omitempty"`
	CustomClaims  map[string]any `json:"custom_claims,omitempty"`
	AMR           []string       `json:"amr,omitempty"`
	Actor         *Actor         `json:"act,omitempty"`
}

type Actor struct {
	Subject string `json:"sub"`
	Type    string `json:"type"`
}

type KeyPair struct {
	PrivatePEM []byte
	PublicJWK  map[string]any
	KID        string
}

func GenerateKeyPair() (KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return KeyPair{}, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemValue := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	kid := uuid.Must(uuid.NewV7()).String()
	return KeyPair{PrivatePEM: pemValue, KID: kid, PublicJWK: PublicJWK(kid, &key.PublicKey)}, nil
}

func PublicJWK(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func Sign(privatePEM []byte, kid string, claims Claims) (string, error) {
	if claims.ApplicationID != "" {
		if err := platformauthz.ValidateScopeClaim(claims.Scope, claims.ApplicationID); err != nil {
			return "", fmt.Errorf("refuse to sign invalid token scope: %w", err)
		}
		if err := validateRoleClaims(claims.Roles); err != nil {
			return "", fmt.Errorf("refuse to sign invalid token roles: %w", err)
		}
		if claims.Actor != nil && (len(claims.Roles.Application) != 0 || len(claims.Roles.Workspaces) != 0) {
			return "", fmt.Errorf("refuse to sign delegated token with normal roles")
		}
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return "", fmt.Errorf("invalid RSA private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func Verify(token string, resolve func(kid string) (*rsa.PublicKey, error), issuer, audience string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("malformed token")
	}
	var header struct{ Alg, KID, Typ string }
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerJSON, &header) != nil || header.Alg != "RS256" || header.Typ != "JWT" || header.KID == "" {
		return Claims{}, fmt.Errorf("invalid token header")
	}
	key, err := resolve(header.KID)
	if err != nil {
		return Claims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return Claims{}, fmt.Errorf("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("invalid token payload")
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, fmt.Errorf("invalid token claims")
	}
	if claims.Issuer != issuer || !contains(claims.Audience, audience) || claims.ExpiresAt <= now.Unix() || claims.NotBefore > now.Add(30*time.Second).Unix() {
		return Claims{}, fmt.Errorf("token claims rejected")
	}
	if claims.ApplicationID != "" {
		if err := platformauthz.ValidateScopeClaim(claims.Scope, claims.ApplicationID); err != nil {
			return Claims{}, fmt.Errorf("token scope rejected: %w", err)
		}
		if err := validateRoleClaims(claims.Roles); err != nil {
			return Claims{}, fmt.Errorf("token roles rejected: %w", err)
		}
		if claims.Actor != nil && (len(claims.Roles.Application) != 0 || len(claims.Roles.Workspaces) != 0) {
			return Claims{}, fmt.Errorf("delegated token roles rejected")
		}
	}
	return claims, nil
}

func validateRoleClaims(roles RoleClaims) error {
	if roles.Application == nil || roles.Workspaces == nil {
		return fmt.Errorf("structured roles claim is required")
	}
	seen := map[string]struct{}{}
	for _, role := range roles.Application {
		if err := platformauthz.ValidateRoleKey(role); err != nil {
			return err
		}
		if _, duplicate := seen[role]; duplicate {
			return fmt.Errorf("application role is duplicated")
		}
		seen[role] = struct{}{}
	}
	for workspaceID, workspaceRoles := range roles.Workspaces {
		if _, err := uuid.Parse(workspaceID); err != nil || workspaceRoles == nil {
			return fmt.Errorf("workspace role context is invalid")
		}
		workspaceSeen := map[string]struct{}{}
		for _, role := range workspaceRoles {
			if err := platformauthz.ValidateRoleKey(role); err != nil {
				return err
			}
			if _, duplicate := workspaceSeen[role]; duplicate {
				return fmt.Errorf("workspace role is duplicated")
			}
			workspaceSeen[role] = struct{}{}
		}
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
