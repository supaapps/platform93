package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Claims struct {
	Issuer        string         `json:"iss"`
	Subject       string         `json:"sub"`
	Audience      []string       `json:"aud"`
	ExpiresAt     int64          `json:"exp"`
	IssuedAt      int64          `json:"iat"`
	NotBefore     int64          `json:"nbf"`
	ApplicationID string         `json:"application_id"`
	TokenKind     string         `json:"token_kind"`
	ActorType     string         `json:"actor_type"`
	Scope         string         `json:"scope"`
	Roles         RoleClaims     `json:"roles"`
	Locale        string         `json:"locale,omitempty"`
	EmailVerified bool           `json:"email_verified"`
	IsOrgVerified bool           `json:"is_org_verified"`
	CustomClaims  map[string]any `json:"custom_claims,omitempty"`
	Actor         *Actor         `json:"act,omitempty"`
}

type RoleClaims struct {
	Application []string            `json:"application"`
	Workspaces  map[string][]string `json:"workspaces"`
}

var (
	permissionSegment = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	roleKey           = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	workspaceKey      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type Actor struct {
	Subject string `json:"sub"`
	Type    string `json:"type"`
}
type Verifier struct {
	Issuer, Audience, ApplicationID string
	Client                          *http.Client
	mu                              sync.Mutex
	keys                            map[string]*rsa.PublicKey
	expires                         time.Time
}

func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("malformed token")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, err
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
		Typ string `json:"typ"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Alg != "RS256" || header.Typ != "JWT" || header.KID == "" {
		return Claims{}, fmt.Errorf("token algorithm rejected")
	}
	key, err := v.key(ctx, header.KID)
	if err != nil {
		return Claims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return Claims{}, fmt.Errorf("token signature rejected")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var claims Claims
	now := time.Now()
	if json.Unmarshal(payload, &claims) != nil || claims.Issuer != strings.TrimRight(v.Issuer, "/") || claims.Subject == "" || claims.IssuedAt == 0 || claims.IssuedAt > now.Add(30*time.Second).Unix() || claims.ApplicationID != v.ApplicationID || claims.ExpiresAt <= now.Unix() || claims.NotBefore == 0 || claims.NotBefore > now.Add(30*time.Second).Unix() || !contains(claims.Audience, v.Audience) || claims.TokenKind == "access" && claims.ActorType != "user" || claims.TokenKind == "machine" && claims.ActorType != "client" || claims.TokenKind != "access" && claims.TokenKind != "machine" {
		return Claims{}, fmt.Errorf("token claims rejected")
	}
	if claims.Actor != nil && (claims.TokenKind != "access" || claims.Actor.Type != "control_user" || claims.Actor.Subject == "") {
		return Claims{}, fmt.Errorf("delegated token actor rejected")
	}
	if !validScopeClaim(claims.Scope, v.ApplicationID) || !validRoleClaims(claims.Roles) {
		return Claims{}, fmt.Errorf("token authorization claims rejected")
	}
	if claims.Actor != nil && (len(claims.Roles.Application) != 0 || len(claims.Roles.Workspaces) != 0) {
		return Claims{}, fmt.Errorf("delegated token roles rejected")
	}
	return claims, nil
}
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Now().Before(v.expires) && v.keys[kid] != nil {
		return v.keys[kid], nil
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	request, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(v.Issuer, "/")+"/jwks.json", nil)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var document struct {
		Keys []struct {
			KID string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&document) != nil {
		return nil, fmt.Errorf("JWKS unavailable")
	}
	v.keys = map[string]*rsa.PublicKey{}
	for _, item := range document.Keys {
		n, nErr := base64.RawURLEncoding.DecodeString(item.N)
		e, eErr := base64.RawURLEncoding.DecodeString(item.E)
		exponent := new(big.Int).SetBytes(e)
		modulus := new(big.Int).SetBytes(n)
		if nErr != nil || eErr != nil || item.KID == "" || item.Kty != "RSA" || item.Alg != "" && item.Alg != "RS256" || item.Use != "" && item.Use != "sig" || modulus.BitLen() < 2048 || !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64()%2 == 0 {
			continue
		}
		v.keys[item.KID] = &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
	}
	v.expires = time.Now().Add(5 * time.Minute)
	key := v.keys[kid]
	if key == nil {
		return nil, fmt.Errorf("unknown signing key")
	}
	return key, nil
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func (c Claims) HasPermission(permission string) bool {
	for _, value := range strings.Fields(c.Scope) {
		if permissionMatches(value, permission) {
			return true
		}
	}
	return false
}

func permissionMatches(granted, wanted string) bool {
	if !validAbsolutePermission(granted) || !validAbsolutePermission(wanted) {
		return false
	}
	if granted == wanted {
		return true
	}
	if !strings.HasSuffix(granted, "/*") {
		return false
	}
	base := strings.TrimSuffix(granted, "/*")
	return wanted == base || strings.HasPrefix(wanted, base+"/")
}

func validScopeClaim(scope, applicationID string) bool {
	if scope == "" {
		return true
	}
	if scope != strings.TrimSpace(scope) || strings.ContainsAny(scope, "\t\r\n") || strings.Contains(scope, "  ") {
		return false
	}
	seen := map[string]struct{}{}
	prefix := "/applications/" + applicationID + "/"
	for _, value := range strings.Split(scope, " ") {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
		if value == "openid" || value == "profile" || value == "email" || value == "offline_access" {
			continue
		}
		if !strings.HasPrefix(value, prefix) || !validAbsolutePermission(value) {
			return false
		}
	}
	return true
}

func validAbsolutePermission(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, " :\\%\t\r\n") {
		return false
	}
	segments := strings.Split(value[1:], "/")
	if len(segments) < 3 {
		return false
	}
	for index, segment := range segments {
		if segment == "*" {
			if index != len(segments)-1 {
				return false
			}
			continue
		}
		if !permissionSegment.MatchString(segment) {
			return false
		}
	}
	return true
}

func validRoleClaims(roles RoleClaims) bool {
	if roles.Application == nil || roles.Workspaces == nil || !uniqueRoles(roles.Application) {
		return false
	}
	for workspaceID, values := range roles.Workspaces {
		if !workspaceKey.MatchString(workspaceID) || values == nil || !uniqueRoles(values) {
			return false
		}
	}
	return true
}

func uniqueRoles(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if !roleKey.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
