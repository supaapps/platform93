package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var externalAuthProviders = []string{"google", "apple", "microsoft", "facebook", "linkedin"}

var microsoftTenantPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

const microsoftConsumerTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

var providerEndpoints = map[string]oauth2.Endpoint{
	"microsoft": {
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
	},
	"linkedin": {
		AuthURL:  "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
	},
	"facebook": {
		AuthURL:  "https://www.facebook.com/v26.0/dialog/oauth",
		TokenURL: "https://graph.facebook.com/v26.0/oauth/access_token",
	},
}

type externalProviderIdentity struct {
	Subject      string
	Email        string
	FirstName    string
	LastName     string
	TrustedEmail bool
	Metadata     map[string]any
}

func validExternalAuthProvider(provider string) bool {
	for _, supported := range externalAuthProviders {
		if provider == supported {
			return true
		}
	}
	return false
}

func providerUsesPKCE(provider string) bool {
	return provider == "google" || provider == "microsoft" || provider == "linkedin"
}

func normalizeMicrosoftTenant(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "common", nil
	}
	if value == "common" || value == "organizations" || value == "consumers" || microsoftTenantPattern.MatchString(value) {
		return value, nil
	}
	return "", fmt.Errorf("microsoft tenant must be common, organizations, consumers, or a tenant UUID")
}

func providerOAuthConfig(config externalAuthProviderConfig, callbackURI string) (oauth2.Config, error) {
	endpoint, ok := providerEndpoints[config.Provider]
	if !ok {
		return oauth2.Config{}, fmt.Errorf("provider does not use the shared OAuth flow")
	}
	if config.Provider == "microsoft" {
		tenant, err := normalizeMicrosoftTenant(config.Credentials["tenant"])
		if err != nil {
			return oauth2.Config{}, err
		}
		endpoint.AuthURL = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize"
		endpoint.TokenURL = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token"
	}
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if config.Provider == "facebook" {
		scopes = []string{"public_profile", "email"}
	}
	return oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.Credentials["client_secret"],
		Endpoint:     endpoint,
		RedirectURL:  callbackURI,
		Scopes:       scopes,
	}, nil
}

func providerAuthorizationURL(config externalAuthProviderConfig, callbackURI, state, nonce, verifier, loginHint string) (string, error) {
	oauthConfig, err := providerOAuthConfig(config, callbackURI)
	if err != nil {
		return "", err
	}
	options := []oauth2.AuthCodeOption{}
	if providerUsesPKCE(config.Provider) {
		options = append(options, oauth2.S256ChallengeOption(verifier))
	}
	if config.Provider != "facebook" {
		options = append(options, oauth2.SetAuthURLParam("nonce", nonce))
	}
	if loginHint != "" && config.Provider == "microsoft" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", loginHint))
	}
	return oauthConfig.AuthCodeURL(state, options...), nil
}

func exchangeExternalProviderIdentity(ctx context.Context, config externalAuthProviderConfig, callbackURI, code, verifier string, nonceDigest []byte, digest func(string) []byte) (externalProviderIdentity, error) {
	if config.Provider == "facebook" {
		return exchangeFacebookIdentity(ctx, config, callbackURI, code)
	}
	oauthConfig, err := providerOAuthConfig(config, callbackURI)
	if err != nil {
		return externalProviderIdentity{}, err
	}
	options := []oauth2.AuthCodeOption{}
	if providerUsesPKCE(config.Provider) {
		options = append(options, oauth2.VerifierOption(verifier))
	}
	token, err := oauthConfig.Exchange(ctx, code, options...)
	if err != nil {
		return externalProviderIdentity{}, err
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return externalProviderIdentity{}, fmt.Errorf("provider did not return an ID token")
	}
	if config.Provider == "linkedin" {
		return verifyLinkedInIdentity(ctx, config, rawIDToken, nonceDigest, digest)
	}
	return verifyMicrosoftIdentity(ctx, config, rawIDToken, nonceDigest, digest)
}

func verifyLinkedInIdentity(ctx context.Context, config externalAuthProviderConfig, raw string, nonceDigest []byte, digest func(string) []byte) (externalProviderIdentity, error) {
	verifier := oidc.NewVerifier("https://www.linkedin.com", oidc.NewRemoteKeySet(ctx, "https://www.linkedin.com/oauth/openid/jwks"), &oidc.Config{ClientID: config.ClientID})
	verified, err := verifier.Verify(ctx, raw)
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		FirstName     string `json:"given_name"`
		LastName      string `json:"family_name"`
		Nonce         string `json:"nonce"`
		EmailVerified bool   `json:"email_verified"`
		Locale        string `json:"locale"`
	}
	if err == nil {
		err = verified.Claims(&claims)
	}
	if err != nil || claims.Subject == "" || claims.Nonce == "" || !equalBytes(nonceDigest, digest(claims.Nonce)) {
		return externalProviderIdentity{}, fmt.Errorf("invalid linkedin identity")
	}
	return externalProviderIdentity{Subject: claims.Subject, Email: claims.Email, FirstName: claims.FirstName, LastName: claims.LastName,
		TrustedEmail: claims.EmailVerified && strings.Contains(claims.Email, "@"), Metadata: map[string]any{"locale": claims.Locale}}, nil
}

func verifyMicrosoftIdentity(ctx context.Context, config externalAuthProviderConfig, raw string, nonceDigest []byte, digest func(string) []byte) (externalProviderIdentity, error) {
	var unverified struct {
		Issuer string `json:"iss"`
		Tenant string `json:"tid"`
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return externalProviderIdentity{}, fmt.Errorf("invalid microsoft token")
	}
	payload, err := decodeJWTPart(parts[1])
	if err != nil || json.Unmarshal(payload, &unverified) != nil {
		return externalProviderIdentity{}, fmt.Errorf("invalid microsoft claims")
	}
	tenant, err := normalizeMicrosoftTenant(config.Credentials["tenant"])
	if err != nil || !microsoftIssuerAllowed(tenant, unverified.Tenant, unverified.Issuer) {
		return externalProviderIdentity{}, fmt.Errorf("microsoft tenant is not allowed")
	}
	verifier := oidc.NewVerifier(unverified.Issuer, oidc.NewRemoteKeySet(ctx, "https://login.microsoftonline.com/common/discovery/v2.0/keys"), &oidc.Config{ClientID: config.ClientID})
	verified, err := verifier.Verify(ctx, raw)
	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
		Nonce             string `json:"nonce"`
		Tenant            string `json:"tid"`
	}
	if err == nil {
		err = verified.Claims(&claims)
	}
	if err != nil || claims.Subject == "" || claims.Nonce == "" || !equalBytes(nonceDigest, digest(claims.Nonce)) {
		return externalProviderIdentity{}, fmt.Errorf("invalid microsoft identity")
	}
	email := claims.Email
	if email == "" && strings.Contains(claims.PreferredUsername, "@") {
		email = claims.PreferredUsername
	}
	first, last := claims.GivenName, claims.FamilyName
	if first == "" && last == "" {
		first, last = splitDisplayName(claims.Name)
	}
	return externalProviderIdentity{Subject: unverified.Issuer + "|" + claims.Subject, Email: email, FirstName: first, LastName: last,
		TrustedEmail: false, Metadata: map[string]any{"tenant_id": claims.Tenant}}, nil
}

func microsoftIssuerAllowed(configured, tenantID, issuer string) bool {
	tenantID = strings.ToLower(tenantID)
	wantIssuer := "https://login.microsoftonline.com/" + tenantID + "/v2.0"
	if !microsoftTenantPattern.MatchString(tenantID) || !strings.EqualFold(strings.TrimRight(issuer, "/"), wantIssuer) {
		return false
	}
	switch configured {
	case "common":
		return true
	case "organizations":
		return tenantID != microsoftConsumerTenantID
	case "consumers":
		return tenantID == microsoftConsumerTenantID
	default:
		return strings.EqualFold(configured, tenantID)
	}
}

func exchangeFacebookIdentity(ctx context.Context, config externalAuthProviderConfig, callbackURI, code string) (externalProviderIdentity, error) {
	oauthConfig, err := providerOAuthConfig(config, callbackURI)
	if err != nil {
		return externalProviderIdentity{}, err
	}
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil || token.AccessToken == "" {
		return externalProviderIdentity{}, fmt.Errorf("facebook exchange failed")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	debugURL := "https://graph.facebook.com/debug_token?" + url.Values{
		"input_token":  {token.AccessToken},
		"access_token": {config.ClientID + "|" + config.Credentials["client_secret"]},
	}.Encode()
	var debug struct {
		Data struct {
			AppID   string `json:"app_id"`
			UserID  string `json:"user_id"`
			IsValid bool   `json:"is_valid"`
		} `json:"data"`
	}
	if err = getBoundedJSON(ctx, client, debugURL, &debug); err != nil || !debug.Data.IsValid || debug.Data.AppID != config.ClientID || debug.Data.UserID == "" {
		return externalProviderIdentity{}, fmt.Errorf("invalid facebook access token")
	}
	proof := hmac.New(sha256.New, []byte(config.Credentials["client_secret"]))
	_, _ = proof.Write([]byte(token.AccessToken))
	profileURL := "https://graph.facebook.com/v26.0/me?" + url.Values{
		"fields":          {"id,first_name,last_name,email"},
		"access_token":    {token.AccessToken},
		"appsecret_proof": {hex.EncodeToString(proof.Sum(nil))},
	}.Encode()
	var profile struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err = getBoundedJSON(ctx, client, profileURL, &profile); err != nil || profile.ID != debug.Data.UserID {
		return externalProviderIdentity{}, fmt.Errorf("invalid facebook profile")
	}
	return externalProviderIdentity{Subject: profile.ID, Email: profile.Email, FirstName: profile.FirstName, LastName: profile.LastName,
		TrustedEmail: false, Metadata: map[string]any{}}, nil
}

func getBoundedJSON(ctx context.Context, client *http.Client, endpoint string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("provider returned %s", response.Status)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target)
}

func splitDisplayName(name string) (string, string) {
	parts := strings.Fields(name)
	if len(parts) < 2 {
		return name, ""
	}
	return strings.Join(parts[:len(parts)-1], " "), parts[len(parts)-1]
}

func decodeJWTPart(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
