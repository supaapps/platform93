package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/supaapps/platform93/sdk/go/client"
)

func httpsURI(value string) error {
	for _, c := range value {
		if c < 33 || c > 126 || c == '"' || c == '\\' {
			return fmt.Errorf("invalid HTTPS resource URI")
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(value, "?#") {
		return fmt.Errorf("invalid HTTPS resource URI")
	}
	return nil
}

func CapabilityScope(applicationID, capability string) (string, error) {
	root := strings.Split(capability, ":")[0]
	if !workspaceKey.MatchString(applicationID) || len(capability) > 160 || root == "roles" || root == "workspaces" {
		return "", fmt.Errorf("invalid resource capability")
	}
	for _, part := range strings.Split(capability, ":") {
		if !permissionSegment.MatchString(part) {
			return "", fmt.Errorf("invalid resource capability")
		}
	}
	return "/applications/" + applicationID + "/" + strings.ReplaceAll(capability, ":", "/"), nil
}

type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

func ResourceMetadata(resource, issuer, applicationID string, capabilities []string) (ProtectedResourceMetadata, error) {
	result := ProtectedResourceMetadata{Resource: resource, AuthorizationServers: []string{issuer}, ScopesSupported: []string{}}
	if err := httpsURI(resource); err != nil {
		return result, err
	}
	if err := httpsURI(issuer); err != nil {
		return result, err
	}
	seen := map[string]bool{}
	for _, capability := range capabilities {
		scope, err := CapabilityScope(applicationID, capability)
		if err != nil {
			return result, err
		}
		if !seen[scope] {
			result.ScopesSupported = append(result.ScopesSupported, scope)
			seen[scope] = true
		}
	}
	return result, nil
}

func ResourceChallenge(metadataURI, code, description string) (string, error) {
	if err := httpsURI(metadataURI); err != nil {
		return "", err
	}
	if code != "" && code != "invalid_token" && code != "insufficient_scope" {
		return "", fmt.Errorf("invalid challenge error")
	}
	for _, c := range description {
		if c < 32 || c > 126 {
			return "", fmt.Errorf("invalid challenge value")
		}
	}
	quote := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
	result := "Bearer resource_metadata=" + quote(metadataURI)
	if code != "" {
		result += ", error=" + quote(code)
	}
	if description != "" {
		result += ", error_description=" + quote(description)
	}
	return result, nil
}

func validateResourceClaims(c Claims, payload []byte, resource string) error {
	reject := fmt.Errorf("Platform93 resource token rejected")
	if c.TokenKind != "resource_access" || c.ActorType != "user" || len(c.Audience) != 1 || c.Audience[0] != resource {
		return reject
	}
	for _, id := range []string{c.ApplicationID, c.Subject, c.SessionID, c.ConnectionID} {
		if !workspaceKey.MatchString(id) {
			return reject
		}
	}
	if c.ClientID == "" {
		return reject
	}
	for _, ch := range c.ClientID {
		if ch < 33 || ch > 126 {
			return reject
		}
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(payload, &raw) != nil {
		return reject
	}
	for _, key := range []string{"act", "workspace_id", "workspace_ids", "workspaces"} {
		if _, present := raw[key]; present {
			return reject
		}
	}
	var roles map[string]json.RawMessage
	if json.Unmarshal(raw["roles"], &roles) != nil || len(roles) != 2 || !validRoleClaims(c.Roles) || len(c.Roles.Application) != 0 || len(c.Roles.Workspaces) != 0 {
		return reject
	}
	if c.Scope == "" || !validScopeClaim(c.Scope, c.ApplicationID) {
		return reject
	}
	prefix := "/applications/" + c.ApplicationID + "/"
	for _, scope := range strings.Split(c.Scope, " ") {
		if scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access" {
			continue
		}
		if !strings.HasPrefix(scope, prefix) {
			return reject
		}
		key := strings.ReplaceAll(strings.TrimPrefix(scope, prefix), "/", ":")
		canonical, err := CapabilityScope(c.ApplicationID, key)
		if err != nil || canonical != scope || strings.HasPrefix(key, "workspaces:") {
			return reject
		}
	}
	return nil
}

type ResourceCheckClient interface {
	CheckResourceAccess(context.Context, client.ResourceAccessCheckRequest) (client.ResourceAccessCheckResponse, error)
}

type ResourceAuthorizer struct {
	Verifier      *Verifier
	Resource      string
	MachineClient ResourceCheckClient
}

// Authorize never caches decisions and never authorizes without a live check.
func (a *ResourceAuthorizer) Authorize(ctx context.Context, token, capability, workspaceID string) (Claims, error) {
	if len(token) > 16*1024 {
		return Claims{}, fmt.Errorf("resource token exceeds 16 KiB")
	}
	if err := httpsURI(a.Resource); err != nil {
		return Claims{}, err
	}
	if a.Verifier == nil || a.MachineClient == nil {
		return Claims{}, fmt.Errorf("resource verifier and machine client required")
	}
	expected, err := CapabilityScope(a.Verifier.ApplicationID, capability)
	if err != nil {
		return Claims{}, err
	}
	if workspaceID != "" && !workspaceKey.MatchString(workspaceID) {
		return Claims{}, fmt.Errorf("invalid workspace ID")
	}
	claims, err := a.Verifier.verify(ctx, token, a.Resource)
	if err != nil {
		return Claims{}, err
	}
	if !contains(strings.Split(claims.Scope, " "), expected) {
		return Claims{}, fmt.Errorf("resource capability denied")
	}
	result, err := a.MachineClient.CheckResourceAccess(ctx, client.ResourceAccessCheckRequest{Token: token, Resource: a.Resource, Capability: capability, WorkspaceID: workspaceID})
	if err != nil {
		return Claims{}, err
	}
	if !result.Allowed {
		return Claims{}, fmt.Errorf("resource access denied")
	}
	for _, id := range []*string{result.UserID, result.ConnectionID, result.WorkspaceID} {
		if id != nil && !workspaceKey.MatchString(*id) {
			return Claims{}, fmt.Errorf("invalid resource check response")
		}
	}
	if result.UserID != nil && *result.UserID != claims.Subject || result.ConnectionID != nil && *result.ConnectionID != claims.ConnectionID || result.WorkspaceID != nil && *result.WorkspaceID != workspaceID {
		return Claims{}, fmt.Errorf("resource check context mismatch")
	}
	return claims, nil
}
