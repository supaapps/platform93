package client

import (
	"context"
	"encoding/json"
	"fmt"
)

type ResourceCapability struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Context     string   `json:"context"`
	Permissions []string `json:"permissions"`
}

type OAuthResource struct {
	ID                  string               `json:"id"`
	ApplicationID       string               `json:"application_id"`
	URI                 string               `json:"uri"`
	Name                string               `json:"name"`
	Enabled             bool                 `json:"enabled"`
	AllowClientMetadata bool                 `json:"allow_client_metadata"`
	ClientIDs           []string             `json:"client_ids"`
	Capabilities        []ResourceCapability `json:"capabilities"`
	Version             int64                `json:"version"`
	CreatedAt           string               `json:"created_at"`
	UpdatedAt           string               `json:"updated_at"`
}

type OAuthConnection struct {
	ID              string   `json:"id"`
	ApplicationID   string   `json:"application_id"`
	ResourceID      string   `json:"resource_id"`
	ResourceVersion int64    `json:"resource_version"`
	UserID          string   `json:"user_id"`
	ClientID        string   `json:"client_id"`
	SessionID       string   `json:"session_id"`
	Capabilities    []string `json:"capabilities"`
	PersonalAccess  bool     `json:"personal_access"`
	WorkspaceIDs    []string `json:"workspace_ids"`
	ExpiresAt       string   `json:"expires_at"`
	RevokedAt       *string  `json:"revoked_at"`
	Version         int64    `json:"version"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

type ResourceAccessCheckRequest struct {
	Token       string `json:"token"`
	Resource    string `json:"resource"`
	Capability  string `json:"capability"`
	WorkspaceID string `json:"workspace_id,omitempty"`
}

type ResourceAccessCheckResponse struct {
	Allowed      bool    `json:"allowed"`
	Reason       string  `json:"reason"`
	UserID       *string `json:"user_id,omitempty"`
	ConnectionID *string `json:"connection_id,omitempty"`
	WorkspaceID  *string `json:"workspace_id,omitempty"`
}

func (r *ResourceAccessCheckResponse) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, key := range []string{"allowed", "reason"} {
		if value, exists := raw[key]; !exists || string(value) == "null" {
			return fmt.Errorf("invalid resource check response")
		}
	}
	for _, key := range []string{"user_id", "connection_id", "workspace_id"} {
		if value, exists := raw[key]; exists && string(value) == "null" {
			return fmt.Errorf("invalid resource check response")
		}
	}
	type plain ResourceAccessCheckResponse
	return json.Unmarshal(data, (*plain)(r))
}

func (c *Client) CheckResourceAccess(ctx context.Context, input ResourceAccessCheckRequest) (ResourceAccessCheckResponse, error) {
	var result ResourceAccessCheckResponse
	err := c.request(ctx, "POST", "/service/resource-access/check", input, "", &result)
	return result, err
}
