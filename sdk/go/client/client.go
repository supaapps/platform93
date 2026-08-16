// Package client provides a server-side Platform93 machine client.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Client struct {
	BaseURL       string
	ApplicationID string
	ClientID      string
	ClientSecret  string
	Scopes        []string
	HTTPClient    *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

type Notification struct {
	TemplateKey string         `json:"template_key"`
	UserID      string         `json:"user_id,omitempty"`
	Recipient   string         `json:"recipient,omitempty"`
	Locale      string         `json:"locale,omitempty"`
	Variables   map[string]any `json:"variables,omitempty"`
	Attachments []Attachment   `json:"attachments,omitempty"`
}

type Attachment struct {
	Filename      string `json:"filename"`
	ContentType   string `json:"content_type"`
	ContentBase64 string `json:"content_base64"`
}

type QueuedNotification struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	RequestedLocale string `json:"requested_locale"`
	ResolvedLocale  string `json:"resolved_locale"`
	FallbackUsed    bool   `json:"fallback_used"`
}

type User struct {
	ID               string          `json:"id"`
	ApplicationID    string          `json:"application_id"`
	Email            string          `json:"email"`
	FirstName        string          `json:"first_name"`
	LastName         string          `json:"last_name"`
	Username         *string         `json:"username"`
	Locale           string          `json:"locale"`
	EmailVerified    bool            `json:"email_verified"`
	OrganizationOK   bool            `json:"is_org_verified"`
	Status           string          `json:"status"`
	CustomAttributes json.RawMessage `json:"custom_attributes"`
	Version          int64           `json:"version"`
}

type Workspace struct {
	ID            string          `json:"id"`
	ApplicationID string          `json:"application_id"`
	OwnerUserID   string          `json:"owner_user_id"`
	Key           string          `json:"key"`
	Name          string          `json:"name"`
	Metadata      json.RawMessage `json:"metadata"`
	Status        string          `json:"status"`
	Version       int64           `json:"version"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type WorkspaceAccess struct {
	Type         string     `json:"type"`
	WorkspaceID  string     `json:"workspace_id"`
	UserID       *string    `json:"user_id"`
	Email        *string    `json:"email"`
	RoleKeys     []string   `json:"role_keys"`
	InvitationID *string    `json:"invitation_id"`
	Status       string     `json:"status"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

type EntitlementGrant struct {
	ID                string          `json:"id"`
	SubjectType       string          `json:"subject_type"`
	SubjectID         string          `json:"subject_id"`
	SourceType        string          `json:"source_type"`
	SourceID          *string         `json:"source_id"`
	FeatureValues     json.RawMessage `json:"feature_values"`
	Configuration     json.RawMessage `json:"configuration"`
	StartsAt          time.Time       `json:"starts_at"`
	ExpiresAt         *time.Time      `json:"expires_at"`
	RevokedAt         *time.Time      `json:"revoked_at"`
	ExternalReference *string         `json:"external_reference"`
}

type BillingProfile struct {
	ID               string  `json:"id"`
	SubjectType      string  `json:"subject_type"`
	SubjectID        string  `json:"subject_id"`
	Name             *string `json:"name"`
	Email            *string `json:"email"`
	TaxID            *string `json:"tax_id"`
	DefaultAddressID *string `json:"default_address_id"`
	Version          int64   `json:"version"`
}

type Subscription struct {
	ID                string     `json:"id"`
	SubjectType       string     `json:"subject_type"`
	SubjectID         string     `json:"subject_id"`
	PriceID           string     `json:"price_id"`
	ProviderID        string     `json:"provider_id"`
	Status            string     `json:"status"`
	CurrentPeriodEnd  *time.Time `json:"current_period_end"`
	CancelAtPeriodEnd bool       `json:"cancel_at_period_end"`
	ExternalReference *string    `json:"external_reference"`
}

type BillingSummary struct {
	SubjectType    string          `json:"subject_type"`
	SubjectID      string          `json:"subject_id"`
	BillingProfile *BillingProfile `json:"billing_profile"`
	Subscriptions  []Subscription  `json:"subscriptions"`
}

type CustomEvent struct {
	Type          string          `json:"type"`
	Subject       string          `json:"subject"`
	Data          json.RawMessage `json:"data"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	CausationID   string          `json:"causation_id,omitempty"`
}

type PublishedEvent struct {
	ID            string          `json:"id"`
	SpecVersion   string          `json:"specversion"`
	Source        string          `json:"source"`
	Type          string          `json:"type"`
	Subject       string          `json:"subject"`
	SchemaVersion string          `json:"schema_version"`
	Data          json.RawMessage `json:"data"`
}

type Invitation struct {
	ID                  string     `json:"id"`
	Email               string     `json:"email"`
	WorkspaceID         *string    `json:"workspace_id"`
	ApplicationRoleKeys []string   `json:"application_role_keys"`
	WorkspaceRoleKeys   []string   `json:"workspace_role_keys"`
	Status              string     `json:"status"`
	ExpiresAt           time.Time  `json:"expires_at"`
	LastSentAt          time.Time  `json:"last_sent_at"`
	ResendAvailableAt   time.Time  `json:"resend_available_at"`
	AcceptedAt          *time.Time `json:"accepted_at"`
	RevokedAt           *time.Time `json:"revoked_at"`
}

type CreateInvitation struct {
	Email               string   `json:"email"`
	WorkspaceID         string   `json:"workspace_id,omitempty"`
	ApplicationRoleKeys []string `json:"application_role_keys,omitempty"`
	WorkspaceRoleKeys   []string `json:"workspace_role_keys,omitempty"`
	ExpiresIn           int64    `json:"expires_in,omitempty"`
}

func (c *Client) UpdateSecret(secret string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ClientSecret = secret
	c.token = ""
	c.expiresAt = time.Time{}
}

func (c *Client) SendNotification(ctx context.Context, input Notification, idempotencyKey string) (QueuedNotification, error) {
	var output QueuedNotification
	err := c.request(ctx, http.MethodPost, "/notifications", input, idempotencyKey, &output)
	return output, err
}

func (c *Client) CreateInvitation(ctx context.Context, input CreateInvitation) (Invitation, error) {
	var output Invitation
	err := c.request(ctx, http.MethodPost, "/invitations", input, "", &output)
	return output, err
}

func (c *Client) ListInvitations(ctx context.Context) (Page[Invitation], error) {
	var output Page[Invitation]
	err := c.request(ctx, http.MethodGet, "/invitations", nil, "", &output)
	return output, err
}

func (c *Client) GetInvitation(ctx context.Context, id string) (Invitation, error) {
	var output Invitation
	err := c.request(ctx, http.MethodGet, "/invitations/"+url.PathEscape(id), nil, "", &output)
	return output, err
}

func (c *Client) ResendInvitation(ctx context.Context, id string) (Invitation, error) {
	var output Invitation
	err := c.request(ctx, http.MethodPost, "/invitations/"+url.PathEscape(id)+"/resend", nil, "", &output)
	return output, err
}

func (c *Client) RevokeInvitation(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/invitations/"+url.PathEscape(id), nil, "", nil)
}

func (c *Client) ListUsers(ctx context.Context) (Page[User], error) {
	var output Page[User]
	err := c.request(ctx, http.MethodGet, "/users", nil, "", &output)
	return output, err
}

func (c *Client) GetUser(ctx context.Context, id string) (User, error) {
	var output User
	err := c.request(ctx, http.MethodGet, "/users/"+url.PathEscape(id), nil, "", &output)
	return output, err
}

func (c *Client) ListWorkspaces(ctx context.Context) (Page[Workspace], error) {
	var output Page[Workspace]
	err := c.request(ctx, http.MethodGet, "/workspaces", nil, "", &output)
	return output, err
}

func (c *Client) GetWorkspace(ctx context.Context, id string) (Workspace, error) {
	var output Workspace
	err := c.request(ctx, http.MethodGet, "/service/workspaces/"+url.PathEscape(id), nil, "", &output)
	return output, err
}

func (c *Client) GetWorkspaceAccess(ctx context.Context, id string) (Page[WorkspaceAccess], error) {
	var output Page[WorkspaceAccess]
	err := c.request(ctx, http.MethodGet, "/service/workspaces/"+url.PathEscape(id)+"/access", nil, "", &output)
	return output, err
}

func (c *Client) SubjectEntitlements(ctx context.Context, subjectType, subjectID string) (Page[EntitlementGrant], error) {
	var output Page[EntitlementGrant]
	err := c.request(ctx, http.MethodGet, "/subjects/"+url.PathEscape(subjectType)+"/"+url.PathEscape(subjectID)+"/entitlements", nil, "", &output)
	return output, err
}

func (c *Client) SubjectBilling(ctx context.Context, subjectType, subjectID string) (BillingSummary, error) {
	var output BillingSummary
	err := c.request(ctx, http.MethodGet, "/subjects/"+url.PathEscape(subjectType)+"/"+url.PathEscape(subjectID)+"/billing", nil, "", &output)
	return output, err
}

func (c *Client) PublishEvent(ctx context.Context, input CustomEvent, idempotencyKey string) (PublishedEvent, error) {
	var output PublishedEvent
	err := c.request(ctx, http.MethodPost, "/events", input, idempotencyKey, &output)
	return output, err
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiresAt.Add(-30*time.Second)) {
		return c.token, nil
	}
	if c.BaseURL == "" || c.ApplicationID == "" || c.ClientID == "" || c.ClientSecret == "" {
		return "", fmt.Errorf("Platform93 machine client requires base URL, application ID, client ID, and client secret")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(c.Scopes) > 0 {
		form.Set("scope", strings.Join(c.Scopes, " "))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.SetBasicAuth(c.ClientID, c.ClientSecret)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.httpClient().Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", responseError(response)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil || payload.AccessToken == "" {
		return "", fmt.Errorf("Platform93 token response is invalid")
	}
	if payload.ExpiresIn < 1 {
		payload.ExpiresIn = 300
	}
	c.token = payload.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	return c.token, nil
}

func (c *Client) request(ctx context.Context, method, path string, input any, idempotencyKey string, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+"/v1/applications/"+url.PathEscape(c.ApplicationID)+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response)
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(output)
}

func responseError(response *http.Response) error {
	excerpt, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("Platform93 request returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(excerpt)))
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}
