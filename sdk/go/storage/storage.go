// Package storage provides the direct-transfer Platform93 object storage flow.
// It never receives or stores S3 credentials; Platform93 authorizes short-lived
// transfer URLs for the authenticated application actor.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL       string
	ApplicationID string
	AccessToken   func(context.Context) (string, error)
	HTTPClient    *http.Client
}

type CreateUpload struct {
	Filename    string         `json:"filename"`
	ContentType string         `json:"content_type"`
	SizeBytes   int64          `json:"size_bytes"`
	Visibility  string         `json:"visibility"`
	Purpose     string         `json:"purpose,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type Object struct {
	ID              string         `json:"id"`
	ApplicationID   *string        `json:"application_id"`
	ProviderID      string         `json:"provider_id"`
	OwnerType       string         `json:"owner_type"`
	OwnerID         *string        `json:"owner_id"`
	Visibility      string         `json:"visibility"`
	Filename        string         `json:"filename"`
	ContentType     string         `json:"content_type"`
	SizeBytes       int64          `json:"size_bytes"`
	ETag            *string        `json:"etag"`
	Metadata        map[string]any `json:"metadata"`
	Status          string         `json:"status"`
	PublicURL       *string        `json:"public_url"`
	UploadExpiresAt *time.Time     `json:"upload_expires_at"`
	ReadyAt         *time.Time     `json:"ready_at"`
	LastError       *string        `json:"last_error"`
	Version         int64          `json:"version"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type UploadAuthorization struct {
	Object          Object            `json:"object"`
	UploadURL       string            `json:"upload_url"`
	UploadExpiresAt time.Time         `json:"upload_expires_at"`
	RequiredHeaders map[string]string `json:"required_headers"`
}

type Page struct {
	Items      []Object `json:"items"`
	NextCursor *string  `json:"next_cursor"`
}

type Download struct {
	URL        string     `json:"url"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Visibility string     `json:"visibility"`
}

func (c *Client) CreateUpload(ctx context.Context, input CreateUpload, idempotencyKey, workspaceID string) (UploadAuthorization, error) {
	var result UploadAuthorization
	err := c.request(ctx, http.MethodPost, c.ownerPath(workspaceID)+"/storage/uploads", input, idempotencyKey, &result)
	return result, err
}

func (c *Client) CompleteUpload(ctx context.Context, objectID, workspaceID string) (Object, error) {
	var result Object
	err := c.request(ctx, http.MethodPost, c.ownerPath(workspaceID)+"/storage/uploads/"+url.PathEscape(objectID)+"/complete", nil, "", &result)
	return result, err
}

func (c *Client) List(ctx context.Context, workspaceID string) (Page, error) {
	var result Page
	err := c.request(ctx, http.MethodGet, c.ownerPath(workspaceID)+"/storage/objects", nil, "", &result)
	return result, err
}

func (c *Client) Download(ctx context.Context, objectID, workspaceID string) (Download, error) {
	var result Download
	err := c.request(ctx, http.MethodPost, c.ownerPath(workspaceID)+"/storage/objects/"+url.PathEscape(objectID)+"/download", nil, "", &result)
	return result, err
}

func (c *Client) Delete(ctx context.Context, objectID, workspaceID string) error {
	return c.request(ctx, http.MethodDelete, c.ownerPath(workspaceID)+"/storage/objects/"+url.PathEscape(objectID), nil, "", nil)
}

// Put transfers bytes directly to the provider URL using only the headers that
// were signed into the authorization. It does not send the Platform93 token.
func (c *Client) Put(ctx context.Context, authorization UploadAuthorization, body io.Reader) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, authorization.UploadURL, body)
	if err != nil {
		return err
	}
	for name, value := range authorization.RequiredHeaders {
		if !strings.EqualFold(name, "host") && !strings.EqualFold(name, "content-length") && !strings.EqualFold(name, "authorization") {
			request.Header.Set(name, value)
		}
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("storage upload returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (c *Client) ownerPath(workspaceID string) string {
	base := "/v1/applications/" + url.PathEscape(c.ApplicationID)
	if workspaceID == "" {
		return base + "/me"
	}
	return base + "/workspaces/" + url.PathEscape(workspaceID)
}

func (c *Client) request(ctx context.Context, method, path string, input any, idempotencyKey string, output any) error {
	if c.BaseURL == "" || c.ApplicationID == "" || c.AccessToken == nil {
		return fmt.Errorf("Platform93 storage client requires base URL, application ID, and access token callback")
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	token, err := c.AccessToken(ctx)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
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
		excerpt, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("Platform93 storage request returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(excerpt)))
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}
