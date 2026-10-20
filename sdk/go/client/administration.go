package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type ManagedUserCreate struct {
	Email            string          `json:"email"`
	FirstName        string          `json:"first_name,omitempty"`
	LastName         string          `json:"last_name,omitempty"`
	Username         *string         `json:"username,omitempty"`
	Locale           string          `json:"locale,omitempty"`
	EmailVerified    *bool           `json:"email_verified,omitempty"`
	IsOrgVerified    *bool           `json:"is_org_verified,omitempty"`
	CustomAttributes *map[string]any `json:"custom_attributes,omitempty"`
	Reason           string          `json:"reason"`
}
type ManagedUserUpdate struct {
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	Username  *string `json:"username,omitempty"`
	Locale    *string `json:"locale,omitempty"`
	Reason    string  `json:"reason"`
}
type ManagedAttributes struct {
	CustomAttributes map[string]any `json:"custom_attributes"`
	Reason           string         `json:"reason"`
}
type ManagedRoleAssignment struct {
	UserID      string  `json:"user_id"`
	RoleID      string  `json:"role_id"`
	WorkspaceID *string `json:"workspace_id,omitempty"`
	Reason      string  `json:"reason"`
}
type UserRoleAssignment struct {
	ID          string  `json:"id"`
	UserID      *string `json:"user_id"`
	RoleID      string  `json:"role_id"`
	RoleKey     string  `json:"role_key,omitempty"`
	RoleScope   string  `json:"role_scope,omitempty"`
	WorkspaceID *string `json:"workspace_id"`
}
type ApplicationRole struct {
	ID          string   `json:"id"`
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"`
}
type UserSession struct {
	ID              string   `json:"id"`
	UserAgent       *string  `json:"user_agent"`
	AuthenticatedAt string   `json:"authenticated_at"`
	ExpiresAt       string   `json:"expires_at"`
	RevokedAt       *string  `json:"revoked_at"`
	AMR             []string `json:"amr"`
}
type InvitationDelivery struct {
	Invitation
	InvitationURL string `json:"invitation_url"`
	EmailQueued   bool   `json:"email_queued"`
	Version       int64  `json:"version"`
}
type RotateInvitation struct {
	SendEmail bool   `json:"send_email"`
	Reason    string `json:"reason"`
}
type Administration struct{ client *Client }

func (c *Client) Administration() *Administration { return &Administration{client: c} }
func (a *Administration) ListUsers(ctx context.Context, search, cursor string, limit int) (Page[User], error) {
	query := url.Values{"query": {search}, "cursor": {cursor}}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var out Page[User]
	err := a.client.request(ctx, "GET", "/users?"+query.Encode(), nil, "", &out)
	return out, err
}
func (a *Administration) GetUser(ctx context.Context, id string) (User, error) {
	return a.client.GetUser(ctx, id)
}
func (a *Administration) CreateUser(ctx context.Context, in ManagedUserCreate, key string) (User, error) {
	var out User
	err := a.client.request(ctx, "POST", "/users", in, key, &out)
	return out, err
}
func (a *Administration) UpdateUser(ctx context.Context, id string, in ManagedUserUpdate, etag string) error {
	return a.client.request(ctx, "PATCH", "/users/"+url.PathEscape(id), in, "", nil, http.Header{"If-Match": {etag}})
}
func (a *Administration) UpdateAttributes(ctx context.Context, id string, in ManagedAttributes, etag string) error {
	return a.client.request(ctx, "PATCH", "/users/"+url.PathEscape(id)+"/attributes", in, "", nil, http.Header{"If-Match": {etag}})
}
func (a *Administration) ChangeUserState(ctx context.Context, id, action, reason, etag, key string) error {
	switch action {
	case "suspend", "restore", "verify-email", "unverify-email", "verify-organization", "unverify-organization", "sessions/revoke":
	default:
		return &InvalidAdministrationAction{}
	}
	return a.client.request(ctx, "POST", "/users/"+url.PathEscape(id)+"/"+action, struct {
		Reason string `json:"reason"`
	}{reason}, key, nil, http.Header{"If-Match": {etag}})
}

type InvalidAdministrationAction struct{}

func (*InvalidAdministrationAction) Error() string {
	return "invalid application administration action"
}
func (a *Administration) ListSessions(ctx context.Context, id string) (Page[UserSession], error) {
	var out Page[UserSession]
	err := a.client.request(ctx, "GET", "/users/"+url.PathEscape(id)+"/sessions", nil, "", &out)
	return out, err
}
func (a *Administration) ListRoles(ctx context.Context) (Page[ApplicationRole], error) {
	var out Page[ApplicationRole]
	err := a.client.request(ctx, "GET", "/roles", nil, "", &out)
	return out, err
}
func (a *Administration) ListAssignments(ctx context.Context, user string) (Page[UserRoleAssignment], error) {
	var out Page[UserRoleAssignment]
	err := a.client.request(ctx, "GET", "/role-assignments?user_id="+url.QueryEscape(user), nil, "", &out)
	return out, err
}
func (a *Administration) AssignRole(ctx context.Context, in ManagedRoleAssignment, etag, key string) (UserRoleAssignment, error) {
	var out UserRoleAssignment
	err := a.client.request(ctx, "POST", "/role-assignments", in, key, &out, http.Header{"If-Match": {etag}})
	return out, err
}
func (a *Administration) RemoveRole(ctx context.Context, id, reason, etag string) error {
	return a.client.request(ctx, "DELETE", "/role-assignments/"+url.PathEscape(id), struct {
		Reason string `json:"reason"`
	}{reason}, "", nil, http.Header{"If-Match": {etag}})
}
func (a *Administration) CreateInvitation(ctx context.Context, in CreateInvitation, key string) (InvitationDelivery, error) {
	var out InvitationDelivery
	err := a.client.request(ctx, "POST", "/invitations", in, key, &out)
	return out, err
}
func (a *Administration) RotateInvitation(ctx context.Context, id string, in RotateInvitation, etag, key string) (InvitationDelivery, error) {
	var out InvitationDelivery
	err := a.client.request(ctx, "POST", "/invitations/"+url.PathEscape(id)+"/rotate", in, key, &out, http.Header{"If-Match": {etag}})
	return out, err
}
func (a *Administration) RevokeInvitation(ctx context.Context, id, reason, etag string) error {
	return a.client.request(ctx, "DELETE", "/invitations/"+url.PathEscape(id), struct {
		Reason string `json:"reason"`
	}{reason}, "", nil, http.Header{"If-Match": {etag}})
}
