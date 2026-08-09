package webhooks

import "time"

type NamedData struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type ApplicationLifecycleData struct {
	OrganizationID string `json:"organization_id"`
	Reason         string `json:"reason"`
}

type OrganizationRetiredData struct {
	ApplicationCount int `json:"application_count"`
}

type OrganizationRestoredData struct {
	DescendantsRestored bool `json:"descendants_restored"`
}

type DelegationCreatedData struct {
	DelegationID string    `json:"delegation_id"`
	UserID       string    `json:"user_id"`
	WorkspaceID  *string   `json:"workspace_id"`
	Permissions  []string  `json:"permissions"`
	Reason       string    `json:"reason"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type DelegationExchangedData struct {
	DelegationID string `json:"delegation_id"`
	UserID       string `json:"user_id"`
}

type DelegationRevokedData struct {
	DelegationID string `json:"delegation_id"`
}

type EntitlementGrantedData struct {
	GrantID     string `json:"grant_id"`
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	Reason      string `json:"reason"`
}

type LocalEntitlementRequestCreatedData struct {
	RequestID   string `json:"request_id"`
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	PriceID     string `json:"price_id"`
}

type LocalEntitlementRequestApprovedData struct {
	RequestID string `json:"request_id"`
	GrantID   string `json:"grant_id"`
}

type OAuthConsentRevokedData struct {
	UserID    string `json:"user_id"`
	ClientID  string `json:"client_id"`
	ClientKey string `json:"client_key"`
}

type WebhookTestData struct {
	WebhookEndpointID string `json:"webhook_endpoint_id"`
	Test              bool   `json:"test"`
}

type StorageObjectData struct {
	ObjectID   string `json:"object_id"`
	OwnerType  string `json:"owner_type"`
	Visibility string `json:"visibility"`
	SizeBytes  int64  `json:"size_bytes"`
}

type StorageProviderData struct {
	ProviderID     string `json:"provider_id"`
	Scope          string `json:"scope"`
	PublicEnabled  bool   `json:"public_enabled"`
	PrivateEnabled bool   `json:"private_enabled"`
}

type UserIDData struct {
	UserID string `json:"user_id"`
}

type UserCreatedData struct {
	UserID        string `json:"user_id"`
	EmailVerified bool   `json:"email_verified"`
	IsOrgVerified bool   `json:"is_org_verified"`
}

type UserVerificationData struct {
	UserID   string `json:"user_id"`
	Verified bool   `json:"verified"`
	Reason   string `json:"reason"`
}

type UserStateData struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}

type WorkspaceInvitationCreatedData struct {
	InvitationID string   `json:"invitation_id"`
	WorkspaceID  string   `json:"workspace_id"`
	RoleKeys     []string `json:"role_keys"`
}

type WorkspaceInvitationAcceptedData struct {
	InvitationID string `json:"invitation_id"`
	WorkspaceID  string `json:"workspace_id"`
	UserID       string `json:"user_id"`
}

type WorkspaceOwnerTransferredData struct {
	WorkspaceID              string `json:"workspace_id"`
	PreviousOwnerUserID      string `json:"previous_owner_user_id"`
	NewOwnerUserID           string `json:"new_owner_user_id"`
	PreviousOwnerDisposition string `json:"previous_owner_disposition"`
}
