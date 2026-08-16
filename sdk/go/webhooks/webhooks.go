package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Event struct {
	SpecVersion    string          `json:"specversion"`
	ID             string          `json:"id"`
	Source         string          `json:"source"`
	Type           string          `json:"type"`
	ContractSource string          `json:"contract_source"`
	Time           time.Time       `json:"time"`
	ApplicationID  string          `json:"application_id"`
	SchemaVersion  string          `json:"schema_version"`
	Subject        *string         `json:"subject"`
	Actor          json.RawMessage `json:"actor"`
	CorrelationID  *string         `json:"correlation_id"`
	CausationID    *string         `json:"causation_id"`
	Data           json.RawMessage `json:"data"`
}

type InvitationLifecycleData struct {
	InvitationID string  `json:"invitation_id"`
	Status       string  `json:"status"`
	WorkspaceID  *string `json:"workspace_id,omitempty"`
	UserID       *string `json:"user_id,omitempty"`
	ExpiresAt    *string `json:"expires_at,omitempty"`
}

type EntitlementLifecycleData struct {
	GrantID           string  `json:"grant_id"`
	Status            string  `json:"status,omitempty"`
	SubjectType       string  `json:"subject_type,omitempty"`
	SubjectID         string  `json:"subject_id,omitempty"`
	ExternalReference *string `json:"external_reference,omitempty"`
	ExpiresAt         *string `json:"expires_at,omitempty"`
	Reason            string  `json:"reason,omitempty"`
}

type BillingLifecycleData struct {
	SubscriptionID    string  `json:"subscription_id,omitempty"`
	InvoiceID         string  `json:"invoice_id,omitempty"`
	PaymentID         string  `json:"payment_id,omitempty"`
	RefundID          string  `json:"refund_id,omitempty"`
	DisputeID         string  `json:"dispute_id,omitempty"`
	Status            string  `json:"status"`
	SubjectType       string  `json:"subject_type,omitempty"`
	SubjectID         string  `json:"subject_id,omitempty"`
	ExternalReference *string `json:"external_reference"`
}

type PermissionGrantLifecycleData struct {
	GrantID        string  `json:"grant_id"`
	SubjectType    string  `json:"subject_type"`
	SubjectID      string  `json:"subject_id"`
	WorkspaceID    *string `json:"workspace_id"`
	Permission     string  `json:"permission"`
	CanonicalScope string  `json:"canonical_scope"`
}

type ControlUserIdentityData struct {
	ControlUserID string `json:"control_user_id"`
	Provider      string `json:"provider"`
}

type ControlInvitationData struct {
	InvitationID     string  `json:"invitation_id"`
	OrganizationID   *string `json:"organization_id,omitempty"`
	ControlUserID    *string `json:"control_user_id,omitempty"`
	Role             string  `json:"role"`
	OnboardingMethod string  `json:"onboarding_method"`
	Status           string  `json:"status"`
}

var PlatformEventVersions = map[string]string{
	"organization.created": "1.0", "organization.retired": "1.0", "organization.restored": "1.0",
	"application.created": "1.0", "application.retired": "1.0", "application.restored": "1.0",
	"authorization.permission_grant.created": "1.0", "authorization.permission_grant.revoked": "1.0",
	"control_user.identity_linked": "1.0", "control_user.identity_unlinked": "1.0",
	"control_user.invitation_created": "1.0", "control_user.invitation_resent": "1.0",
	"control_user.invitation_revoked": "1.0", "control_user.invitation_accepted": "1.0",
	"control_auth.policy_updated": "1.0", "control_auth.provider_login_enabled": "1.0", "control_auth.provider_login_disabled": "1.0",
	"delegation.created": "1.0", "delegation.exchanged": "1.0", "delegation.revoked": "1.0",
	"entitlement.granted": "1.0", "local_entitlement_request.created": "1.0", "local_entitlement_request.approved": "1.0",
	"oauth.consent_revoked": "1.0", "platform93.webhook.test": "1.0", "user.created": "1.0",
	"storage.object.upload_requested": "1.0", "storage.object.ready": "1.0", "storage.object.deleted": "1.0",
	"storage.provider.verified": "1.0", "storage.provider.disabled": "1.0",
	"user.email_verified": "1.0", "user.email_unverified": "1.0", "user.organization_verified": "1.0",
	"user.organization_unverified": "1.0", "user.email_changed": "1.0", "user.password_reset": "1.0",
	"user.pending_deletion": "1.0", "user.anonymized": "1.0", "user.deleted": "1.0",
	"user.suspended": "1.0", "user.restored": "1.0", "workspace.invitation_created": "1.0",
	"workspace.invitation_accepted": "1.0", "workspace.owner_transferred": "1.0",
	"application_invitation.created": "1.0", "application_invitation.resent": "1.0", "application_invitation.revoked": "1.0",
	"application_invitation.accepted": "1.0", "application_invitation.expired": "1.0", "user.updated": "1.0",
	"workspace.created": "1.0", "workspace.updated": "1.0", "workspace.archived": "1.0", "workspace.member_added": "1.0",
	"workspace.member_updated": "1.0", "workspace.member_removed": "1.0", "entitlement.adjusted": "1.0",
	"entitlement.revoked": "1.0", "entitlement.restored": "1.0", "entitlement.expired": "1.0", "entitlement.effective_changed": "1.0",
	"billing.subscription.updated": "1.0", "billing.invoice.updated": "1.0", "billing.payment.updated": "1.0",
	"billing.refund.updated": "1.0", "billing.dispute.updated": "1.0",
}

type Handler func(context.Context, Event) error

// Dispatch routes a known Platform93 event by exact type and sends custom events
// to the optional fallback. It rejects unsupported major contract versions.
func Dispatch(ctx context.Context, event Event, handlers map[string]Handler, custom Handler) (bool, error) {
	if event.IsCustom() {
		if custom == nil {
			return false, nil
		}
		return true, custom(ctx, event)
	}
	if !event.SupportsKnownVersion() {
		return false, fmt.Errorf("unsupported Platform93 event contract %s version %s", event.Type, event.SchemaVersion)
	}
	handler := handlers[event.Type]
	if handler == nil {
		return false, nil
	}
	return true, handler(ctx, event)
}

func (e Event) IsPlatform() bool { return e.ContractSource == "platform93" }
func (e Event) IsCustom() bool   { return e.ContractSource == "application" }

func (e Event) SupportsKnownVersion() bool {
	supported, ok := PlatformEventVersions[e.Type]
	return ok && strings.SplitN(supported, ".", 2)[0] == strings.SplitN(e.SchemaVersion, ".", 2)[0]
}

func DecodeData[T any](event Event) (T, error) {
	var value T
	err := json.Unmarshal(event.Data, &value)
	return value, err
}

func VerifyAndDecode(body []byte, header, secret string, now time.Time, tolerance time.Duration) (Event, error) {
	if err := Verify(body, header, secret, now, tolerance); err != nil {
		return Event{}, err
	}
	var event Event
	if err := json.Unmarshal(body, &event); err != nil {
		return Event{}, fmt.Errorf("webhook envelope rejected: %w", err)
	}
	if event.SpecVersion != "1.0" || event.Type == "" || event.SchemaVersion == "" || (event.ContractSource != "platform93" && event.ContractSource != "application") || len(event.Data) == 0 {
		return Event{}, fmt.Errorf("webhook envelope rejected")
	}
	return event, nil
}

func Verify(body []byte, header, secret string, now time.Time, tolerance time.Duration) error {
	values := map[string]string{}
	for _, part := range strings.Split(header, ",") {
		pair := strings.SplitN(part, "=", 2)
		if len(pair) == 2 {
			values[pair[0]] = pair[1]
		}
	}
	timestamp, err := strconv.ParseInt(values["t"], 10, 64)
	if err != nil || timestamp == 0 || now.Sub(time.Unix(timestamp, 0)) > tolerance || time.Unix(timestamp, 0).Sub(now) > time.Minute {
		return fmt.Errorf("webhook timestamp rejected")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(values["t"] + "."))
	_, _ = mac.Write(body)
	actual, err := hex.DecodeString(values["v1"])
	if err != nil || !hmac.Equal(mac.Sum(nil), actual) {
		return fmt.Errorf("webhook signature rejected")
	}
	return nil
}
