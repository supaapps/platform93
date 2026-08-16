from __future__ import annotations

import threading
import time
from typing import NotRequired, TypedDict, cast
from urllib.parse import quote

import httpx


JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


class NotificationInput(TypedDict):
    template_key: str
    user_id: NotRequired[str]
    recipient: NotRequired[str]
    locale: NotRequired[str]
    variables: NotRequired[dict[str, JsonValue]]


class QueuedNotification(TypedDict):
    id: str
    status: str
    requested_locale: str
    resolved_locale: str
    fallback_used: bool


class InvitationInput(TypedDict):
    email: str
    workspace_id: NotRequired[str]
    application_role_keys: NotRequired[list[str]]
    workspace_role_keys: NotRequired[list[str]]
    expires_in: NotRequired[int]


class Invitation(TypedDict):
    id: str
    email: str
    workspace_id: str | None
    application_role_keys: list[str]
    workspace_role_keys: list[str]
    status: str
    expires_at: str


class InvitationPage(TypedDict):
    items: list[Invitation]
    next_cursor: str | None


class InvitationResent(TypedDict):
    id: str
    last_sent_at: str
    resend_available_at: str
    expires_at: str


class User(TypedDict):
    id: str
    application_id: str
    email: str
    first_name: str
    last_name: str
    username: str | None
    locale: str
    email_verified: bool
    is_org_verified: bool
    status: str
    custom_attributes: dict[str, JsonValue]
    version: int


class UserPage(TypedDict):
    items: list[User]
    next_cursor: str | None


class Workspace(TypedDict):
    id: str
    application_id: str
    owner_user_id: str
    key: str
    name: str
    metadata: dict[str, JsonValue]
    status: str
    version: int
    created_at: str
    updated_at: str


class WorkspacePage(TypedDict):
    items: list[Workspace]
    next_cursor: str | None


class WorkspaceAccess(TypedDict):
    type: str
    workspace_id: str
    user_id: str | None
    email: str | None
    role_keys: list[str]
    invitation_id: str | None
    status: str
    expires_at: str | None


class WorkspaceAccessPage(TypedDict):
    items: list[WorkspaceAccess]
    next_cursor: str | None


class EntitlementGrant(TypedDict):
    id: str
    subject_type: str
    subject_id: str
    source_type: str
    feature_values: dict[str, JsonValue]
    configuration: dict[str, JsonValue]
    starts_at: str
    expires_at: str | None
    external_reference: str | None


class EntitlementPage(TypedDict):
    items: list[EntitlementGrant]
    next_cursor: str | None


class BillingProfile(TypedDict):
    id: str
    subject_type: str
    subject_id: str
    name: str | None
    email: str | None
    tax_id: str | None
    version: int


class Subscription(TypedDict):
    id: str
    subject_type: str
    subject_id: str
    price_id: str
    provider_id: str
    status: str
    external_reference: str | None


class BillingSummary(TypedDict):
    subject_type: str
    subject_id: str
    billing_profile: BillingProfile | None
    subscriptions: list[Subscription]


class CustomEventInput(TypedDict):
    type: str
    subject: str
    data: dict[str, JsonValue]
    correlation_id: NotRequired[str]
    causation_id: NotRequired[str]


class PublishedEvent(TypedDict):
    id: str
    specversion: str
    source: str
    type: str
    subject: str
    schema_version: str
    data: dict[str, JsonValue]


class MachineClient:
    """Server-only Platform93 client with cached OAuth client credentials."""

    def __init__(
        self,
        *,
        base_url: str,
        application_id: str,
        client_id: str,
        client_secret: str,
        scopes: list[str] | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        if not all((base_url, application_id, client_id, client_secret)):
            raise ValueError("Platform93 machine client requires base_url, application_id, client_id, and client_secret")
        self.base_url = base_url.rstrip("/")
        self.application_id = application_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes or []
        self.client = client or httpx.Client(timeout=30.0)
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def update_secret(self, secret: str) -> None:
        if not secret:
            raise ValueError("Platform93 machine client secret is required")
        with self._lock:
            self.client_secret = secret
            self._token = None
            self._expires_at = 0.0

    def send_notification(self, notification: NotificationInput, idempotency_key: str) -> QueuedNotification:
        return cast(QueuedNotification, self._request("POST", "/notifications", notification, idempotency_key))

    def create_invitation(self, invitation: InvitationInput) -> Invitation:
        return cast(Invitation, self._request("POST", "/invitations", invitation))

    def list_invitations(self) -> InvitationPage:
        return cast(InvitationPage, self._request("GET", "/invitations"))

    def get_invitation(self, invitation_id: str) -> Invitation:
        return cast(Invitation, self._request("GET", f"/invitations/{quote(invitation_id, safe='')}"))

    def resend_invitation(self, invitation_id: str) -> InvitationResent:
        return cast(InvitationResent, self._request("POST", f"/invitations/{quote(invitation_id, safe='')}/resend"))

    def revoke_invitation(self, invitation_id: str) -> None:
        self._request("DELETE", f"/invitations/{quote(invitation_id, safe='')}")

    def list_users(self) -> UserPage:
        return cast(UserPage, self._request("GET", "/users"))

    def get_user(self, user_id: str) -> User:
        return cast(User, self._request("GET", f"/users/{quote(user_id, safe='')}"))

    def list_workspaces(self) -> WorkspacePage:
        return cast(WorkspacePage, self._request("GET", "/workspaces"))

    def get_workspace(self, workspace_id: str) -> Workspace:
        return cast(Workspace, self._request("GET", f"/service/workspaces/{quote(workspace_id, safe='')}"))

    def get_workspace_access(self, workspace_id: str) -> WorkspaceAccessPage:
        return cast(WorkspaceAccessPage, self._request("GET", f"/service/workspaces/{quote(workspace_id, safe='')}/access"))

    def get_entitlements(self, subject_type: str, subject_id: str) -> EntitlementPage:
        return cast(EntitlementPage, self._request("GET", f"/subjects/{self._subject(subject_type, subject_id)}/entitlements"))

    def get_billing(self, subject_type: str, subject_id: str) -> BillingSummary:
        return cast(BillingSummary, self._request("GET", f"/subjects/{self._subject(subject_type, subject_id)}/billing"))

    def publish_event(self, event: CustomEventInput, idempotency_key: str) -> PublishedEvent:
        return cast(PublishedEvent, self._request("POST", "/events", event, idempotency_key))

    def _subject(self, subject_type: str, subject_id: str) -> str:
        if subject_type not in {"user", "workspace"}:
            raise ValueError("Platform93 subject type must be user or workspace")
        return f"{subject_type}/{quote(subject_id, safe='')}"

    def _access_token(self) -> str:
        with self._lock:
            if self._token and time.time() < self._expires_at - 30:
                return self._token
            data = {"grant_type": "client_credentials"}
            if self.scopes:
                data["scope"] = " ".join(self.scopes)
            response = self.client.post(
                f"{self.base_url}/oidc/token",
                data=data,
                auth=(self.client_id, self.client_secret),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
            token = payload.get("access_token")
            if not isinstance(token, str) or not token:
                raise RuntimeError("Platform93 token response did not contain an access token")
            self._token = token
            self._expires_at = time.time() + max(1, int(payload.get("expires_in", 300)))
            return token

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, object]:
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self._access_token()}"}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        response = self.client.request(
            method,
            f"{self.base_url}/v1/applications/{quote(self.application_id, safe='')}{path}",
            json=body,
            headers=headers,
        )
        response.raise_for_status()
        return response.json() if response.content else {}
