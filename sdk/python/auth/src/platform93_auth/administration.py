"""Application administration using the caller's user or scoped machine token."""
from collections.abc import Callable
from typing import Literal, NotRequired, TypedDict, cast
from urllib.parse import quote
import httpx
from .machine import User, UserPage, InvitationInput, Invitation, InvitationPage


class ManagedUserCreate(TypedDict):
    email: str
    reason: str
    first_name: NotRequired[str]
    last_name: NotRequired[str]
    username: NotRequired[str]
    locale: NotRequired[str]
    email_verified: NotRequired[bool]
    is_org_verified: NotRequired[bool]
    custom_attributes: NotRequired[dict[str, object]]


class ManagedUserUpdate(TypedDict):
    reason: str
    first_name: NotRequired[str]
    last_name: NotRequired[str]
    username: NotRequired[str]
    locale: NotRequired[str]


class Role(TypedDict):
    id: str
    key: str
    name: str
    scope: str
    permissions: list[str]


class RoleAssignment(TypedDict):
    id: str
    user_id: str | None
    role_id: str
    workspace_id: str | None


class Session(TypedDict):
    id: str
    user_agent: str | None
    authenticated_at: str
    expires_at: str
    revoked_at: str | None
    amr: list[str]


class RolePage(TypedDict):
    items: list[Role]
    next_cursor: str | None


class RoleAssignmentPage(TypedDict):
    items: list[RoleAssignment]
    next_cursor: str | None
    user_version: int


class SessionPage(TypedDict):
    items: list[Session]
    next_cursor: str | None


class InvitationDelivery(TypedDict):
    id: str
    invitation_url: str
    email_queued: bool
    version: int
    expires_at: str


UserAction = Literal["suspend", "restore", "verify-email", "unverify-email", "verify-organization", "unverify-organization", "sessions/revoke"]


class ApplicationAdministrationClient:
    def __init__(self, base_url: str, application_id: str, access_token: Callable[[], str], *, client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.application_id = application_id
        self.access_token = access_token
        self.client = client or httpx.Client(timeout=30.0)

    def list_users(self, query: str = "", cursor: str = "", limit: int = 20) -> UserPage:
        return cast(UserPage, self._request("GET", "/users", params={"query": query, "cursor": cursor, "limit": str(limit)}))

    def get_user(self, user_id: str) -> User:
        return cast(User, self._request("GET", f"/users/{quote(user_id, safe='')}"))

    def create_user(self, user: ManagedUserCreate, idempotency_key: str) -> User:
        return cast(User, self._request("POST", "/users", dict(user), key=idempotency_key))

    def update_user(self, user_id: str, update: ManagedUserUpdate, etag: str) -> None:
        self._request("PATCH", f"/users/{quote(user_id, safe='')}", dict(update), etag=etag)

    def update_attributes(self, user_id: str, attributes: dict[str, object], reason: str, etag: str) -> None:
        self._request("PATCH", f"/users/{quote(user_id, safe='')}/attributes", {"custom_attributes": attributes, "reason": reason}, etag=etag)

    def change_user_state(self, user_id: str, action: UserAction, reason: str, etag: str, idempotency_key: str) -> None:
        if action not in {"suspend", "restore", "verify-email", "unverify-email", "verify-organization", "unverify-organization", "sessions/revoke"}:
            raise ValueError("Invalid administration action")
        self._request("POST", f"/users/{quote(user_id, safe='')}/{action}", {"reason": reason}, key=idempotency_key, etag=etag)

    def list_sessions(self, user_id: str) -> SessionPage:
        return cast(SessionPage, self._request("GET", f"/users/{quote(user_id, safe='')}/sessions"))

    def list_roles(self) -> RolePage:
        return cast(RolePage, self._request("GET", "/roles"))

    def list_assignments(self, user_id: str) -> RoleAssignmentPage:
        return cast(RoleAssignmentPage, self._request("GET", "/role-assignments", params={"user_id": user_id}))

    def assign_role(self, user_id: str, role_id: str, reason: str, etag: str, idempotency_key: str, workspace_id: str | None = None) -> RoleAssignment:
        data: dict[str, object] = {"user_id": user_id, "role_id": role_id, "reason": reason}
        if workspace_id is not None:
            data["workspace_id"] = workspace_id
        return cast(RoleAssignment, self._request("POST", "/role-assignments", data, key=idempotency_key, etag=etag))

    def remove_role(self, assignment_id: str, reason: str, etag: str) -> None:
        self._request("DELETE", f"/role-assignments/{quote(assignment_id, safe='')}", {"reason": reason}, etag=etag)

    def create_invitation(self, invitation: InvitationInput, idempotency_key: str) -> InvitationDelivery:
        return cast(InvitationDelivery, self._request("POST", "/invitations", dict(invitation), key=idempotency_key))

    def list_invitations(self) -> InvitationPage:
        return cast(InvitationPage, self._request("GET", "/invitations"))

    def get_invitation(self, invitation_id: str) -> Invitation:
        return cast(Invitation, self._request("GET", f"/invitations/{quote(invitation_id, safe='')}"))

    def rotate_invitation(self, invitation_id: str, send_email: bool, reason: str, etag: str, idempotency_key: str) -> InvitationDelivery:
        return cast(InvitationDelivery, self._request("POST", f"/invitations/{quote(invitation_id, safe='')}/rotate", {"send_email": send_email, "reason": reason}, key=idempotency_key, etag=etag))

    def revoke_invitation(self, invitation_id: str, reason: str, etag: str) -> None:
        self._request("DELETE", f"/invitations/{quote(invitation_id, safe='')}", {"reason": reason}, etag=etag)

    def _request(self, method: str, path: str, body: dict[str, object] | None = None, *, key: str | None = None, etag: str | None = None, params: dict[str, str] | None = None) -> dict[str, object]:
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self.access_token()}"}
        if key is not None:
            headers["Idempotency-Key"] = key
        if etag is not None:
            headers["If-Match"] = etag
        response = self.client.request(method, f"{self.base_url}/v1/applications/{quote(self.application_id, safe='')}{path}", json=body, params=params, headers=headers)
        response.raise_for_status()
        return response.json() if response.content else {}
