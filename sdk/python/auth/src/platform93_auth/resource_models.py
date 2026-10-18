from typing import Literal, NotRequired, TypedDict


class ResourceCapability(TypedDict):
    key: str
    name: str
    context: Literal["personal", "workspace"]
    permissions: list[str]


class OAuthResource(TypedDict):
    id: str
    application_id: str
    uri: str
    name: str
    enabled: bool
    allow_client_metadata: bool
    client_ids: list[str]
    capabilities: list[ResourceCapability]
    version: int
    created_at: str
    updated_at: str


class OAuthConnection(TypedDict):
    id: str
    application_id: str
    resource_id: str
    resource_version: int
    user_id: str
    client_id: str
    session_id: str
    capabilities: list[str]
    personal_access: bool
    workspace_ids: list[str]
    expires_at: str
    revoked_at: str | None
    version: int
    created_at: str
    updated_at: str


class ResourceAccessCheckRequest(TypedDict):
    token: str
    resource: str
    capability: str
    workspace_id: NotRequired[str]


class ResourceAccessCheckResponse(TypedDict):
    allowed: bool
    reason: str
    user_id: NotRequired[str]
    connection_id: NotRequired[str]
    workspace_id: NotRequired[str]
