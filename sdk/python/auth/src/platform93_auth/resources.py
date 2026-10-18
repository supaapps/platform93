import re
import time
from typing import Protocol
from urllib.parse import urlsplit

import jwt

from .resource_models import ResourceAccessCheckRequest, ResourceAccessCheckResponse
from .verifier import Claims, Verifier

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_SEGMENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_PROTOCOL_SCOPES = {"openid", "profile", "email", "offline_access"}


class ResourceCheckClient(Protocol):
    def check_resource_access(self, request: ResourceAccessCheckRequest) -> ResourceAccessCheckResponse: ...


def _uuid(value) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value))


def _https_uri(value: str) -> str:
    if not isinstance(value, str) or any(ord(c) < 33 or ord(c) > 126 or c in '\\"' for c in value):
        raise ValueError("Invalid HTTPS resource URI")
    uri = urlsplit(value)
    if uri.scheme != "https" or not uri.netloc or not uri.hostname or uri.username is not None or uri.password is not None or "#" in value or "?" in value:
        raise ValueError("Invalid HTTPS resource URI")
    return value


def capability_scope(application_id: str, capability: str) -> str:
    if not _uuid(application_id) or not isinstance(capability, str) or len(capability) > 160 or capability.split(":")[0] in {"roles", "workspaces"} or not all(_SEGMENT.fullmatch(part) for part in capability.split(":")):
        raise ValueError("Invalid resource capability")
    return f"/applications/{application_id}/{capability.replace(':', '/')}"


def protected_resource_metadata(resource: str, issuer: str, application_id: str, capabilities: list[str]) -> dict:
    return {"resource": _https_uri(resource), "authorization_servers": [_https_uri(issuer)], "scopes_supported": list(dict.fromkeys(capability_scope(application_id, c) for c in capabilities))}


def resource_challenge(metadata_uri: str, error: str | None = None, description: str | None = None) -> str:
    def quote(value: str) -> str:
        if not isinstance(value, str) or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise ValueError("Invalid challenge value")
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    if error not in (None, "invalid_token", "insufficient_scope"):
        raise ValueError("Invalid challenge error")
    result = "Bearer resource_metadata=" + quote(_https_uri(metadata_uri))
    if error is not None:
        result += ", error=" + quote(error)
    if description is not None:
        result += ", error_description=" + quote(description)
    return result


def authorize_resource(verifier: Verifier, token: str, resource: str, capability: str, machine_client: ResourceCheckClient, workspace_id: str | None = None) -> Claims:
    """Validate locally and perform a fresh machine check; never cache decisions."""
    if not isinstance(token, str) or len(token.encode("utf-8")) > 16 * 1024:
        raise jwt.InvalidTokenError("Resource token exceeds 16 KiB")
    _https_uri(resource)
    expected = capability_scope(verifier.application_id, capability)
    if workspace_id is not None and not _uuid(workspace_id):
        raise ValueError("Invalid workspace ID")
    claims = verifier._verify(token, resource)
    values = claims.values
    roles = values["roles"]
    prefix = f"/applications/{verifier.application_id}/"
    scopes = values["scope"].split(" ")
    if (
        not (values["aud"] == resource or values["aud"] == [resource])
        or not all(type(values.get(key)) is int for key in ("iat", "nbf", "exp"))
        or values["exp"] <= time.time() or values["nbf"] > time.time() or values["iat"] > time.time()
        or not all(_uuid(values.get(key)) for key in ("sub", "sid", "connection_id"))
        or not isinstance(values.get("client_id"), str) or not values["client_id"] or any(ord(c) < 33 or ord(c) > 126 for c in values["client_id"])
        or any(key in values for key in ("act", "workspace_id", "workspace_ids", "workspaces"))
        or roles != {"application": [], "workspaces": {}}
        or expected not in scopes
    ):
        raise jwt.InvalidTokenError("Platform93 resource token rejected")
    for scope in scopes:
        if scope in _PROTOCOL_SCOPES:
            continue
        key = scope.removeprefix(prefix).replace("/", ":")
        if not scope.startswith(prefix) or key.startswith("workspaces:") or capability_scope(verifier.application_id, key) != scope:
            raise jwt.InvalidTokenError("Platform93 resource scope rejected")
    request: ResourceAccessCheckRequest = {"token": token, "resource": resource, "capability": capability}
    if workspace_id is not None:
        request["workspace_id"] = workspace_id
    result = machine_client.check_resource_access(request)
    if not isinstance(result, dict) or result.get("allowed") is not True or not isinstance(result.get("reason"), str):
        raise jwt.InvalidTokenError("Platform93 resource access denied")
    for key, expected_value in (("user_id", values["sub"]), ("connection_id", values["connection_id"]), ("workspace_id", workspace_id)):
        if key in result and (not _uuid(result[key]) or result[key] != expected_value):
            raise jwt.InvalidTokenError("Platform93 resource check context mismatch")
    return claims
