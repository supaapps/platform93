import hashlib
import hmac
import json
import time
from typing import Any, Literal, TypedDict


class Platform93Event(TypedDict):
    specversion: Literal["1.0"]
    id: str
    source: str
    type: str
    contract_source: Literal["platform93", "application"]
    time: str
    application_id: str
    schema_version: str
    subject: str | None
    actor: dict[str, Any] | None
    correlation_id: str | None
    causation_id: str | None
    data: dict[str, Any]


PLATFORM_EVENT_VERSIONS = dict.fromkeys((
    "organization.created", "organization.retired", "organization.restored",
    "application.created", "application.retired", "application.restored",
    "delegation.created", "delegation.exchanged", "delegation.revoked",
    "entitlement.granted", "local_entitlement_request.created", "local_entitlement_request.approved",
    "oauth.consent_revoked", "platform93.webhook.test", "user.created",
    "user.email_verified", "user.email_unverified", "user.organization_verified",
    "user.organization_unverified", "user.email_changed", "user.password_reset",
    "user.pending_deletion", "user.anonymized", "user.deleted", "user.suspended", "user.restored",
    "workspace.invitation_created", "workspace.invitation_accepted", "workspace.owner_transferred",
), "1.0")


def verify_webhook(
    raw_body: bytes,
    header: str,
    secret: str,
    tolerance_seconds: int = 300,
    now: float | None = None,
) -> Platform93Event:
    values: dict[str, list[str]] = {}
    for part in header.split(","):
        if "=" in part:
            key, value = part.split("=", 1)
            values.setdefault(key, []).append(value)
    timestamp = int(values.get("t", ["0"])[0])
    current = time.time() if now is None else now
    if not timestamp or abs(current - timestamp) > tolerance_seconds:
        raise ValueError("Platform93 webhook timestamp rejected")
    expected = hmac.new(
        secret.encode(), str(timestamp).encode() + b"." + raw_body, hashlib.sha256
    ).hexdigest()
    if not any(
        hmac.compare_digest(expected, signature) for signature in values.get("v1", [])
    ):
        raise ValueError("Platform93 webhook signature rejected")
    event = json.loads(raw_body)
    if (
        event.get("specversion") != "1.0"
        or not isinstance(event.get("type"), str)
        or event.get("contract_source") not in ("platform93", "application")
        or not isinstance(event.get("schema_version"), str)
        or not isinstance(event.get("data"), dict)
    ):
        raise ValueError("Platform93 webhook envelope rejected")
    return event


def is_platform_event(event: Platform93Event) -> bool:
    return event["contract_source"] == "platform93" and event["type"] in PLATFORM_EVENT_VERSIONS


def is_custom_event(event: Platform93Event) -> bool:
    return event["contract_source"] == "application"


def assert_supported_platform_event(event: Platform93Event) -> None:
    if not is_platform_event(event):
        raise ValueError("Unknown Platform93 event contract")
    supported = PLATFORM_EVENT_VERSIONS[event["type"]]
    if event["schema_version"].split(".", 1)[0] != supported.split(".", 1)[0]:
        raise ValueError("Unsupported Platform93 event schema version")
