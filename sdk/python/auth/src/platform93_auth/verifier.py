from dataclasses import dataclass
import re
from typing import Any

import jwt
from jwt import PyJWKClient


@dataclass(frozen=True)
class Claims:
    values: dict[str, Any]

    @property
    def locale(self) -> str:
        return str(self.values.get("locale", ""))

    @property
    def custom_claims(self) -> dict[str, Any]:
        value = self.values.get("custom_claims", {})
        return value if isinstance(value, dict) else {}

    @property
    def roles(self) -> dict[str, Any]:
        return self.values["roles"]

    def has_permission(self, permission: str) -> bool:
        if not _valid_absolute_permission(permission):
            return False
        return any(
            value == permission
            or (
                value.endswith("/*")
                and (permission == value[:-2] or permission.startswith(value[:-1]))
            )
            for value in self.values.get("scope", "").split(" ")
            if _valid_absolute_permission(value)
        )


class Verifier:
    def __init__(self, issuer: str, audience: str, application_id: str):
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.application_id = application_id
        self.jwks = PyJWKClient(
            f"{self.issuer}/jwks.json", cache_jwk_set=True, lifespan=300
        )

    def verify(self, token: str) -> Claims:
        header = jwt.get_unverified_header(token)
        if (
            header.get("alg") != "RS256"
            or header.get("typ") != "JWT"
            or not isinstance(header.get("kid"), str)
            or not header["kid"]
        ):
            raise jwt.InvalidTokenError("Platform93 token algorithm rejected")
        key = self.jwks.get_signing_key_from_jwt(token)
        values = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.issuer,
            options={
                "require": [
                    "exp", "iat", "nbf", "iss", "sub", "aud",
                    "application_id", "token_kind", "actor_type", "scope", "roles",
                ]
            },
        )
        if (
            not isinstance(values.get("sub"), str)
            or not values["sub"]
            or values.get("application_id") != self.application_id
            or not (
                values.get("token_kind") == "access"
                and values.get("actor_type") == "user"
                or values.get("token_kind") == "machine"
                and values.get("actor_type") == "client"
            )
            or not isinstance(values.get("scope"), str)
        ):
            raise jwt.InvalidTokenError("Platform93 token context rejected")
        actor = values.get("act")
        if actor is not None and (
            values["token_kind"] != "access"
            or not isinstance(actor, dict)
            or actor.get("type") != "control_user"
            or not isinstance(actor.get("sub"), str)
            or not actor["sub"]
        ):
            raise jwt.InvalidTokenError("Platform93 delegated token actor rejected")
        if not _valid_scope_claim(values["scope"], self.application_id) or not _valid_roles_claim(values.get("roles")):
            raise jwt.InvalidTokenError("Platform93 token authorization claims rejected")
        if actor is not None and (values["roles"]["application"] or values["roles"]["workspaces"]):
            raise jwt.InvalidTokenError("Platform93 delegated token roles rejected")
        return Claims(values)


def _valid_scope_claim(scope: Any, application_id: str) -> bool:
    if not isinstance(scope, str):
        return False
    if scope == "":
        return True
    if scope != scope.strip() or any(value in scope for value in ("\t", "\r", "\n", "  ")):
        return False
    values = scope.split(" ")
    if len(values) != len(set(values)):
        return False
    prefix = f"/applications/{application_id}/"
    return all(value in _PROTOCOL_SCOPES or value.startswith(prefix) and _valid_absolute_permission(value) for value in values)


def _valid_absolute_permission(value: str) -> bool:
    if not isinstance(value, str) or not value.startswith("/") or any(character in value for character in " :\\%\t\r\n"):
        return False
    segments = value[1:].split("/")
    return len(segments) >= 3 and all(
        index == len(segments) - 1 if segment == "*" else bool(_SEGMENT.fullmatch(segment))
        for index, segment in enumerate(segments)
    )


def _valid_roles_claim(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"application", "workspaces"}:
        return False
    application, workspaces = value["application"], value["workspaces"]
    if not isinstance(application, list) or not isinstance(workspaces, dict) or not _unique_roles(application):
        return False
    return all(
        bool(_WORKSPACE_KEY.fullmatch(workspace_id)) and isinstance(roles, list) and _unique_roles(roles)
        for workspace_id, roles in workspaces.items()
    )


def _unique_roles(values: list[Any]) -> bool:
    if not all(isinstance(value, str) and _ROLE_KEY.fullmatch(value) for value in values):
        return False
    return len(values) == len(set(values))

_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ROLE_KEY = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")
_WORKSPACE_KEY = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_PROTOCOL_SCOPES = {"openid", "profile", "email", "offline_access"}
