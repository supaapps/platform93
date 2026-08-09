from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient


@dataclass(frozen=True)
class Claims:
    values: dict[str, Any]

    @property
    def locale(self) -> str:
        return str(self.values.get("locale", ""))

    def has_permission(self, permission: str) -> bool:
        return any(
            value == permission
            or value == "*"
            or (
                value.endswith("/*")
                and (permission == value[:-2] or permission.startswith(value[:-1]))
            )
            for value in self.values.get("scope", "").split()
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
                    "application_id", "token_kind", "actor_type", "scope",
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
            or actor.get("type") != "operator"
            or not isinstance(actor.get("sub"), str)
            or not actor["sub"]
        ):
            raise jwt.InvalidTokenError("Platform93 delegated token actor rejected")
        return Claims(values)
