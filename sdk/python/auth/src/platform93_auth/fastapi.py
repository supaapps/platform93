from typing import Annotated

from fastapi import Header, HTTPException

from .verifier import Claims, Verifier


def bearer_dependency(verifier: Verifier):
    def verify(authorization: Annotated[str | None, Header()] = None) -> Claims:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required")
        try:
            return verifier.verify(authorization[7:].strip())
        except Exception as error:
            raise HTTPException(status_code=401, detail="Invalid bearer token") from error

    return verify
