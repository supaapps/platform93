from functools import wraps

from flask import g, jsonify, request

from .verifier import Verifier


def require_platform93(verifier: Verifier):
    def decorator(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            if not authorization.lower().startswith("bearer "):
                return jsonify(detail="Bearer token required"), 401
            try:
                g.platform93_claims = verifier.verify(authorization[7:].strip())
            except Exception:
                return jsonify(detail="Invalid bearer token"), 401
            return function(*args, **kwargs)

        return wrapped

    return decorator
