import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from platform93_auth import Verifier


fixture = json.loads((Path(__file__).parents[4] / "conformance" / "jwt.json").read_text())
primary = rsa.generate_private_key(public_exponent=65537, key_size=2048)
wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(primary.public_key()))
public_jwk.update({"kid": "primary", "alg": "RS256", "use": "sig"})


class JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"keys": [public_jwk]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), JWKSHandler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
issuer = f"http://127.0.0.1:{server.server_port}"
verifier = Verifier(issuer, fixture["audience"], fixture["application_id"])


def token_for(mutation: str) -> str:
    now = int(time.time())
    headers = {"alg": "RS256", "typ": "JWT", "kid": "primary"}
    claims = {
        "iss": issuer,
        "sub": "user-1",
        "aud": [fixture["audience"]],
        "exp": now + 300,
        "iat": now,
        "nbf": now - 1,
        "application_id": fixture["application_id"],
        "token_kind": "access",
        "actor_type": "user",
        "scope": "/applications/app/profile/read",
    }
    signing_key = primary
    if mutation == "machine": claims.update(token_kind="machine", actor_type="client")
    elif mutation == "delegated": claims["act"] = {"sub": "operator-1", "type": "operator"}
    elif mutation == "wrong_issuer": claims["iss"] = "https://wrong.example"
    elif mutation == "wrong_audience": claims["aud"] = ["wrong-api"]
    elif mutation == "wrong_application": claims["application_id"] = "01900000-0000-7000-8000-000000000000"
    elif mutation == "expired": claims["exp"] = now - 60
    elif mutation == "future_nbf": claims["nbf"] = now + 300
    elif mutation == "future_iat": claims["iat"] = now + 300
    elif mutation == "missing_sub": claims.pop("sub")
    elif mutation == "missing_application": claims.pop("application_id")
    elif mutation == "missing_token_kind": claims.pop("token_kind")
    elif mutation == "missing_actor_type": claims.pop("actor_type")
    elif mutation == "operator_actor": claims["actor_type"] = "operator"
    elif mutation == "missing_kid": headers.pop("kid")
    elif mutation == "unknown_kid": headers["kid"] = "unknown"
    elif mutation == "wrong_signature": signing_key = wrong
    elif mutation == "delegated_wrong_actor_type": claims["act"] = {"sub": "operator-1", "type": "user"}
    token = jwt.encode(claims, signing_key, algorithm="RS256", headers=headers)
    if mutation == "wrong_algorithm":
        parts = token.split(".")
        parts[0] = base64.urlsafe_b64encode(json.dumps({**headers, "alg": "HS256"}).encode()).rstrip(b"=").decode()
        token = ".".join(parts)
    return token


try:
    for case in fixture["cases"]:
        accepted = True
        try:
            verifier.verify(token_for(case["mutation"]))
        except Exception:
            accepted = False
        assert accepted == case["accept"], case["name"]
finally:
    server.shutdown()
