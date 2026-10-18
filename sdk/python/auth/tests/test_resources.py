import json
import time
import unittest
from types import SimpleNamespace
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from platform93_auth import MachineClient, Verifier, capability_scope, protected_resource_metadata, resource_challenge

APP = "01900000-0000-7000-8000-000000000093"
ID = "01900000-0000-7000-8000-000000000094"
RESOURCE = "https://resource.example/api"
ISSUER = "https://issuer.example"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SCOPE = capability_scope(APP, "documents:read")
RESOURCE_FIXTURE = json.loads((Path(__file__).parents[4] / "conformance" / "resource-jwt.json").read_text())


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.verifier = Verifier(ISSUER, RESOURCE, APP)
        self.verifier.jwks = SimpleNamespace(get_signing_key_from_jwt=lambda _: SimpleNamespace(key=KEY.public_key()))
        self.checks = 0
        self.exchanges = 0
        self.decision = {"allowed": True, "reason": "allowed", "user_id": ID, "connection_id": ID}
        self.status = 200
        self.offline = False

        def transport(request):
            if request.url.path == "/oidc/token":
                self.exchanges += 1
                self.assertTrue(request.headers["Authorization"].startswith("Basic "))
                return httpx.Response(200, json={"access_token": "machine", "expires_in": 300})
            self.assertEqual(request.url.path, f"/v1/applications/{APP}/service/resource-access/check")
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.headers["Authorization"], "Bearer machine")
            self.checks += 1
            self.body = json.loads(request.content)
            if self.offline:
                raise httpx.ConnectError("offline")
            return httpx.Response(self.status, content=json.dumps(self.decision), headers={"Content-Type": "application/json"})

        self.http = httpx.Client(transport=httpx.MockTransport(transport))
        self.addCleanup(self.http.close)
        self.machine = MachineClient(base_url=ISSUER, application_id=APP, client_id="backend", client_secret="test", client=self.http)

    def token(self, changes=None, omit=()):
        now = int(time.time())
        claims = {"iss": ISSUER, "exp": now + 300, "iat": now, "nbf": now - 1}
        claims.update(RESOURCE_FIXTURE["claims"])
        claims.update(changes or {})
        for key in omit:
            del claims[key]
        return jwt.encode(claims, KEY, algorithm="RS256", headers={"typ": "JWT", "kid": "primary"})

    def authorize(self, token, workspace_id=None):
        return self.verifier.authorize_resource(token, resource=RESOURCE, capability="documents:read", machine_client=self.machine, workspace_id=workspace_id)

    def test_fresh_machine_check_and_workspace(self):
        token = self.token()
        self.assertEqual(self.authorize(token).values["connection_id"], ID)
        self.authorize(token)
        self.assertEqual((self.checks, self.exchanges), (2, 1))
        self.assertEqual(self.body, {"token": token, "resource": RESOURCE, "capability": "documents:read"})
        self.decision["workspace_id"] = ID
        self.authorize(token, ID)
        self.assertEqual(self.body["workspace_id"], ID)
        self.decision = {"allowed": False, "reason": "revoked"}
        with self.assertRaises(jwt.InvalidTokenError):
            self.authorize(token)

    def test_shared_resource_jwt_conformance(self):
        for case in RESOURCE_FIXTURE["cases"]:
            with self.subTest(name=case["name"]):
                before = self.checks
                accepted = True
                try:
                    self.authorize(self.token(case.get("changes"), case.get("omit", [])))
                except (jwt.InvalidTokenError, ValueError, TypeError):
                    accepted = False
                self.assertEqual(accepted, case["accept"])
                self.assertEqual(self.checks - before, 1 if case["accept"] else 0)

    def test_ordinary_verifier_rejects_resource(self):
        with self.assertRaises(jwt.InvalidTokenError):
            self.verifier.verify(self.token())

    def test_local_rejections_before_live_check(self):
        changes = [
            {"application_id": ID}, {"iss": RESOURCE}, {"aud": RESOURCE + "/other"}, {"aud": [RESOURCE, ISSUER]}, {"aud": [RESOURCE, RESOURCE]},
            {"actor_type": "client"}, {"token_kind": "access"}, {"sid": "bad"}, {"connection_id": "bad"}, {"client_id": ""},
            {"exp": 1}, {"iat": int(time.time()) + 1000}, {"nbf": int(time.time()) + 1000}, {"exp": str(int(time.time()) + 300)},
            {"roles": {"application": ["member"], "workspaces": {}}}, {"roles": {"application": [], "workspaces": {ID: []}}},
            {"workspace_ids": [ID]}, {"workspace_id": ID}, {"act": None}, {"scope": ""}, {"scope": f"{SCOPE} {SCOPE}"},
            {"scope": f"{SCOPE}\t{SCOPE}"}, {"scope": f"/applications/{APP}/*"}, {"scope": f"{SCOPE} admin"}, {"scope": "openid offline_access"},
            {"scope": f"{SCOPE} /applications/{APP}/roles/member"},
            {"scope": f"/applications/{ID}/documents/read"}, {"scope": f"{SCOPE} /applications/{APP}/workspaces/{ID}/read"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises((jwt.InvalidTokenError, ValueError, TypeError)):
                self.authorize(self.token(change))
        for key in ("sub", "sid", "client_id", "connection_id", "scope", "roles", "exp", "iat", "nbf"):
            with self.subTest(missing=key), self.assertRaises((jwt.InvalidTokenError, ValueError)):
                self.authorize(self.token(omit=[key]))
        self.assertEqual(self.checks, 0)

    def test_oversized_token_before_verification(self):
        self.verifier.jwks = None
        with self.assertRaisesRegex(jwt.InvalidTokenError, "16 KiB"):
            self.authorize(self.token({"padding": "a" * (16 * 1024)}))
        self.assertEqual(self.checks, 0)

    def test_malformed_decisions_and_failures_never_authorize(self):
        token = self.token()
        for response in [None, {}, {"allowed": "true", "reason": "ok"}, {"allowed": True}, {"allowed": True, "reason": None},
                         {"allowed": True, "reason": "ok", "user_id": APP}, {"allowed": True, "reason": "ok", "connection_id": None},
                         {"allowed": True, "reason": "ok", "workspace_id": ID}]:
            self.decision = response
            with self.subTest(response=response), self.assertRaises(jwt.InvalidTokenError):
                self.authorize(token)
        self.status = 503
        with self.assertRaises(httpx.HTTPStatusError):
            self.authorize(token)
        self.offline = True
        with self.assertRaises(httpx.ConnectError):
            self.authorize(token)

    def test_signature_and_header_rejected(self):
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claims = jwt.decode(self.token(), options={"verify_signature": False})
        for headers, key in [({"kid": "primary", "typ": "JWT"}, wrong), ({"kid": "primary", "typ": "other"}, KEY), ({"typ": "JWT"}, KEY)]:
            with self.assertRaises(jwt.InvalidTokenError):
                self.authorize(jwt.encode(claims, key, algorithm="RS256", headers=headers))
        self.assertEqual(self.checks, 0)

    def test_metadata_and_challenge(self):
        self.assertEqual(protected_resource_metadata(RESOURCE, ISSUER, APP, ["documents:read", "documents:read"]),
                         {"resource": RESOURCE, "authorization_servers": [ISSUER], "scopes_supported": [SCOPE]})
        self.assertIn('error_description="a\\"b\\\\c"', resource_challenge(RESOURCE, "invalid_token", 'a"b\\c'))
        for uri in ("http://resource.example", "https://user@resource.example", "https://resource.example/#fragment", "https://resource.example/?query=1", "https://resource.example/\n"):
            with self.assertRaises(ValueError):
                protected_resource_metadata(uri, ISSUER, APP, [])
        with self.assertRaises(ValueError):
            resource_challenge(RESOURCE, description="bad\r\nheader")
        for capability in ("*", "a:*", "a::b", "../read", "a%20b", "a b", "roles:member", "workspaces:read"):
            with self.assertRaises(ValueError):
                capability_scope(APP, capability)


if __name__ == "__main__":
    unittest.main()
