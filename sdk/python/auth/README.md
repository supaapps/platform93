# supaapps-platform93-auth

Strict Platform93 JWT verification plus a backend-only `MachineClient`. The machine
client uses OAuth client credentials and provides notification, invitation, user,
workspace, entitlement, billing-summary, and custom-event methods. Keep its client
secret in backend secret storage and never expose it to browser code.

Strict server-side verification for Platform93 application JWTs, including issuer,
audience, actor type, application boundary, expiry, and JWKS rotation checks.

```bash
pip install supaapps-platform93-auth
```

Framework adapters are available through the `fastapi`, `django`, and `flask` extras.
See the [Platform93 repository](https://github.com/supaapps/platform93) for contracts
and integration documentation.

## Protected Resources

Ordinary `Verifier.verify` rejects resource tokens. Resource backends use
`verifier.authorize_resource(token, resource="https://resource.example/api",
capability="documents:read", machine_client=machine_client, workspace_id=workspace_id)`.
Omit `workspace_id` for personal access. The machine client needs the application's
`resource_access:check` permission. The helper verifies locally and performs a
fresh live check on every call; denial, malformed decisions, and service failures
raise rather than falling back to offline authorization.

`protected_resource_metadata(resource, issuer, application_id, capabilities)` builds
discovery metadata; `resource_challenge(metadata_uri, error=None, description=None)`
builds a validated and escaped `WWW-Authenticate` value. No authorization decisions
are cached. Resource JWTs are limited to 16 KiB.
