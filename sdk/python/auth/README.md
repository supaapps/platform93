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
