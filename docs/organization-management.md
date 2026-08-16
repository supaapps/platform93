# Organization management and governance

Platform93 can expose an optional machine-only API for installation provisioning systems. It is disabled by default and is independent of Platform user sessions and application OAuth clients.

## Security boundary

- Installation owners or administrators activate the API and create management clients under **Platform -> Control**.
- A management client secret is returned once. Platform93 stores only its keyed digest.
- Clients exchange credentials at `POST /oidc/token` with `grant_type=client_credentials`.
- The resulting JWT uses the installation issuer, the `platform93:control` audience, `actor_type=management_client`, `token_kind=management`, and a five-minute lifetime.
- Management JWTs are accepted only under `/v1/management`. They cannot authenticate the hosted admin, `/v1/control`, or application APIs.
- Every request checks the installation kill switch and client status live. Disabling either immediately invalidates issued tokens.
- Management writes are recorded with `actor_type=management_client`.

```sh
ACCESS_TOKEN="$(curl -fsS -u "$P93_CLIENT_ID:$P93_CLIENT_SECRET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'grant_type=client_credentials&scope=/management/organizations/*' \
  https://platform93.example/oidc/token | jq -r .access_token)"

curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://platform93.example/v1/management/organizations
```

The initial management scope is `/management/organizations/*`. It permits organization lifecycle, application lifecycle, and organization-policy operations. It does not grant installation provider, signing-key, Platform user, audit-export, or recovery access.

## Organization policy

Every organization receives an installation-owned policy. Organization Platform users can read the policy and current usage, but only installation owners/administrators and management clients can update it.

Limits are nullable. `null` means unlimited and `0` prevents creation:

- `max_applications` counts active applications in the organization.
- `max_users` counts non-deleted users across every application in the organization.

Creation checks lock the policy row in the same transaction as the new application or user. Concurrent requests therefore cannot exceed a configured limit.

The policy can disable public registration, password authentication, passwordless authentication, personal API keys, Platform user delegation, organization provider overrides, application provider overrides, custom events, and outgoing webhooks. Existing installations default to all capabilities enabled.

Disabling a capability is immediate. Platform93 also applies these cleanup rules:

- Personal API keys are revoked when personal keys are disabled.
- Delegations and delegated sessions are revoked when delegation is disabled.
- Application webhooks are disabled when webhooks are disabled.
- Restricted application authentication settings are forced off and cannot be re-enabled below the organization boundary.

Policy updates use optimistic concurrency. Read the `ETag` from `GET .../policy` and send it as `If-Match` on `PUT .../policy`.

## Provisioning routes

The machine boundary supports organization lifecycle, application lifecycle, and policy operations under `/v1/management/organizations` as described in the OpenAPI document.

Organizations created through this API intentionally have no synthetic Platform user membership. Provisioning can separately invite or assign real Platform users through the control-plane invitation workflow.
