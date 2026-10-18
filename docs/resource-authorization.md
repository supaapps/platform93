# Resource authorization

Resource authorization is an explicit, application-local opt-in. Set
`internal_config.resource_authorization_enabled` to `true` under application
Settings, Runtime and access policy. The default is `false`. Ordinary application
tokens and their authorization behavior are unchanged.

## Resources and capability maps

In application Identity, OAuth resources, register an audience URI and name.
Resources default to `enabled: true`, `allow_client_metadata: false`,
`client_ids: []`. Add at least one capability before saving. Maintain the explicit allowed OAuth
client identifiers in `client_ids`; these are not client database IDs. There is
no dynamic client registration (DCR). The client metadata flag is not DCR.

Each capability has a relative `key`, display `name`, `context` (`personal` or
`workspace`), and a list of relative permissions. For example:

```json
{
  "uri": "https://resource.example.test",
  "name": "Example resource",
  "enabled": true,
  "allow_client_metadata": false,
  "client_ids": ["example-client"],
  "capabilities": [
    {"key": "documents:read", "name": "Read documents", "context": "workspace", "permissions": ["documents:read"]}
  ]
}
```

An explicit empty permission list (`permissions: []`) is valid for identity-only
applications. It requires only an active application user in personal context,
or current membership in the explicitly selected workspace in workspace context.
No role assignment is automatically required. The application must enforce record
ownership and any record-level authorization itself; identity or membership alone
does not prove access to an individual record.

Relative keys and permissions use colon-separated segments matching
`[a-z0-9][a-z0-9._-]{0,63}`. Wildcards are not allowed; capability keys cannot use
`roles` or `workspaces` as their first segment. The backend is authoritative for
validation, including rejection of `.` and `..` segments.

A resource supports up to 32 capabilities. Consent supports up to 100 selected
workspaces per connection; this does not limit the user's workspace memberships.

Capabilities do not grant underlying permissions. Consent limits the delegated
capabilities and contexts; the live authorization decision remains authoritative.
Token scopes use the canonical application path for each capability: colons in
the relative capability key become slashes. For example, `documents:read` becomes
`/applications/{application_id}/documents/read`. This is the same scope shape as
application scopes, not a new resource-specific scope namespace. The separate
`token_kind` distinguishes resource access.

## Control API and concurrency

All routes below are nested under
`/v1/control/applications/{application_id}/oauth-resources`:

| Route | Methods | Purpose |
| --- | --- | --- |
| collection | GET, POST | List or create resources |
| `/{resource_id}` | GET, PATCH | Inspect or update a resource |
| `/{resource_id}/connections` | GET | List resource connections |
| `/{resource_id}/connections/{connection_id}` | GET, DELETE | Inspect or revoke a connection |

Create requests carry an `Idempotency-Key`. The UI reuses the key when retrying
the same creation payload. Resource PATCH and connection DELETE carry `If-Match`
using the loaded entity version (`"v` plus the hexadecimal version plus `"`).
On a version conflict, reload and review current state rather than blindly
overwriting it. List views support cursor pagination.

Resources expose `id`, `application_id`, `uri`, `name`, `enabled`,
`allow_client_metadata`, `client_ids`, `capabilities`, `version`, `created_at`, and
`updated_at`. Connection inspection exposes `id`, `application_id`, `resource_id`,
`resource_version`, `user_id`, `client_id`, `session_id`, `capabilities`,
`personal_access`, `workspace_ids`, `expires_at`, `revoked_at`, `version`,
`created_at`, and `updated_at`. A non-revoked connection is not proof of current
access: expiration and live authorization still apply.

## Explicit hosted consent

The hosted interaction may include `resource_consent` with a resource summary,
requested capability summaries, available workspaces, and
`personal_access_available`. The `/auth` frontend begins with no selected
capabilities, personal access, or workspaces. Users can reduce the requested
capabilities and choose individual workspaces; personal access requires its own
explicit choice. Selecting a workspace capability requires at least one selected
workspace; selecting a personal capability requires personal access. Cancel and
account switching remain available. Ordinary non-resource consent is unchanged.

The existing hosted approve action adds `approved_capabilities` (relative keys),
`personal_access`, and `workspace_ids`. The frontend submits only selected
capabilities and their selected contexts. It does not infer consent from a
previous login or preselect all access. Server validation remains authoritative.

## Resource token enforcement

Resource audience tokens represent an application user actor (`actor_type: user`) and
carry `token_kind: resource_access`. Verify the intended audience and token kind;
never treat an ordinary application token as resource access merely because its
scope strings have the same canonical shape.

The resource service must perform a live check with its machine credential:

```http
POST /v1/applications/{application_id}/service/resource-access/check
Authorization: Bearer <machine-token-with-resource_access:check>
Content-Type: application/json

{
  "token": "<resource-access-token>",
  "resource": "https://resource.example.test",
  "capability": "documents:read",
  "workspace_id": "<explicitly-selected-workspace-id>"
}
```

The machine permission is `resource_access:check`. Omit `workspace_id` for a
personal-context capability. Check the exact capability and workspace for the
operation, and fail closed when the check denies access or cannot complete.
JWT signature verification never replaces the live check. Do not log bearer
tokens. Resource and connection changes, consent limits, user/session state,
and current permissions must be respected by the server's live decision.

## OAuth requests and lifecycle

The issuer remains `https://platform.example.test/oidc`, with discovery at
`/oidc/.well-known/openid-configuration`. A resource server publishes its own
protected-resource metadata, naming that issuer and its exact registered resource
URI. The backend SDKs provide metadata and authentication-challenge helpers.

Start authorization in the user's browser, using the canonical capability scope:

```text
GET /oidc/authorize
  ?client_id=example-client
  &resource=https%3A%2F%2Fresource.example.test
  &response_type=code
  &redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback
  &scope=%2Fapplications%2FAPPLICATION_UUID%2Fdocuments%2Fread%20offline_access
  &state=CLIENT_GENERATED_RANDOM_STATE
  &code_challenge=CLIENT_GENERATED_S256_CHALLENGE
  &code_challenge_method=S256
```

Configure registered clients with `authorization_ui: hosted` for browser-hosted
login and consent. Published metadata clients use hosted authorization and public
client authentication (`none`). Published identities must be explicitly allowed
on the resource and are never registered through an unrestricted DCR endpoint.
Metadata fetches are size/time bounded, reject redirects and non-public network
targets, and are cached for five minutes. Metadata credentials are not supported.

Administrator-registered clients take precedence, including HTTPS client IDs.
Their registered redirects and confidential-client authentication remain in force.
A disabled registration never falls back to a public metadata identity.

Published metadata clients are resource-only. Their redirect URIs do not become
ordinary application sign-in callbacks, invitation destinations, billing return
URLs, or trusted application CORS origins. Resource login uses the hosted
interaction and returns to the external client only after explicit resource
consent; it never grants an ordinary application session to that client.
Manage published clients through the resource's allowed client identifiers, not
the ordinary OAuth client editor. Internal metadata records cannot be edited,
disabled, assigned roles, or granted direct permissions through normal client
administration; removing a client from the resource blocks its live checks.
Published redirects and grants are stored separately from ordinary clients. The
hosted-flow anchor in the ordinary registry is permanently disabled, has no
redirects, grants, scopes or secret, and is protected by a database constraint.
Older binaries therefore cannot admit it during mixed-version operation or
rollback. Migration rollback retains only these inert anchors, never active
ordinary credentials. Resource connections themselves are removed by rollback.

The callback includes `code`, `state`, and `iss`; validate state and the exact
expected issuer before exchanging the code. Public clients submit:

```text
POST /oidc/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=example-client&code=ONE_TIME_CODE&code_verifier=ORIGINAL_PKCE_VERIFIER&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&resource=https%3A%2F%2Fresource.example.test
```

Confidential clients authenticate with their registered client secret and must
also use PKCE. Refresh requests retain the same `resource` and client binding,
use `grant_type=refresh_token`, and send the latest rotating refresh token.
An optional `scope` may reduce the previous grant, never expand it. Subsequent
refreshes retain that reduction. Refresh-token reuse invalidates the family.
Each exchange and refresh also recomputes effective capability scopes from current
permissions. Temporary permission or workspace-access loss does not change the
private consent ceiling; restored authority can re-enable only previously
consented, non-reduced capabilities. A workspace capability is emitted only when
at least one explicitly selected workspace currently qualifies; every operation
still checks its exact workspace live. If no capability currently qualifies,
only retained protocol scopes may remain; no resource operation is authorized.

Headless consent clients read the resource `version` from the JSON authorization
interaction and submit `resource_version`, JSON-encoded `approved_capabilities`
and `workspace_ids`, and `personal_access=true|false` with their approval. Hosted
consent retains the displayed version server-side. Changed definitions require
restarting consent rather than approving a different permission mapping.

Access tokens last five minutes by default and are limited to 16 KiB. They carry
only approved capabilities, empty roles, and connection identifiers, not every
workspace membership. Connections expire no later than the underlying user
session or 30 days. A new authorization creates an independent connection;
revoke unwanted older connections explicitly.

Application users manage their connections through
`/v1/applications/{application_id}/me/connections` and its `/{connection_id}`
detail/revocation route, authenticated with their normal application user token.
PATs and support-delegation sessions cannot manage these connections. Resource
tokens cannot access those endpoints or ordinary application UserInfo.

Every operation requires a fresh machine-authenticated check. Connection/token
revocation, refresh replay, disabled clients/resources, and current access changes
are enforced there. Checks begun after revocation commits are denied; previously
authorized in-flight work is not retroactively cancelled. Recheck before running
queued work. No positive authorization cache or offline fallback is provided.

Use `createResourceAuthorizer` in TypeScript, `ResourceAuthorizer` in Go,
`Verifier.authorizeResource` in PHP, or the Python resource authorizer rather
than accepting a JWT with an ordinary application verifier. SDK machine clients
acquire their own short-lived service token using client credentials. Never
forward a resource token to an endpoint expecting an application audience.

## Manual Verification Matrix

These are integration verification steps, not a claim of real-host conformance.
Mocked browser tests verify frontend behavior only. Run the matrix against the
deployed backend and a generic resource service before claiming interoperability.

| Scenario | Expected verification |
| --- | --- |
| Default application | Opt-in is off; ordinary login and tokens unchanged |
| Create and retry | Explicit clients/map retained; identical retry is idempotent |
| Concurrent resource edit | Stale `If-Match` rejected; reload shows current version |
| Resource isolation | Another application's resource/connection inaccessible |
| No selection | Approve disabled; no implicit all-capability grant |
| Reduced consent | Only checked capability keys and contexts submitted |
| Personal only | Explicit personal selection, empty workspace list |
| Workspace only | Explicit workspace subset, personal access false |
| Mixed consent | Both contexts explicitly selected; unrelated workspaces excluded |
| Unavailable context | No capability can approve an unavailable context |
| Wrong audience/kind | Live check denies ordinary or wrong-resource tokens |
| Wrong workspace/capability | Live check denies access outside consent |
| Revoked/expired connection | Live check denies; stale revoke version rejected |
| Permissions/session changed | Live check reflects current authorization |
| Identity-only capability | Empty permissions require an active user or selected-workspace membership, not an automatic role; application enforces record ownership |
| Workspace selection limit | Up to 100 selected workspaces per connection, without limiting memberships |
| Check unavailable | Resource operation fails closed |
| Ordinary consent | Existing approve body and identity consent unchanged |
| Desktop/mobile | Capability editor and consent remain usable with keyboard |
