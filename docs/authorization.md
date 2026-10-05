# Application authorization

Platform93 authorizes application requests from the JWT `scope` claim. The
structured `roles` claim is for user interfaces and diagnostics; applications
must not authorize from role names alone.

## New users and zero-permission tokens

Authentication does not automatically grant application permissions. Public
registration, including social registration, creates an application identity;
it does not assign a default role, create a workspace, or join an existing one.
A user can exist without a workspace.

The zero-permission application access-token contract is:

```json
{
  "actor_type": "user",
  "token_kind": "access",
  "scope": "",
  "roles": {
    "application": [],
    "workspaces": {}
  }
}
```

This is a claim excerpt, not a complete JWT. Normal issuer, audience,
application ID, session, subject, and expiry validation still applies. An empty
scope means no role markers or permission paths, not an invalid identity and
never unrestricted access. Permission-protected operations must deny access
unless their required scope is granted. Identity-bound self-service operations
can remain available according to their endpoint rules, including creating a
workspace as its owner.

The `scope` field must be present as a string, including when empty; do not
substitute `null`, a list, or a default wildcard. OAuth protocol scopes such as
`openid`, `profile`, and `email` do not grant application permissions.

## Default-role onboarding

There is currently no application setting that automatically assigns a role to
every newly registered user. A role named `member` or `default` has no special
behavior. Implement the desired onboarding policy explicitly:

1. In the application's **Roles** view, create an application-scoped role with
   the minimum required relative permissions. For example, `member` with
   `documents:read`.
2. Create or register the application user, then obtain their user ID from a
   verified session or administrative user record. Never trust a user-supplied
   ID as proof of identity.
3. In **Role assignments**, assign that role to the user without a workspace ID.
   The equivalent control API calls are shown below. These require an authorized
   Platform user, not the new user's token or a browser-held administrative secret.
4. Refresh the user's access token after assignment, or sign in again. Existing
   access tokens retain their earlier scopes until refreshed or expired.

```http
POST /v1/control/applications/{application_id}/roles
Content-Type: application/json

{"key":"member","name":"Member","scope":"application","permissions":["documents:read"]}
```

Use the returned role `id` in the assignment:

```http
POST /v1/control/applications/{application_id}/role-assignments
Content-Type: application/json

{"user_id":"{user_id}","role_id":"{role_id}"}
```

The refreshed token contains both the role marker
`/applications/{application_id}/roles/member` and the expanded permission
`/applications/{application_id}/documents/read`. Authorize against the permission,
not the role's display name. Application invitations can instead carry
`application_role_keys` and apply those roles atomically during acceptance.
Public registration alone does not perform that invitation assignment.

## Workspace onboarding

Workspace context is explicit in API paths and request bodies. Tokens contain
access to all assigned workspaces; there is no selected or implicit default
workspace claim. The consuming application may choose which workspace to show
in its UI, but must not treat that selection as authorization.

For a new personal workspace, the authenticated application user calls:

```http
POST /v1/applications/{application_id}/me/workspaces
Content-Type: application/json

{"key":"personal","name":"My workspace","metadata":{}}
```

Choose a key unique within the application; `personal` above is only an example.
The server binds ownership to the authenticated user. After refresh, the owner
receives `/applications/{application_id}/workspaces/{workspace_id}/*`. Owners are
not members and do not need a workspace membership role. Ownership transfer
still requires a live ownership check; the wildcard does not prove ownership.

For an existing workspace, invite the user with `workspace_role_keys`, or have
an authorized Platform user assign a workspace-scoped role using the control
role-assignment API with `workspace_id`. That assignment creates membership for
a non-owner user. Invitation acceptance applies membership and roles together.
User-driven invitations require `user_invitations_enabled`; administrative
invitations remain separate. Never place every registered user into a shared
workspace unless that is the application's explicit access policy.

## Permission keys

Role definitions, direct grants, delegation requests, and permission checks use
relative permission keys. A key is one or more lowercase ASCII segments joined
by `:`, for example `invoices:read`, `members:42:read`, or `members:42:*`.

Each segment starts with a lowercase letter or digit and may then contain
lowercase letters, digits, `.`, `_`, or `-`. `*` is valid only as the complete
final segment. A key is at most 160 characters. Whitespace, Unicode, `%`, path
separators, empty segments, traversal segments, and embedded wildcards are
rejected rather than escaped or normalized.

API callers never submit complete `/applications/...` paths. Platform93 combines
validated permission keys with trusted application and optional workspace UUIDs:

```text
invoices:read
-> /applications/{application_id}/invoices/read

members:42:*
-> /applications/{application_id}/workspaces/{workspace_id}/members/42/*
```

Wildcards match only complete path boundaries. A grant ending in `/*` does not
match a similarly prefixed sibling resource or another workspace.

## Roles and direct scopes

Roles are reusable application- or workspace-scoped permission sets. Direct
grants are immutable, additive assignments to one user or machine client and
are intended for dynamic resource-specific access. Revocation records who
revoked the grant and when; it does not mutate the original grant definition.

Workspace ownership is never represented by a grant. It remains a live database
fact and contributes the workspace owner wildcard only while ownership is active.
Invitations assign roles, not direct grants.

Tokens contain the sorted, deduplicated union of role markers, expanded role
permissions, active direct grants, and current workspace-owner wildcards. PATs
can only reduce the user's current effective scopes. Delegated tokens contain
only their validated reduction and expose empty structured roles.

## Verification

Use a Platform93 server SDK verifier. Verifiers require RS256, the installation
issuer, exact application audience and ID, a valid actor/token-kind pair, and
canonical authorization claims. A malformed, duplicated, cross-application, or
whitespace-injected scope invalidates the whole JWT.

Applications with many workspace assignments can produce large JWTs. Configure
ingress proxies and application servers to accept the required Authorization
header size; do not truncate the header or parse only a prefix.
