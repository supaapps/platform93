# Application authorization

Platform93 authorizes application requests from the JWT `scope` claim. The
structured `roles` claim is for user interfaces and diagnostics; applications
must not authorize from role names alone.

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
