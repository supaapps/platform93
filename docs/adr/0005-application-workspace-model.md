# ADR 0005: Application And Workspace Identity Model

- Status: Accepted
- Date: 2026-08-07

## Decision

Platform93 uses `installation -> organization -> application -> workspace -> user`.
Applications are the identity and isolation boundary and belong directly to an
organization. A user belongs to exactly one application and may exist without a
workspace. Workspaces are optional application resources; a user can own or join
multiple workspaces, and ownership is stored separately from membership.

The installation has one `/oidc` issuer and signing-key lifecycle. Control tokens
use audience `platform93:control` and actor type `control_user`. Application tokens use
audience `platform93:application:{application_id}` and actor type `user` or `client`.
Every verifier must validate issuer, exact audience, actor type, and application ID.

Platform users are installation-wide identities stored independently from application
users. A Platform user can hold one installation role and multiple organization roles.
Installation roles grant deployment-wide control; organization roles grant control
over every application in that organization. Application user creation never grants
control-plane authority, even when both records use the same email address.

Application access tokens contain all current application and workspace role paths
in the standard `scope` claim. No workspace is selected in a session. APIs identify
workspace context in their path or request body, and ownership-sensitive operations
perform a live database check.

## Consequences

Development, testing, and production are separate applications rather than modes
inside one application. The same email can identify different users in different
applications. Role changes become visible after refresh or the five-minute access
token expires. Deployments must accept large authorization headers when users have
many workspace assignments; Platform93 itself accepts up to 1 MiB of request
headers, while external proxies must be configured separately.
