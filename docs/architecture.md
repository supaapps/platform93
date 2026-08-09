# Architecture Principles

Formal decisions and their consequences are tracked in the
[ADR index](adr/README.md).

Platform93 is being designed as a modular monolith backed by PostgreSQL.

## Boundaries

- The hierarchy is installation, organization, application, workspace, and user.
- Installation operators administer organizations and their applications. There are
  no application-level operator memberships.
- Control-plane identities are called operators, not users. An operator may have an
  installation role, one or more organization memberships, or both. Installation
  roles are `owner`, `admin`, and `auditor`; organization roles are `owner`, `admin`,
  `auditor`, and `member`.
- Installation owners and admins add installation operators directly. Organization
  owners and admins issue one-time organization invitations; accepting an invitation
  creates or reuses the operator identity, adds the membership, and starts a control
  session. This acceptance flow works without SMTP when the credential is shared out
  of band.
- Operators sign in with email codes or magic links and may add an Argon2id password
  after a recent email-authenticated session. Password changes revoke every other
  operator session. External operator identities require a dedicated control-plane
  linking flow and never inherit application-user login providers implicitly.
- A user belongs to exactly one application, can exist without a workspace, and can
  own or join multiple workspaces.
- Workspaces are optional for consuming applications and can model teams, customer
  accounts, or other shared billing and authorization subjects.
- One installation issuer signs all JWTs. Exact audience and `actor_type` checks keep
  operator, user, and machine-client tokens non-interchangeable.
- Applications isolate identities, credentials, products, billing, entitlements, events, and data.
- Operator middleware resolves application ownership through the organization
  membership before any application administration handler runs. Read-only operator
  roles cannot perform mutations.
- PostgreSQL RLS is a required pre-1.0 defense-in-depth layer and is not yet enabled;
  the current runtime must not be represented as RLS-backed.

## Token And Workspace Context

- Control JWTs use audience `platform93:control`. Application JWTs use audience
  `platform93:application:{application_id}` and include that exact `application_id`.
- Application and workspace role markers plus expanded permission paths are emitted
  in the standard space-delimited `scope` claim and recomputed at login and refresh.
- Access JWTs expire after five minutes. Permission changes do not require live checks
  on ordinary requests and therefore take effect at refresh or expiry.
- A token never contains a selected workspace. Workspace context is explicit in a
  route or request body; ownership transfer additionally requires live ownership and
  recent-auth checks.
- Platform93 accepts request headers up to 1 MiB. Reverse proxies must support the
  largest expected JWT. For ingress-nginx, configure `large-client-header-buffers` in
  the controller ConfigMap; this is not a safe per-Ingress annotation.

## Runtime

One immutable image is intended to expose API, worker, dispatcher, migration,
diagnostic, and version commands. Deployments can run these commands in separate
containers and scale them independently.

API pods expose health, readiness, and Prometheus metrics on port 8093. Worker and
dispatcher pods expose health and Prometheus metrics on port 9090. All process modes
consume the same migration history and use cooperative signal cancellation.

## Asynchronous Work

Domain changes and outbox events commit atomically in PostgreSQL. Background work
is at-least-once, idempotent, observable, and safe to resume after process failure.
River owns durable scheduled work. Outbox dispatch and delivery rows use PostgreSQL
`FOR UPDATE SKIP LOCKED` leases so multiple workers can make progress without a broker.

## Distribution

One synchronized `vX.Y.Z` tag versions the CLI, OCI image, Helm chart, npm packages,
Python packages, Composer package, OpenAPI contract, and event schemas. Release jobs
use OIDC trusted publishing where registries support it and emit provenance, SBOMs,
checksums, and a keyless OCI signature.

## Contracts

HTTP APIs use OpenAPI. Event payloads use versioned JSON Schema. SDKs are generated
from those contracts and may add ergonomic helpers without inventing behavior.
OpenAPI 3.1 is canonical. Until stable `oapi-codegen` supports 3.1, a deterministic
3.0.3 projection is generated solely for strict Go server/model generation; CI
fails if either projection or generated code drifts.

## Self-hosting

The open-source system must operate without a hosted control plane. PostgreSQL is
the only required data service in the initial architecture. Additional brokers or
orchestrators may be supported later but will not become hidden requirements.
