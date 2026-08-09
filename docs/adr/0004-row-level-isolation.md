# ADR 0004: Enforced Row-Level Isolation Before 1.0

- Status: Accepted
- Date: 2026-08-07

## Decision

Application middleware and application-scoped SQL are necessary but not sufficient
for the stable release. Platform93 must run with a non-owner PostgreSQL role and
enforce application isolation through row-level security using request-scoped
database context before `v1.0.0`.

## Consequences

The current prerelease cannot be described as RLS-backed or production 1.0. The RLS
work must include pool-safe context reset, background-job context, installation-level
operations, migration ownership, and negative cross-application tests. Enabling
policies without those controls would create either bypasses or production outages.
