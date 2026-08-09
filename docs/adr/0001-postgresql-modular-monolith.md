# ADR 0001: PostgreSQL Modular Monolith

- Status: Accepted
- Date: 2026-08-07

## Decision

Platform93 is a Go modular monolith. PostgreSQL 16 or newer is its only mandatory
production service and provides transactional state, River jobs, outbox leasing,
idempotency, and coordination. One rootless image exposes independently scalable
API, worker, dispatcher, migration, diagnostic, bootstrap, and recovery commands.

## Consequences

Domain boundaries remain explicit Go packages but deploy atomically. Redis and
message brokers may be optional integrations later and cannot become hidden runtime
requirements. Cross-module state changes can use one PostgreSQL transaction.
