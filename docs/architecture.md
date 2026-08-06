# Architecture Principles

Platform93 is being designed as a modular monolith backed by PostgreSQL.

## Boundaries

- Installation operators administer owner organizations, projects, and environments.
- Application users authenticate inside one environment.
- Application tenants model an application's organizations, workspaces, teams, or accounts.
- Operator and application-user tokens are never interchangeable.
- Environments isolate identities, credentials, products, billing, entitlements, events, and data.

## Runtime

One immutable image is intended to expose API, worker, dispatcher, migration,
diagnostic, and version commands. Deployments can run these commands in separate
containers and scale them independently.

## Asynchronous Work

Domain changes and outbox events commit atomically in PostgreSQL. Background work
is at-least-once, idempotent, observable, and safe to resume after process failure.

## Contracts

HTTP APIs use OpenAPI. Event payloads use versioned JSON Schema. SDKs are generated
from those contracts and may add ergonomic helpers without inventing behavior.

## Self-hosting

The open-source system must operate without a hosted control plane. PostgreSQL is
the only required data service in the initial architecture. Additional brokers or
orchestrators may be supported later but will not become hidden requirements.
