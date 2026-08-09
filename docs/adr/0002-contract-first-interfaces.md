# ADR 0002: Contract-First Public Interfaces

- Status: Accepted
- Date: 2026-08-07

## Decision

OpenAPI 3.1 is the canonical HTTP contract. A deterministic OpenAPI 3.0 projection
feeds strict Go generation until the Go generator supports 3.1 directly. TypeScript
is generated from the canonical document. Events use versioned JSON Schema and a
CloudEvents-compatible envelope. CI rejects invalid schemas, unmatched routes, and
generated drift.

## Consequences

Public behavior is changed in contracts before implementation. SDK convenience
layers may improve ergonomics but may not invent server behavior. RFC 9457 errors,
UUIDv7 identifiers, UTC timestamps, cursor pagination, and snake-case JSON are
shared conventions rather than framework-specific choices.
