# ADR 0003: One Synchronized Release Train

- Status: Accepted
- Date: 2026-08-07

## Decision

One `vX.Y.Z` tag versions the CLI, OCI image, Helm OCI chart, OpenAPI and event
artifacts, all npm packages, both Python distributions, and the Composer package.
Tag publication is blocked on a shared verification job. Registries use trusted or
keyless publishing where supported, and images include SBOM and provenance metadata.

## Consequences

Components do not drift across independent versions. A failed verification prevents
all publication, but a registry outage can still produce a partial external release;
reruns must be idempotent and maintainers must verify every registry before announcing
the release.
