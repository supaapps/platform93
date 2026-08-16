# v0.1.0 Security Review Record

This record describes automated release-hardening evidence. It is not an independent
security audit and does not replace the broader review required before `v1.0.0`.

## Required gates

- Gitleaks scans full Git history and the release worktree with redaction enabled.
- CodeQL analyzes Go and TypeScript on pull requests, `main`, and release tags.
- Dependency Review rejects high or critical additions and disallowed AGPL licenses.
- `govulncheck` runs with Go `1.25.13`, matching the pinned release builder.
- pnpm, Composer, project-isolated Python dependencies, Trivy filesystem/configuration,
  and the final tagged multi-architecture image reject high or critical findings.
- Actor/audience boundaries, origin checks, permission grammar, IDOR isolation, provider
  SSRF controls, webhook signatures, idempotency, and entitlement grant uniqueness have
  negative tests in the PostgreSQL or conformance suites.

## Accepted finding

`govulncheck` reports `GO-2026-5932` at module level because the dependency graph contains
`golang.org/x/crypto/openpgp`. Platform93 does not import or call `openpgp`; symbol and
package analysis both report zero reachable vulnerabilities. The advisory has no fixed
module version. This transitive, unreachable finding is accepted for `v0.1.0` and must be
reviewed on every dependency update. Any reachable finding fails the release.

Provider smoke-test results are recorded separately using the redacted checklist in
[Release Process](releasing.md). No credentials, account identifiers, tokens, email
addresses, or provider payloads belong in this repository or a GitHub release.
