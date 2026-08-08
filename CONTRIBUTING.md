# Contributing

Platform93 is at an early design stage. Contract and architecture changes should
be discussed before substantial implementation.

## Expectations

- Keep changes focused and include tests.
- Use conventional commits.
- Update public documentation when behavior changes.
- Add or update OpenAPI and event schemas before implementing public contract changes.
- Use migrations for every database schema change.
- Never include real credentials or copied environment files in issues, fixtures, logs, or commits.
- Use synthetic identities and provider references in tests.

## Security-sensitive Changes

Authentication, authorization, token, cryptography, billing, entitlement, secret,
and application/workspace-isolation changes require explicit threat analysis and negative tests.

## Compatibility

No stable API exists yet. Once compatibility rules are published, breaking changes
will require the documented versioning and deprecation process.
