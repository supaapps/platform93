# Release Readiness

Platform93 is under active development. The current tree is a functional
clean-install prerelease and must not be tagged `v1.0.0` yet.

## Implemented And Verified

- One rewritten clean-install PostgreSQL baseline, one-time bootstrap, break-glass recovery,
  database-only doctor/migrate/backup/restore commands, and live backup restoration.
- Separate Platform user and application-user sessions, one installation
  issuer, exact control/application audiences and actor types, audit records, and
  cross-organization/application middleware tests.
- Platform user account profile, footer logout, email code/link and optional Argon2id
  password login, recent-auth password enrollment, and session revocation controls.
- Password, email code/link, Google authorization code with PKCE, rotating refresh
  families, replay containment, account lifecycle, personal keys, TOTP, WebAuthn,
  recovery codes, recent-auth gates, sessions, consent, and delegation contracts.
- Fosite-backed OAuth 2.1/OIDC discovery, S256 authorization code, token, refresh,
  client credentials, revocation, introspection, userinfo, consent, and RS256 JWKS rotation.
- Application and workspace roles, permission checks/explanations, unified invitations,
  explicit workspace context, atomic membership replacement and ownership transfer,
  workspace retirement, custom-role lifecycle, and organization/application recovery.
- Products with typed entitlement defaults, immutable price snapshots, typed checkout
  configuration, public catalog, append-only entitlement actions, and immutable
  local-entitlement request snapshots.
- Stripe Dahlia connection, Checkout/portal and billing lifecycle contracts, payment
  method policy including TWINT validation, webhook receipts/replay, reconciliation,
  refunds/disputes, tax/address controls, and entitlement effects for handled events.
- Installation/application SMTP lifecycle, versioned templates, preferences,
  bounded attachments, retry/dead-letter history, statistics, and test delivery.
- Built-in and application-defined event contracts, authenticated custom event
  publication, CloudEvents records, transactional outbox, signed SSRF-protected
  webhooks, endpoint update/test/rotation, replay, delivery details, audit search/export,
  HTTP and worker Prometheus metrics, and OTLP HTTP traces.
- Optional inherited S3-compatible public/private storage with provider pinning,
  transactional quotas, direct presigned transfers, asynchronous cleanup, managed
  email images, encrypted credentials, SSRF controls, and MinIO integration coverage.
- Static administrator workflows for control, identity, workspaces, catalog, billing,
  entitlements, local requests, notifications, webhooks, events, audit, and operations.
- Clean-install Playwright coverage includes bootstrap, boundary creation,
  application retirement/recovery, and serious/critical Axe accessibility checks.
- Generated, strongly typed 3.1/3.0 OpenAPI contracts with 455 mounted-operation parity, six npm
  packages, one root Composer package with optional Laravel guard, two Python packages
  with FastAPI/Django/Flask adapters, and Go authentication/webhook/storage packages.
- Rootless multi-architecture image, Compose, Helm with migration/backup jobs and
  network policy, synchronized trusted-publishing workflow, SBOM/provenance/signing,
  shared cross-language conformance, and a real clean-install Playwright flow.
- Exact-origin browser CORS derived from enabled public-client redirects or verified
  application domains, non-credentialed cross-origin SDK access, strict control-cookie
  mutation origins, HTTPS HSTS, anti-framing headers, and bounded request bodies.
- The single unpublished baseline is verified cleanly in both directions (`up`, `down`,
  then `up`) in CI before `doctor` validates River and authorization state.

## `v0.1.0` Candidate Gates

- All fixed public request and response objects reject unknown top-level fields; only
  documented metadata, configuration, template-variable, and custom-event maps remain open.
- PostgreSQL and MinIO integration tests must report passing sentinel tests in CI rather
  than merely receiving environment variables and silently skipping.
- The exact tagged commit must pass reusable verification and security workflows. The
  final published multi-architecture image is rescanned after it is built.
- Alpha databases must be recreated. Existing external application data and Stripe
  resources are not imported or adopted automatically.
- The redacted Stripe, SMTP, Google, Apple, and S3 release-candidate checklist in
  [Release Process](releasing.md) must be complete before the stable tag.

## Blocking `v1.0.0`

- Enforce PostgreSQL row-level security with a non-owner runtime role and request-
  scoped application context. Current isolation is enforced by middleware and scoped SQL.
- Replace remaining handwritten persistence queries with the accepted sqlc boundary,
  or record an ADR changing that requirement with equivalent compile-time verification.
- Run real-provider Stripe test-clock suites across Checkout, portal, subscription
  proration/cancellation, tax, refunds, disputes, duplicate/stale/missed webhooks, and TWINT.
- Run real Google, SMTP, and browser virtual-authenticator suites for passwordless,
  password reset, account linking, TOTP, WebAuthn, recovery, and step-up behavior.
- Complete granular Platform user permissions beyond owner/admin/auditor/member roles.
- Add multi-process crash/lease/duplicate-delivery chaos tests, sustained load tests,
  migration upgrade/rollback fixtures, and backup retention/restore drills in CI.
- Add comprehensive Playwright coverage for all administrator and headless user flows,
  accessibility checks, fuzz targets, and supported-version package matrices.
- Complete threat modeling, independent security review, and remediation of all findings.

Every blocker must be implemented and verified, or changed by an accepted ADR,
before a `v1.0.0` tag is created.
