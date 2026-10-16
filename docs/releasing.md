# Release Process

All Platform93 artifacts use one `vX.Y.Z` release tag and must originate from the same
verified commit. Release candidates use `vX.Y.Z-rc.N` and publish npm packages under the
`rc` tag without changing `latest`.

## Required GitHub configuration

- Protect `main`; disallow force pushes and require the `CI / Verify` and `Security`
  workflow checks before merging.
- Keep workflows on standard GitHub-hosted runners.
- Configure npm trusted publishing for all six `@supaapps/platform93-*` packages.
  `@supaapps/platform93-expo` uses repository `supaapps/platform93`, workflow
  `release.yml`, and environment `npm`.
- Configure both PyPI projects with repository `supaapps/platform93`, workflow
  `release.yml`, and environment `pypi`.
- Register the Composer package `supaapps/platform93` on Packagist from this repository.

## Candidate verification

Tag a release candidate only after the release PR is merged. The tag workflow reruns
contracts, migrations, race tests, browser tests, package tests, secret/dependency/code
scans, image scanning, Compose validation, and Helm validation against that exact commit.

Complete the provider checks with dedicated test accounts. Credentials and provider
identifiers must stay in a secret manager and must not be committed, attached to the
release, pasted into issues, or printed in logs.

| Provider | Required result |
| --- | --- |
| Stripe | Card one-time and subscription Checkout, portal, cancellation, refund, tax/address options, webhook duplicate/replay, and CHF one-time TWINT pass. |
| SMTP | Verification, localized login/invitation email, attachment, retry, and dead-letter recovery pass. |
| Google | Application and Platform-user login/link/invitation flows pass with state, nonce, and PKCE checks. |
| Apple | Application and Platform-user login/link/invitation flows pass with state and nonce checks. |
| Microsoft | Application and Platform-user flows pass for the configured tenant mode, with state, nonce, PKCE, and Platform93 email completion for new application users. |
| Facebook | Access tokens are debugged against the configured App ID; application signup completes Platform93 email verification. |
| LinkedIn | OIDC login, nonce, PKCE, verified-email handling, and missing-email completion pass. |
| S3 | Public/private verification, direct upload, private download, deletion, inheritance, and disabled-provider behavior pass. |

Record only the date, release candidate, tester, environment class, and redacted
pass/fail outcome. Fix product defects on a normal branch and issue another RC tag.
Infrastructure-only reruns reuse the same tag and verify existing artifact integrity.

The stable tag may point to the accepted RC commit only after every artifact can be
clean-installed and the real-provider checklist is complete. Stable npm packages publish
directly to `latest` because npm trusted-publisher credentials authorize `npm publish` but
not a later `npm dist-tag` command. The workflow publishes the GitHub release only after
npm, PyPI, Composer source tags, GHCR image, Helm chart, checksums, SBOM/provenance,
signatures, and GitHub release assets are all available.

## Registry Readiness And Finalization

A successful publish command means the registry accepted the artifact, not that
every registry reader can immediately download it. Finalization waits for all six
npm packages, both Python packages, the Helm chart and the OCI image using one
ten-minute deadline with capped backoff. Individual HTTP/CLI probes are limited to
fifteen seconds, with npm metadata/download sharing that probe budget. Ready
artifacts are not repeatedly downloaded during subsequent retry rounds.

The npm job uploads a safe package/version/SHA-512 manifest calculated from its
packed artifacts. Finalization checks the exact npm versions, registry integrity
and downloaded tarball bytes against that manifest. It also checks the exact Python
versions and listed distribution files, Helm chart/application versions, and OCI
image-index availability before checking GitHub asset checksums and publishing
the draft release. Python metadata visibility is not a full consumer-install test.

Post-publication 404s, throttling and temporary server/network failures are retried
within the deadline. Authorization/configuration errors, malformed metadata and
integrity/version mismatches fail immediately. Probe output identifies pending
artifacts and timeout reasons without dumping registry credentials. Finalization
never republishes packages or moves tags. A finalization-only rerun reuses the
uploaded manifest from the successful npm job; rerunning npm replaces that manifest
only after its normal immutable-package checks and publishing step succeed.

Run the network-free regression suite with `pnpm test:release`. It is also required
by the reusable contracts verification job on pull requests and release tags.
