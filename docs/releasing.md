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
| S3 | Public/private verification, direct upload, private download, deletion, inheritance, and disabled-provider behavior pass. |

Record only the date, release candidate, tester, environment class, and redacted
pass/fail outcome. Fix product defects on a normal branch and issue another RC tag.
Infrastructure-only reruns reuse the same tag and verify existing artifact integrity.

The stable tag may point to the accepted RC commit only after every artifact can be
clean-installed and the real-provider checklist is complete. The workflow moves npm
`latest` only after npm, PyPI, Composer source tags, GHCR image, Helm chart, checksums,
SBOM/provenance, signatures, and GitHub release assets are all available.
