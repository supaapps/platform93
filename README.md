# Platform93

Platform93 is an Apache-2.0 self-hosted control plane for application identity,
authorization, workspaces, billing, entitlements, transactional email, events, and
outgoing webhooks, with optional S3-compatible light object storage. PostgreSQL is
the only required runtime service.

It keeps authoritative security and commercial state outside application code and
exposes it through versioned APIs, events, and generated SDKs.

Authorization uses strict relative permission keys, reusable roles, and optional
identity-specific direct grants. See [application authorization](docs/authorization.md).

> The control plane outside your app.

Platform93 targets fresh installations and new contracts. It does not include
legacy API adapters, source-database import, hosted end-user pages, CRM,
marketing automation, or a generic application database.

The repository is currently a development foundation, not a `v1.0.0` release.
See [Release Readiness](docs/release-readiness.md) for implemented coverage and
the gates that remain before a production tag.

## Repository

- `cmd/platform93`: API, worker, dispatcher, migration, bootstrap, and recovery CLI.
- `internal`: isolated Go domain and infrastructure modules.
- `migrations`: explicit PostgreSQL schema history embedded in the binary.
- `api/openapi`: canonical HTTP contract.
- `schemas/events`: immutable event contracts.
- `web`: statically exported administrator application embedded in the image.
- `sdk`: supported TypeScript, PHP, Python, and Go integrations.
- `deploy`: Docker Compose and production Helm packaging.

## Local Start

Create `postgres_password`, `database_url`, and `platform93_master_key` files in
`deploy/compose/secrets`. The database URL uses the PostgreSQL password; the
master key is the base64 representation of exactly 32 random bytes.

```bash
docker build -t platform93:dev .
PLATFORM93_IMAGE=platform93:dev docker compose -f deploy/compose/compose.yaml up -d
docker compose -f deploy/compose/compose.yaml run --rm api bootstrap
```

Open `http://localhost:8093` and consume the one-time bootstrap credential.

## Development

```bash
pnpm install
pnpm typecheck
go test ./...
pnpm --filter @platform93/admin build
go build ./cmd/platform93
```

## Integration Packages

- `@supaapps/platform93-sdk`: generated TypeScript API client.
- `@supaapps/platform93-auth`: headless browser authentication and token storage adapters.
- `@supaapps/platform93-expo`: Expo/React Native auth sessions with SecureStore-backed refresh credentials.
- `@supaapps/platform93-react`: React provider and authentication hooks.
- `@supaapps/platform93-server`: strict Node.js JWT/JWKS verification.
- `@supaapps/platform93-events`: event contracts and webhook verification.
- `supaapps/platform93`: Composer authentication/webhook package with optional Laravel guard.
- `supaapps-platform93-auth`: Python verifier with FastAPI, Django, and Flask adapters.
- `supaapps-platform93-webhooks`: Python webhook signature verification.
- `github.com/supaapps/platform93/sdk/go`: Go authentication, machine-client, webhook, and direct-storage packages.

Native applications can register exact custom-scheme callbacks on public clients; see
[Native mobile authentication](docs/native-mobile-auth.md).

## Principles

- Self-hosting is complete and never depends on a managed service.
- Security boundaries deny by default and remain explicit in tokens and APIs.
- Public behavior is contract-first and versioned.
- Data is exportable and provider integrations remain replaceable.
- Operations, migrations, backups, and diagnostics are product features.
- The repository never contains deployment credentials or private application data.

See [Architecture Principles](docs/architecture.md),
[Platform User Authentication](docs/platform-user-authentication.md),
[Application Configuration](docs/application-configuration.md),
[Application And Workspace Invitations](docs/invitations.md),
[Catalog And Entitlements](docs/catalog-entitlements.md),
[Notification Templates](docs/notifications.md),
[Provider Inheritance](docs/provider-inheritance.md),
[Organization Management And Governance](docs/organization-management.md),
[Events And Webhooks](docs/events-webhooks.md),
[Optional Object Storage](docs/object-storage.md),
[Migration From Supaapps Platform](docs/migrating-from-supaapps-platform.md),
[Helm deployment](deploy/helm/platform93/README.md),
[Upgrades](docs/upgrades.md),
[Release process](docs/releasing.md),
[v0.1.0 security review record](docs/security-review-0.1.0.md),
[Contributing](CONTRIBUTING.md), and [Security Policy](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
