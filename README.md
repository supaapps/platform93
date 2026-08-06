# Platform93

Platform93 is an open-source control plane for application identity, tenants,
products, billing, entitlements, customer data, events, and administration.

It keeps authoritative security and commercial state outside application code and
exposes it through versioned APIs, events, and generated SDKs.

> The control plane outside your app.

## Project Status

Platform93 is in its initial architecture and contract-design phase. No stable
release or compatibility promise exists yet.

## Intended Capabilities

- Passwordless-first authentication, sessions, OAuth 2.1, and OpenID Connect.
- Application users, tenants, memberships, roles, and permissions.
- Products, prices, payment-provider checkout, subscriptions, invoices, and taxes.
- Local entitlement checkout and administrative grants.
- User and tenant entitlements with explicit provenance and expiration.
- Durable events, signed webhooks, notifications, and audit history.
- Admin web interface, CLI, OpenAPI contract, and generated SDKs.
- Self-hosting with PostgreSQL and one published application image.

## Principles

- Self-hosting is complete and never depends on a managed service.
- Security boundaries deny by default and remain explicit in tokens and APIs.
- Public behavior is contract-first and versioned.
- Data is exportable and provider integrations remain replaceable.
- Operations, migrations, backups, and diagnostics are product features.
- The repository never contains deployment credentials or private environment data.

See [Architecture Principles](docs/architecture.md), [Contributing](CONTRIBUTING.md),
and [Security Policy](SECURITY.md).

## License

An OSI-approved license will be selected before the first source release. Until a
license file is committed, copyright law applies and the repository should not be
treated as licensed for redistribution.
