# Migrating From Supaapps Platform

Platform93 is a native replacement contract, not a legacy API or database clone.
Applications replace their SDK configuration and migrate their own identifiers;
Platform93 does not import an old database or automatically adopt Stripe objects.

## Identity And Authorization

| Supaapps platform | Platform93 |
| --- | --- |
| Root realm | Installation control plane |
| Application realm | Application |
| Realm user | Application user |
| Workspace | Workspace |
| Root scopes | Installation and organization administrative roles |
| Realm/workspace scopes | Application and workspace roles with expanded permission paths |
| Auth guard packages | Platform93 TypeScript, Go, PHP, or Python verifier |
| Config fetcher | Public application configuration SDK method |

Password, email-code, magic-link, Google, Apple, Microsoft, Facebook, LinkedIn, MFA, email verification, rotating
sessions, personal API keys, and delegation have native Platform93 flows. OAuth
browser integrations use authorization code with PKCE. Application invitations
and optional workspace role assignment use the unified invitation API; invitation
links always return to the application's configured redirect URI.

## Billing And Entitlements

| Supaapps platform | Platform93 |
| --- | --- |
| `product_key` | Product `key` |
| Product `config` | Typed feature values and `entitlement_config` |
| `config_version` | Immutable price snapshot |
| `local_reference` | `external_reference` |
| Entitlement/subscription messages | Signed, versioned webhooks |

Platform93 owns its catalog. Products define entitlement defaults and immutable
prices snapshot effective feature values and configuration. Stripe metadata carries
only Platform93 application, product, price, checkout, subject, and external
reference identifiers; entitlement configuration is not copied into Stripe.

Existing Stripe products and subscriptions are not adopted automatically. Recreate
or explicitly map catalog records before moving checkout traffic. Application-
triggered no-payment trials remain a documented deferred capability.

## Notifications And Events

Replace notification queue messages with the backend machine SDK. Machine clients
use OAuth client credentials and explicit `notifications:send` or
`notifications:send_external` permissions. Callers select an active template and
provide validated variables; raw subject/body delivery is intentionally unsupported.

Replace RabbitMQ entitlement and subscription consumers with outgoing Platform93
webhooks. Verify signatures against the raw body, dispatch Platform93 events by
their versioned contract, and handle application-defined events as custom JSON.
Event handlers must be idempotent because delivery is at least once.

## Package Replacement

| Previous integration responsibility | Platform93 package |
| --- | --- |
| Browser API/config client | `@supaapps/platform93-sdk` |
| Browser password, passwordless, invitation, PKCE, and MFA flows | `@supaapps/platform93-auth` and `@supaapps/platform93-react` |
| Node backend guard and machine service calls | `@supaapps/platform93-server` |
| TypeScript webhook contracts and dispatch | `@supaapps/platform93-events` |
| PHP guard, webhook verification, and machine calls | `supaapps/platform93` |
| Python guard and machine calls | `supaapps-platform93-auth` |
| Python webhook verification | `supaapps-platform93-webhooks` |
| Go guard, webhook dispatch, and machine calls | `github.com/supaapps/platform93/sdk/go/...` |

Public configuration is read from the application runtime-config endpoint through
the browser-safe SDK. Backend configuration and credentials remain in the consuming
application's secret manager; Platform93 does not recreate the old config-fetcher
process or distribute machine secrets to browsers.

## Cutover Checklist

1. Create the organization, application, public OAuth client, machine clients, and roles.
2. Configure redirects, providers, application policy, templates, and public config.
3. Recreate products, immutable prices, feature values, and provider mappings.
4. Replace backend auth guards, notification publishing, event consumers, and billing correlation fields.
5. Replace browser authentication and invitation handling with Platform93 SDK flows.
6. Validate issuer, exact application audience, actor type, permissions, webhooks, and reconciliation before switching traffic.
