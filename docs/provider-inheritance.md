# Provider inheritance

Platform93 supports authentication, notification, billing, and object-storage providers at three scopes:

1. Installation providers can serve the control plane and, when marked inheritable, every organization and application.
2. Organization providers can serve applications in that organization when marked inheritable.
3. Application providers serve only that application.

For an application, resolution is deterministic: application, organization, then installation. A disabled or non-inheritable parent provider is skipped. Application providers cannot be marked inheritable.

Provider credentials are encrypted with the installation master key. APIs and the administrator UI return redacted metadata, scope, inheritance status, and callback or webhook URLs, but never return stored credentials.

Inheritance can be enabled or disabled after a provider is created without resubmitting its credentials. In the administrator UI, installation providers expose a **Global default for organizations and applications** toggle; organization providers expose an **Available to applications in this organization** toggle. Turning either off leaves the provider configured and usable at its owning scope, but removes it from child resolution immediately. Existing sessions, subscriptions, and queued deliveries keep their original records; only new provider resolution changes.

## Authentication

Google and Sign in with Apple can be configured at any scope. Each application still has its own users, external identities, challenges, sessions, redirect allowlist, and callback path even when it inherits provider credentials.

Register these callback patterns with the provider:

```text
https://platform.example/v1/applications/{application_id}/auth/providers/google/callback
https://platform.example/v1/applications/{application_id}/auth/providers/apple/callback
```

Google requires a web OAuth client ID and client secret. Apple requires a Services ID, Team ID, Sign in with Apple Key ID, and ES256 private key. Apple posts the authorization result to the callback, so the public Platform93 URL must use HTTPS outside local development.

Changing a parent authentication provider affects new authorization flows. Existing Platform93 sessions and linked provider identities remain application-owned.

## SMTP

The control plane always resolves an installation SMTP provider. Organization notifications resolve an organization provider first and then an inheritable installation provider. Application notifications resolve an application provider first, then an inheritable organization provider, then an inheritable installation provider.

Saving SMTP credentials does not prove connectivity. Use **Verify** at the scope that owns the provider. Sender identities and delivery attempts remain associated with the selected provider and application notification.

## Stripe

Register each Stripe connection webhook URL shown by the administrator UI:

```text
https://platform.example/provider-webhooks/stripe/{connection_public_id}
```

A shared Stripe account can serve many applications, but Platform93 billing customers, Checkout sessions, subscriptions, invoices, payments, refunds, disputes, and entitlements remain application-owned. Platform93 writes application and subject metadata to Stripe objects and also resolves later metadata-light events through stored provider object identifiers.

Checkout and portal requests may omit `provider_id`; Platform93 then resolves the newest active application, organization, or installation connection in that order. Supplying `provider_id` explicitly pins an allowed connection. Existing subscriptions remain attached to their original connection so lifecycle operations continue using the correct credentials.

## Object Storage

Public and private storage resolve independently, which allows an application to
override one bucket role and inherit the other. Objects remain pinned to their
original provider when inheritance changes. See [Optional Object Storage](object-storage.md)
for direct uploads, verification, CORS, lifecycle, and quota behavior.

## Access control

- Installation provider reads require an installation role. Mutations require installation `owner` or `admin`.
- Organization provider reads require organization membership or an installation role. Mutations require organization `owner` or `admin`, or installation `owner` or `admin`.
- Application reads follow application visibility. Mutations require organization or installation administration rights.
- Inherited providers are read-only from a child scope. Select the owning installation or organization context to update, verify, or disable them.
