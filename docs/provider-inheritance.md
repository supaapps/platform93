# Provider inheritance

Platform93 supports authentication, notification, billing, and object-storage providers at three scopes:

1. Installation providers can serve the control plane and, when marked inheritable, every organization and application.
2. Organization providers can serve applications in that organization when marked inheritable.
3. Application providers serve only that application.

For an application, resolution is deterministic: application, organization, then installation. A disabled or non-inheritable parent provider is skipped. Application providers cannot be marked inheritable.

Provider credentials are encrypted with the installation master key. APIs and the administrator UI return redacted metadata, scope, inheritance status, and callback or webhook URLs, but never return stored credentials.

Inheritance can be enabled or disabled after a provider is created without resubmitting its credentials. In the administrator UI, installation providers expose a **Global default for organizations and applications** toggle; organization providers expose an **Available to applications in this organization** toggle. Turning either off leaves the provider configured and usable at its owning scope, but removes it from child resolution immediately. Existing sessions, subscriptions, and queued deliveries keep their original records; only new provider resolution changes.

## Authentication

Google, Apple, Microsoft, Facebook, and LinkedIn can be configured at any scope. Each application still has its own users, external identities, challenges, sessions, and consuming-application redirect allowlist even when it inherits provider credentials. Every provider has one installation-wide callback URL: Platform93 resolves the application from the random, single-use sign-in state stored before redirecting to the provider.

Register these exact callback URLs once with the provider:

```text
https://platform.example/v1/auth/providers/google/callback
https://platform.example/v1/auth/providers/apple/callback
```

Google requires a web OAuth client ID and client secret. Apple requires a Services ID, Team ID, Sign in with Apple Key ID, and ES256 private key. Microsoft requires an Entra application ID, client secret, and tenant mode (`common`, `organizations`, `consumers`, or an exact tenant UUID). Facebook requires an App ID and App secret. LinkedIn requires a client ID, client secret, and the OpenID Connect product. Apple posts the authorization result to the callback, so the public Platform93 URL must use HTTPS outside local development.

Platform93 accepts provider email as verified identity data only when the provider supplies a verified OpenID Connect email claim. Microsoft and Facebook email/profile fields are never treated as proof of mailbox ownership. A new application signup through either provider must complete Platform93 email-code or magic-link verification before the user is created. LinkedIn follows the same fallback when no verified email claim is available.

Changing a parent authentication provider affects new authorization flows. Existing Platform93 sessions and linked provider identities remain application-owned.

## SMTP

The control plane always resolves an installation SMTP provider. Organization notifications resolve an organization provider first and then an inheritable installation provider. Application notifications resolve an application provider first, then an inheritable organization provider, then an inheritable installation provider.

Saving SMTP credentials does not prove connectivity. Use **Verify** at the scope that owns the provider. Sender identities and delivery attempts remain associated with the selected provider and application notification.

### Application email sender name

An application may keep inherited SMTP credentials and its authorized sender
address while using its own display name, such as `Example Support
<noreply@example.com>`. In the application context, open **Providers → Email →
Application email sender**, enter **App sender name**, and save. Clearing the field
restores the selected provider's name. This also works with app-owned SMTP.

The control API uses `PATCH /v1/control/applications/{application_id}/internal-config`
with `If-Match` for the application's current version and a partial body:

```json
{"email_sender_name":"Example Support"}
```

Names are trimmed and limited to 200 Unicode characters; control characters,
non-string values and `null` are rejected. Use `""` to reset. Omitted settings are
preserved. This is internal configuration, not public application config.

The worker applies the current override to all application emails, including
authentication and invitations, when it attempts delivery. It changes only the
`From` display name, never the SMTP envelope address, provider configuration or
credentials. Queued retries use the current name. Sibling applications and
installation/organization control emails are unaffected. Changing providers keeps
the app's override until it is cleared; disabling a provider does not bypass normal
provider resolution or delivery restrictions.

Display names are presentation only, not a new verified sender domain. The
provider's authorized address and existing SPF/DKIM configuration remain in use.

## Stripe

Register each Stripe connection webhook URL shown by the administrator UI:

```text
https://platform.example/provider-webhooks/stripe/{connection_public_id}
```

A shared Stripe account can serve many applications, but Platform93 billing customers, Checkout sessions, subscriptions, invoices, payments, refunds, disputes, and entitlements remain application-owned. Platform93 writes application and subject metadata to Stripe objects and also resolves later metadata-light events through stored provider object identifiers.

Verified webhook deliveries return a JSON acknowledgement:

```json
{"received":true,"status":"ignored","reason":"unrelated_event"}
```

`processed` means billing changes and the receipt committed together; `duplicate`
means the receipt is already complete. `ignored` means no application billing
changes were made. Its reason is `unsupported_event` or `unrelated_event`.
Unsupported types are acknowledged after signature/envelope validation without
application routing. Supported types with no P93 markers or connection-scoped
record association are unrelated; a connection's owning application is never used
as a default owner. Shared accounts may safely contain unrelated subscriptions.
This classification uses local records and event metadata, not a Stripe API
lookup. An event with neither cannot be distinguished from external account
activity, even if a mapping might be introduced later; it is not automatically
recovered. Preserve P93 metadata and existing customer/object mappings. A known
P93 reference whose required mapping is missing is retryable instead.

Ignored decisions are logged with connection/event identifiers, event type,
reason and request ID, not raw payloads, metadata, customer details or secrets.
They are not stored in application billing-event history. Repeated ignored
deliveries remain harmless. Select only required event types in Stripe to reduce
noise: checkout completion/async success/expiry, subscription creation/update/
deletion, supported invoice and payment-intent lifecycle events, refunds and
disputes. Unsupported account events such as payouts do not require app metadata.

Invalid signatures and malformed envelopes are rejected. Invalid/conflicting P93
references and forbidden application/connection combinations return 422. P93-marked
events lacking their association return retryable 503; database, storage and
processing failures return 5xx, never `ignored`. Keep these failures visible rather
than inventing application metadata to make an unrelated event pass.

Failed/pending receipts retry under a database row lock. Normalization, grants,
events/outbox and completion status share one transaction, so failure rolls back
side effects. A crash after receipt insertion but before processing leaves a
pending receipt recoverable through Stripe retry or administrative replay.
Completed duplicates and administrative replays are no-ops; replay
of a failed receipt uses the same atomic processing path. Application/control-user
authorization for administrative replay is unchanged.

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
