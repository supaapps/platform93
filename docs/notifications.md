# Notification Templates

Notification templates are immutable, versioned installation or application
records. A draft can be previewed and then published; editing an existing version creates a new draft.
Templates have a subject, a required plain-text fallback, an optional HTML body,
and a typed schema for application-supplied variables.

Platform93 seeds published installation templates for Platform user sign-in,
application sign-in, email verification/change, password reset, organization,
application, and workspace invitations. Applications list these basic templates
as inherited defaults. Editing an inherited template creates an application
draft; it does not mutate the installation version. Once that draft is published,
it becomes the effective template for that application. Rendered subject, text,
HTML, and template version are snapshotted when a notification is queued.

## Localization

Every template key may have multiple published locale variants. Locale values are
canonical BCP 47 language tags such as `de`, `de-CH`, `en-GB`, or `pt-BR`.
Creating or editing a localization produces an immutable draft version; publishing
it replaces only the previously published version for that template key and locale.

Application users have an optional free-text `locale` profile field. It can be
updated through the current-user or control-plane user APIs and is also exposed as
the standard `locale` OIDC profile claim. An empty value means no preference.

When a message is queued, Platform93 resolves localization in this order:

1. The explicit `locale` on the queue request, when present.
2. The selected user's locale when `user_id` is present.
3. Parent language tags, for example `de-CH` then `de`.
4. English (`en`).
5. The first remaining published locale in stable alphabetical order.

At every step, an application template overrides an installation template for
the same locale. The notification stores the actual resolved locale, and the
encrypted immutable template snapshot records the requested locale and whether a
fallback occurred. Queue responses also return `requested_locale`,
`resolved_locale`, and `fallback_used`.

Installation owners and administrators manage defaults under:

```text
/v1/control/installation/notification-templates
```

## Template Codes

Codes use `{{code_name}}` syntax. Platform93 escapes replacement values in HTML
and rejects undeclared application codes. The admin composer lists every code,
inserts it at the active cursor, and renders sample values without sending mail.

These codes are resolved by Platform93 for every queued notification:

- `application_id`, `application_name`, and `application_slug`
- `support_name`, `support_email`, and `support_url` from public application configuration
- `recipient_email`
- `current_year`
- `message_locale`

These codes are resolved from the current active user when `user_id` is supplied
to the queue request:

- `user_id`, `email`, `first_name`, `last_name`, and `full_name`
- `username`
- `email_verified` and `is_org_verified`
- `user_locale`

The caller cannot override built-in values through `variables`. This prevents a
message from displaying identity data that disagrees with its actual recipient.
Messages queued with only a raw `recipient` cannot use user-only codes.

Applications can define additional string, integer, number, or boolean codes in
the template variable schema. Those values must be included in `variables` when
the notification is queued. Required values and types are checked before any
notification record is created.

The authoritative built-in catalog is available from:

```text
GET /v1/control/applications/{application_id}/notification-template-variables
```

The response includes labels, descriptions, availability rules, declared types,
and safe preview samples for admin tooling.

System templates also declare flow-specific codes such as `code`, `magic_link`,
`invitation_code`, `invitation_link`, `workspace_name`, roles, and `expires_at`. These
are populated only by Platform93; an application cannot supply or spoof them in
a built-in security flow.

## Application Redirects

Each application can configure `auth_config.flows` with a public OAuth client ID,
an exact registered sign-in redirect URI, and a same-origin invitation redirect
URI. The client must allow `authorization_code`. Platform93 rejects unregistered
sign-in redirects and non-HTTPS redirect origins, except HTTP localhost during
development.

Email magic links return to the configured sign-in URI with a one-time challenge.
After consuming the challenge, `@supaapps/platform93-auth` can call
`createAuthorizationRequest()` to generate a verifier, S256 code challenge, and
authorization URL. The invitation URI receives an application ID, invitation ID,
and one-time link credential. Applications exchange it through the browser auth
package; email plus the eight-character invitation code is the equivalent manual
path.

## Machine Delivery

Application backends send template notifications with an application machine
client. Create a machine client, assign `notification_sender` or a custom role,
and keep its client secret in the backend secret manager. The server SDK exchanges
client credentials, caches the short-lived JWT, and calls:

```text
POST /v1/applications/{application_id}/notifications
```

`notifications:send` permits delivery to an application `user_id`.
`notifications:send_external` is separate and permits arbitrary recipients.
Application-user tokens, personal API keys, delegated sessions, Platform user tokens,
and browser requests are rejected by this endpoint.
Keys under `platform93.*` are reserved for internal security, invitation, account,
and billing flows and cannot be selected by a machine client.

## Delivery Safety

Template HTML is trusted administrator content but scripts, iframes, JavaScript
URLs, and data HTML URLs are rejected. Replacement values are always HTML
escaped. The admin renders unsent previews in a sandboxed iframe with a restrictive
content security policy.
