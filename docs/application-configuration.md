# Application Configuration

Every application has separate public runtime configuration and internal access
policy. They intentionally have different exposure and enforcement rules.

## Public Configuration

`public_config` is an arbitrary JSON object managed from the application Overview
or `PATCH /v1/control/applications/{application_id}/public-config`. Platform93
returns the complete object without authentication from
`GET /v1/applications/{application_id}/public-config`.

The TypeScript SDK loads the typed runtime envelope directly:

```ts
const runtime = await client.application().publicConfig();
console.log(runtime.public_config);
```

The generated client also exports the lower-level `publicConfig(...)` operation.
The authentication package uses this same endpoint when it builds PKCE authorization
requests from the application's public flow configuration.

Use it for client-safe values such as branding, support links, feature display
preferences, or public service identifiers. Never store credentials, tokens,
provider secrets, private endpoints, or operational data in this object.

The runtime response also contains a derived `auth` capability object. This lets
an application render only the authentication methods currently allowed without
exposing internal-only policy such as delegation or personal-key controls.

## Internal Access Policy

`internal_config` is visible only through the authenticated control API. Platform93
enforces these values on the server rather than relying on clients to hide UI:

- `registration_mode`: `public` permits account creation; `invite_only` limits
  access to users created by an administrator or an invitation workflow.
- `password_enabled`: permits password sign-in and password registration when
  registration is public.
- `passwordless_enabled`: permits email codes and magic links. Disabling it also
  prevents outstanding email challenges from being exchanged.
- `personal_api_keys_enabled`: permits users to create and use personal API keys.
  Disabling it revokes every active personal key in the application.
- `delegation_enabled`: permits audited operator delegation into application-user
  access. Disabling it revokes active delegations and their delegated sessions.

New applications default to public registration, password and passwordless
authentication enabled, and personal API keys and delegation disabled. Provider
credentials and inheritance remain separate from both configuration objects.

All configuration writes use the application ETag through `If-Match`. Public
configuration writes replace the complete public object. Internal writes are
strict partial updates and reject unknown keys.
