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

## Browser Origins

Platform93 permits direct browser SDK requests only from exact origins derived from
an enabled public OAuth client's web redirect URIs or from a verified application
domain. Register `https://app.example/auth/callback` on a public client to permit
the origin `https://app.example`; paths do not widen access beyond that origin.
Loopback HTTP origins are supported for development through the same exact redirect
registration. Custom mobile schemes do not create browser CORS origins.

Cross-origin requests never include Platform93 control cookies. Allowed application
origins may send bearer tokens and the documented `Content-Type`, `Authorization`,
`Idempotency-Key`, and `If-Match` headers. Unknown origins, methods, and request
headers fail closed. OIDC discovery and JWKS are public; token and userinfo access
uses the same registered public-client origin policy.

Use it for client-safe values such as branding, support links, feature display
preferences, or public service identifiers. Never store credentials, tokens,
provider secrets, private endpoints, or operational data in this object.

The runtime response also contains a derived `auth` capability object. This lets
an application render only the authentication methods currently allowed without
exposing internal-only policy such as delegation or personal-key controls.

The derived `storage` object reports only safe runtime capabilities and limits:
whether public/private uploads resolve, their maximum object sizes, the managed
email-image limit, and the source scope. It never exposes provider endpoints,
credentials, bucket names, or private object metadata.

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
- `delegation_enabled`: permits audited Platform user delegation into application-user
  access. Disabling it revokes active delegations and their delegated sessions.
- `user_invitations_enabled`: permits workspace owners and members with invitation
  management permission to create and resend invitations. Administrative Platform users
  and machine clients remain governed by their own permissions. Disabling this does
  not invalidate invitations that were already sent.
- `custom_token_claim_keys`: allowlists user `custom_attributes` keys that may be
  copied under the JWT and userinfo `custom_claims` object. Standard claims cannot
  be replaced, and the serialized object is limited to 4 KiB.

New applications default to public registration, password and passwordless
authentication enabled, and personal API keys and delegation disabled. Provider
credentials and inheritance remain separate from both configuration objects.
User-managed invitations are disabled and the custom-claim allowlist is empty.

All configuration writes use the application ETag through `If-Match`. Public
configuration writes replace the complete public object. Internal writes are
strict partial updates and reject unknown keys.
