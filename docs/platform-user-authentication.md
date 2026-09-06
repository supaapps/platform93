# Platform user authentication

Platform users administer the installation and organizations. They are not application users, even when both records use the same email address.

Control access tokens always use the installation issuer, audience `platform93:control`, `actor_type=control_user`, and `token_kind=control`. Provider identities linked to an application user are never reused for Platform access. Control tokens remain invalid at application endpoints.

## Sign-in methods

Installation owners configure the available methods under **Platform > Identity**:

- Email code and magic-link sign-in require an active installation SMTP provider.
- Password sign-in is globally switchable and is available only to accounts that have stored a password.
- Google, Apple, Microsoft, Facebook, and LinkedIn require an installation-scoped provider with **Platform user sign-in** enabled.
- Provider inheritance is independent. A provider may authenticate Platform users, be inherited by applications, do both, or do neither.

The public `GET /v1/control/auth/methods` endpoint is the source of truth for rendering a login screen. Sessions record `authenticated_at` and `amr`; access tokens expose `amr` without changing the control audience.

## External identities

Platform93 uses the same installation-wide provider callback URLs for application and Platform flows:

- Google: `/v1/auth/providers/google/callback`
- Apple: `/v1/auth/providers/apple/callback`
- Microsoft: `/v1/auth/providers/microsoft/callback`
- Facebook: `/v1/auth/providers/facebook/callback`
- LinkedIn: `/v1/auth/providers/linkedin/callback`

Signed state resolves the pending flow. Organization- and application-scoped provider credentials can never authenticate a Platform user.

Email matching does not link or create a Platform account. A provider subject becomes usable only after either:

1. An authenticated Platform user starts a recent-auth account-linking flow.
2. A Platform-user invitation explicitly requires that provider and the provider-verified email exactly matches the invitation.

Disabling a provider preserves linked identities. Re-enabling the same provider configuration makes them usable again.

## Invitations and lockout prevention

Installation and organization Platform users are provisioned through invitations. Each invitation selects `email`, `google`, `apple`, `microsoft`, `facebook`, or `linkedin` for initial onboarding. Resending rotates the credential, refreshes expiry, and invalidates outstanding provider challenges. The selected method does not restrict later sign-in after acceptance.

Platform93 blocks policy changes, provider disabling, and identity unlinking when the current Platform user or any active installation owner would lose every usable sign-in method. Changes affecting only non-owner accounts require explicit confirmation and return `affected_users` in the RFC 9457 problem response.

If setup is completed without SMTP, the bootstrap owner must set a password. Recovery remains available through the `platform93 recover` command.
