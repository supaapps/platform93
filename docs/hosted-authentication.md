# Optional hosted authentication

Platform93 applications can use either headless SDK authentication or an optional
hosted browser flow for ordinary OIDC relying parties. The hosted UI is included
at `/auth/` in the same static export and Go image as the administrator UI, but
authenticates application users, never Platform users.

## Client setup

Create a public or confidential authorization-code client inside the application.
Register the relying party's exact callback URI and enable `authorization_ui:
hosted` in its OAuth client details. Existing and new clients default to `headless`.
Browser authorization requests use the hosted interaction only for opted-in
clients. Requests explicitly accepting `application/json` keep the existing
headless consent contract.

Use the installation issuer `/oidc` and its relative discovery URL
`/oidc/.well-known/openid-configuration`. Discovery advertises authorization,
token, userinfo and JWKS endpoints. Request `openid email profile` when the client
needs the stable subject, verified-email status and display name. ID-token audience
is the OAuth client ID; access-token audience remains the application audience.
Validate signature, issuer, audience, expiry, nonce and state in the relying party.
Hosted consent requires verified email before granting the `email` scope; an
unverified password signup cannot claim an email-matched relying-party account.

S256 PKCE remains required by default, and is always required for public/native
clients. A confidential web client authenticating with its secret can explicitly
disable required PKCE for compatibility. Supplied challenges are still verified:
there is no plain-PKCE or challenged-request downgrade. Client-secret Basic and
POST authentication are supported; never expose that secret in a browser.

## Browser session behavior

Validated interactions live for fifteen minutes in PostgreSQL, bound to their
browser cookie, application, client and callback. POST actions require both a
same-origin request and the interaction CSRF credential. Access and refresh
credentials stay encrypted on the server; the hosted page uses no browser token
storage. Successful consent redirects with a one-time authorization code only.

Email codes and links, password registration/recovery, configured social providers,
email verification, required TOTP/passkey MFA and recovery codes reuse application
policies. A passkey must have been enrolled for the hosted origin; an application
origin's passkey cannot be used at an unrelated Platform93 origin.

Refresh resumes an unfinished interaction. Back navigation and failed provider
exchange can be recovered by starting over or beginning a new request from the
application. One-time return credentials are removed from the visible URL before
exchange. Concurrent mutations are leased and fenced in PostgreSQL.

Sessions and consent are application-local. `prompt=login`, `consent`,
`select_account`, `none` and `max_age` are supported. Silent requests return
`login_required` or `consent_required` rather than showing a page. Account switching
revokes the current hosted application session, not other applications' sessions.
Invalid clients/callbacks display a local error; cancellation can return
`access_denied` only through a validated authorization callback.

## Invitations

Existing invitations remain application-directed. For an explicitly hosted
invitation, supply `hosted_client_id` (the client's UUID) and
`hosted_redirect_uri` (one of its registered callbacks) when creating it. Also
configure the client's HTTPS `initiate_login_uri`, a sign-in/start page rather
than its callback. The invitation email uses the normal localized templates.

Acceptance verifies the email/provider, applies roles and membership, and handles
MFA with the existing one-time invitation and PKCE protections. It then returns to
the application's sign-in/start page. That application starts a fresh OIDC request
with its own state/nonce. Platform93 must not send an unsolicited authorization
code to a callback without a relying-party request. A valid hosted session avoids
another login; first consent can still be required.

## Branding

Under Providers, edit hosted branding at installation, organization or application
scope. Application overrides take precedence over organization and installation
values. Empty fields inherit; resetting removes the local override. Localized
heading/help use language-tag keys with requested-language, browser-language,
default-language and English fallback.

Branding supports display name, HTTPS logo/favicon URLs, public managed assets,
approved layouts, readable colors and privacy/terms/support links. It accepts
plain text only: no injected HTML/CSS/scripts, remote fonts or tracking code.
Provider labels, client identity, consent disclosures and errors are not removable.
Email templates, registration policy and provider inheritance remain independent.

## Confidential web client example

[Postal's documented OIDC setup](https://docs.postalserver.io/features/oidc/)
requires a callback such as `https://mail.example/auth/oidc/callback`, discovery,
client-secret authentication and email claims. Its stock configuration does not
enable PKCE, so choose a confidential hosted client with explicit compatibility
mode. Keep PKCE required for integrations that support it.

```yaml
oidc:
  enabled: true
  name: Platform93
  issuer: https://identity.example/oidc
  identifier: YOUR_CLIENT_ID
  secret: YOUR_SERVER_SIDE_CLIENT_SECRET
  scopes: [openid, email, profile]
```

Postal requires a pre-existing local user. Initial matching uses email, then the
stable subject on subsequent logins; it does not provision users. Restrict access
to trusted accounts with verified email and consider the security implications of
email-based initial matching. Platform93 does not merge identities across apps or
provide Postal provisioning, SAML or cross-application single logout.

The opt-in `PLATFORM93_POSTAL_COMPAT_TEST=1` PostgreSQL integration fixture runs
the pinned Postal 3.3.7 image with a disposable MariaDB database and a temporary
trusted TLS certificate. It verifies stock discovery and client authentication,
first and repeat login for an existing local user, and rejection of an unknown
local user. CI runs this fixture; it requires Docker and the built static admin.
