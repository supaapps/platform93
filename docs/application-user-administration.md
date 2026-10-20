# Application user administration

Applications can build their own user-management UI using the SDK and the signed-in
application user's token. This never creates a Platform user or grants access to
the hosted control panel, SMTP, provider credentials, application settings, billing
connections, or organization administration. A role named `admin` has no special
meaning: only its explicitly assigned permissions grant access.

These are application-wide capabilities, not a role hierarchy: a caller allowed
to suspend users or revoke sessions can target another administrator in the same
application. Grant these permissions only to trusted administrators. Separate
role-assignment ceilings still prevent granting or removing roles outside the
caller's own effective permissions.

## Initial configuration

A Platform user creates an application role and assigns it to the initial
application administrator using the existing control workflows. Registration does
not automatically grant this role. A typical user-management role contains:

```json
[
  "users:read", "users:create", "users:update", "users:suspend", "users:restore",
  "users:sessions:read", "users:sessions:revoke",
  "roles:read", "roles:assign", "invitations:manage"
]
```

Use a smaller role for support staff. Separately grant
`users:email_verification:manage`, `users:organization_verification:manage`, or
`users:attributes:write` only when those sensitive operations are intended.
Custom attributes may appear in configured custom JWT claims; attribute writers
must therefore be trusted by the consuming application as well.

Application roles are expanded into `/applications/{application_id}/...` paths
using the standard permission grammar. Workspace ownership does not grant
application-wide user administration. Role definitions, OAuth client management,
password/email replacement, identity provisioning, MFA removal, delegation,
deletion and anonymization are not included.

## SDK usage

With `Platform93Auth`, the SDK already uses the signed-in application's user token:

```ts
const admin = auth.client.application().administration();
const users = await admin.listUsers({ query: "person@example.test", limit: 20 });
const user = await admin.getUser(users.items[0].id);
const etag = `"v${user.version.toString(16)}"`;

await admin.updateUser(user.id, {
  first_name: "Person", reason: "Correct the user's profile",
}, etag);

const invitation = await admin.createInvitation({
  email: "colleague@example.test",
  onboarding_method: "google", // or "email"
  send_email: true,            // false generates a copy-only invitation
  reason: "Onboard a colleague",
}, crypto.randomUUID());

// Display in a private, dismissible result panel, never analytics or logs.
await navigator.clipboard.writeText(invitation.invitation_url);
```

All mutations need an audit reason. Retryable POST mutations need a stable
`Idempotency-Key`; existing-resource changes need an explicit `If-Match` version.
After a change, reload the resource before further edits. Role-assignment mutations
use the recipient user's version; listing that user's assignments also returns
`user_version` for role managers who do not have general user-read permission.

The Go client accepts an `AccessToken` callback and exposes `Administration()`.
Python and PHP expose `ApplicationAdministrationClient` with an access-token
callback. Their machine clients expose `administration()` (Go: `Administration()`)
using existing client credentials and explicitly granted application permissions.
In a backend-for-frontend, forward the caller's application token rather than
silently replacing it with a more powerful machine token. Never put machine
secrets into browser or React configuration.

Silent account creation requires `users:create`, creates an unverified account,
and sends nothing. It does not create a password, session, workspace, or role
assignment. Initial verification flags or custom attributes require their separate
permissions. Silent provisioning from a known Google `sub` remains control-only.

## Invitations and delivery

Google invitations require the application's effective Google provider and a
Google-verified email matching the recipient, including Google Workspace emails.
No subject identifier is supplied by the inviter. Existing accounts without that
Google identity must authenticate and explicitly link it using the existing
account-linking flow; matching email alone never claims an account.
Other existing provider invitations likewise require a trusted matching email or
an identity already linked to the matching recipient account. An unverified
provider email cannot claim the invited address; use email onboarding first when
the provider cannot prove it.

`send_email` defaults to `true`. P93 validates active inherited/local SMTP and
renders a localized invitation before atomically queueing it with invitation
creation. `email_queued` is not a delivery guarantee. Copy-only invitations do not
require SMTP or template rendering. Both modes return `invitation_url` once.

If the recipient does not receive the message, send the returned URL manually.
After dismissing it, generate a replacement with `rotateInvitation`, choosing
whether to also send email. Rotation/resend shares a 60-second cooldown, rotates
both invitation credentials, refreshes expiry to seven days, and invalidates
outstanding email/provider acceptance challenges. Previously accepted, revoked,
or expired invitations cannot be rotated. List/detail responses never contain
the secret URL. Idempotent creation/rotation retries can recover the same result
for the original authorized caller; these response receipts are encrypted.
Receipts do not extend credential expiry or reverse later rotation/revocation;
a replayed response may contain a URL that has since become unusable.

Invitation creation, resend, and rotation by application users require
`user_invitations_enabled=true`, even for administrators. Disabling this setting
does not block existing invitation acceptance, inspection, or revocation.
Machine/control invitation exceptions remain separate. Roles included in an
invitation must be within the inviter's current permissions. P93 rechecks inviter
authority and role definitions before accepting; loss of authority prevents
partial account or membership creation.

Destinations use the configured application invitation redirect. Optional existing
hosted authentication redirects use the hosted sign-in surface, never the Platform
administrator panel, and then return through the registered application callback.

## Independent recipient authentication

An invitation link or invitation code is **not a login credential**. The creator
can copy it, so it must not let that creator impersonate the recipient.

For email invitations, either accept with a verified matching ordinary user
session, or request a separate mailbox challenge:

```ts
const invitation = { invitation_id, link_token }; // From the invitation URL.
const challenge = await auth.startInvitationEmailAuthentication(invitation);

// This code comes only from the recipient's separate authentication email,
// not from the invitation email, admin API, or copied invitation URL.
const result = await auth.acceptEmailInvitation(invitation, challenge.challenge_id, {
  code: recipientAuthenticationCode,
});
// Continue MFA if returned; do not treat an MFA challenge as a session.
```

Email challenge delivery requires active SMTP and enabled passwordless login.
If passwordless login is disabled, use an existing verified recipient session or
enable email authentication before onboarding a new email-only recipient.
An already verified matching session can accept without another email. The
independent email link also works in the originating PKCE browser context through
`acceptEmailInvitation(..., { linkToken })`. Its `challenge_id` and `link_token`
query fields identify the authentication proof, not the original invitation
credential. Preserve the original invitation context privately and remove
credential parameters from the address bar promptly.

An existing account with a password, linked provider, MFA method, active personal
key, or non-email session must have been email-verified before this invitation was
created. Otherwise acceptance returns `invited_account_review_required` without
consuming the invitation or granting roles. Later email verification alone does
not bypass this guard. This prevents account pre-hijacking: mailbox proof must not
leave an attacker's earlier credentials usable. A Platform administrator must
review and secure the account, revoke the old invitation, and issue a new one
after establishing the legitimate recipient. Do not merely toggle verification
or reissue invitations without reviewing credentials. Credential-free silent
accounts can complete independent mailbox authentication normally.
An application administrator with `users:email_verification:manage` can change
verification, but that permission does not include password, MFA or identity
recovery. Use the existing account/control workflows to secure such credentials;
then an authorized invitation manager may revoke and reissue the invitation.

Use `startApplicationInvitationProvider("google", invitation)` for Google-specific
invitations and the normal provider-exchange SDK continuation. Google verifies
the recipient independently. PKCE, provider state/nonce, and MFA remain required.

## Security and upgrade notes

Administrative requests require exact application audience/actor validation,
current active authority intersected with token scopes, and live session checks.
After creating a workspace, refresh the owner's token before administering its
invitations: live ownership alone cannot expand a token's original scope ceiling.
Sensitive human changes require authentication within ten minutes. Machine
clients use explicit permissions rather than human recent-authentication checks.
PATs, delegated sessions, resource tokens, and control tokens cannot substitute
for an application administrator. Granting `/applications/{id}/*` still cannot
authenticate to any control-plane route.

Role assignment/removal requires `roles:assign` and every permission represented
by the selected role. Workspace roles remain workspace-bound and cannot make an
owner into a member. Role changes and status/session changes use atomic audit and
event/outbox transactions. Removing a workspace role does not remove workspace
membership; remove membership separately when that is intended. DELETE mutation
requests include a JSON body with an audit `reason`.

Control invitation resend retains its existing optional version-header behavior;
application-user and machine invitation changes require explicit versions.

Third-party APIs verifying ordinary JWTs offline still
observe revocation or permission changes only at their normal token expiry.

This release intentionally tightens invitation authentication: pending invitations
remain valid, but invitation-only session issuance is removed. Headless consumers
must add the independent recipient-authentication step; the hosted flow prompts
for it. Machine/application invitation mutations also require reasons, explicit
versions where applicable, and idempotency keys; update SDK call sites accordingly.
No production data import, provider changes, or legacy UUID adoption is involved.
