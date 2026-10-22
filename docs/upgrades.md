# Upgrades

## Passwordless email delivery

Migration 00010 publishes delivery-aware versions of the unchanged English
authentication defaults, preserving their archived versions and all customizations.
For customized/localized templates, wrap optional code and link sections in
`{{#if code}}...{{/if}}` and `{{#if magic_link}}...{{/if}}`, respectively.
Code-only delivery no longer depends on a configured sign-in redirect. Link or
combined delivery without an explicit registered or configured redirect now returns
422 `sign_in_redirect_required` instead of silently sending an empty link. Configure
the application's sign-in flow or pass an allowed `redirect_uri` before requesting
`link` or `both`. See [notification templates](notifications.md).

## Application administration and invitations

The release adding application-user administration requires a forward migration
and an updated invitation client flow. Invitation URLs/codes no longer establish
sessions by themselves; recipients authenticate independently. Existing pending
invitations remain valid, while pre-upgrade invitation-only authorization codes
expire and in-flight provider invitations must restart. Administrative invitation
mutations require audit reasons, idempotency keys and explicit versions as applicable.
See [the administration and onboarding guide](application-user-administration.md).

Compatibility details for this upgrade:

- A credential-bearing account not verified before invitation creation requires
  fresh invitation-bound mailbox proof, including pending invitations. That proof
  atomically resets the old password, identities, MFA/passkeys and recovery codes,
  revokes stored sessions/OAuth credentials/PATs/delegations, invalidates pending
  authentication challenges and then accepts the invitation. Existing sessions
  or a later verification flag cannot authorize recovery. The UUID and application
  data remain unchanged. Established verified accounts keep their credentials.
  Explain this recovery to recipients in headless onboarding; they can configure
  new login methods after completion. Offline JWT integrations still observe old
  access tokens until expiry. No external-provider account deletion is attempted.
  Recovery also revokes OAuth consents and connected-app grants. In-flight login
  attempts are bound to the account's authentication epoch and cannot mint a new
  session or MFA challenge across a committed recovery. Old MFA methods are
  intentionally removed; applications requiring MFA must guide the recipient to
  enroll a new factor after recovery before exposing MFA-protected features.
  Credential-creation requests require a live non-delegated application session;
  personal keys cannot create replacement keys or provider links. A concurrent
  credential reset returns `401 authentication_restarted`; start authentication
  again rather than retrying the old proof or session.
  PAT/delegated/machine credentials receive `403 direct_authentication_required`
  for credential creation rather than a misleading expired-session response.
- Invitation list responses now default to 20 records, ordered by ascending UUID,
  with search, bounded limits and `next_cursor`. Follow pagination rather than
  assuming the response includes every invitation.
- Workspace owners refresh their token after workspace creation before managing
  invitations. Live ownership does not expand the token's original permissions.
- Administrative DELETE calls include a JSON audit `reason`. Application/machine
  invitation mutations require explicit versions where applicable. Control
  resend retains its existing optional version-header behavior.
- Resend uses the shared credential-rotation operation: old invitation codes,
  links and outstanding authentication challenges become invalid. Copy-only
  rotation does not send an email or change the last successful queue timestamp.
- Machine token permission paths already come from persisted role assignments
  and direct grants, not the client's OAuth protocol-scope allowlist alone.
  Invitation administration now also rechecks those grants live, so revocation
  takes effect without waiting for token expiry. Existing machine service-read
  contracts retain their ordinary token checks.
- New idempotency response receipts are encrypted; old plaintext receipts remain
  readable until normal retention cleanup. If encryption fails after a committed
  mutation, a 503 cannot imply rollback. Do not retry with a different key: inspect
  the resource before further action. Such an incomplete receipt cannot recover
  a one-time URL; use explicit invitation rotation if needed after the cooldown.

Platform93 uses forward-only application migrations during normal upgrades. Before an
upgrade, retain a tested PostgreSQL backup, the matching installation master key, the
current image digest, and the current Helm values.

```sh
platform93 backup /backups/pre-upgrade.dump
helm get values platform93 -n platform93 -o yaml > platform93-values.yaml
helm upgrade platform93 oci://ghcr.io/supaapps/charts/platform93 \
  --namespace platform93 --version TARGET_VERSION --reuse-values
kubectl -n platform93 wait --for=condition=complete job/platform93-migrate --timeout=5m
kubectl -n platform93 rollout status deployment/platform93-api
kubectl -n platform93 exec deployment/platform93-api -- /app/platform93 doctor
```

An application rollback is safe only when the target release supports the database
schema left by the newer release. If the release notes do not explicitly say so, restore
the pre-upgrade database backup and deploy the prior image together while all Platform93
processes are stopped.

## Alpha installations

The schemas published before `v0.1.0` are development snapshots and are not migration
targets. Recreate alpha databases, bootstrap a fresh installation, and configure the
required organizations, applications, users, providers, products, and roles again.
Platform93 does not automatically import data from older Supaapps installations and
does not adopt existing Stripe products, prices, customers, or subscriptions.

After `v0.1.0`, `migrations/00001_foundation.sql` is permanent history and must never be
edited or squashed. Every schema change requires a new numbered migration.
