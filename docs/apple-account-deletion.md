# Apple Account Deletion

Apple authorization-code exchanges retain the returned refresh token encrypted
with identity-bound authenticated encryption. Tokens never appear in user APIs,
identity metadata, logs, or lifecycle webhook payloads.

Identity creation/linking and invitation acceptance retain the token in the same
transaction. Retention failure rolls back onboarding, including invitation
membership, roles, and acceptance events.

Account deletion and anonymization copy each Apple credential to a durable
revocation outbox in the same database transaction as identity removal. The
dedicated revocation worker sends revocation to Apple's fixed HTTPS endpoint with a fresh
client secret, bounded timeout, and no redirects. Failures are retried with
bounded exponential backoff; successful revocation erases the credential.

Unlinking an application user's Apple identity also queues revocation before
removing the identity. Deleting the account afterwards preserves this pending
revocation. Unlinking other providers does not queue Apple revocations.

Older Apple identities without a retained token must sign in with Apple again
before deletion, anonymization, or unlinking; the API returns HTTP 403 with
`apple_reauthentication_required` and leaves the account unchanged. Never mark
these identities revoked merely because a Platform93 session was revoked.

Deploy migration 00003 with both API and worker. Monitor:

```sql
SELECT count(*), max(attempts), min(created_at) FROM apple_token_revocations;
```

Signing credentials are encrypted and snapshotted with each retained token and
copied into the revocation outbox. Provider configuration updates do not change
pending revocation credentials. Keep the original Apple key and Services ID valid
until their retained tokens and pending revocations are gone; revoking keys at
Apple itself cannot be undone by Platform93. Investigate persistent backlog.
Revocations run in a separate River job with at most five requests per batch, so
Apple latency cannot delay invitation or entitlement expiry sweeps.

This implements application-user deletion, not Apple's server-to-server
consent/account notifications or control-user retirement. Those paths remain
separate integration work.

Reference: https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
