# Apple Account Deletion

Apple authorization-code exchanges retain the returned refresh token encrypted
with identity-bound authenticated encryption. Tokens never appear in user APIs,
identity metadata, logs, or lifecycle webhook payloads.

Identity creation/linking and invitation acceptance retain the token in the same
transaction. Retention failure rolls back onboarding, including invitation
membership, roles, and acceptance events.

Account deletion and anonymization copy each Apple credential to a durable
revocation outbox in the same database transaction as identity removal. The
lifecycle worker sends revocation to Apple's fixed HTTPS endpoint with a fresh
client secret, bounded timeout, and no redirects. Failures are retried with
bounded exponential backoff; successful revocation erases the credential.

Unlinking an application user's Apple identity also queues revocation before
removing the identity. Deleting the account afterwards preserves this pending
revocation. Unlinking other providers does not queue Apple revocations.

Older Apple identities without a retained token must sign in with Apple again
before deletion or unlinking; the API returns `apple_reauthentication_required`. Never mark
these identities revoked merely because a Platform93 session was revoked.

Deploy migration 00003 with both API and worker. Monitor:

```sql
SELECT count(*), max(attempts), min(created_at) FROM apple_token_revocations;
```

Investigate persistent backlog or signing-configuration changes. Do not delete
provider configurations while revocations depend on them. Keep the original
Services ID available for revocation after client-ID changes.

This implements application-user deletion, not Apple's server-to-server
consent/account notifications or control-user retirement. Those paths remain
separate integration work.

Reference: https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens
