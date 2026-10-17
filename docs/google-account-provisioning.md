# Silent Google account provisioning

Installation and organization administrators can provision an application user's
known Google identity without sending an invitation or notification. This is an
administrative trust operation: obtain the Google `sub` from a trustworthy identity
export, not an unverified user submission. Treat the subject as an opaque string;
never derive it from an email address.

## Create a user and identity

Call `POST /v1/control/applications/{application_id}/users/provision-google` with a
Platform user control access token, a unique `Idempotency-Key`, and this JSON body:

```json
{
  "google_sub": "subject-from-trusted-export",
  "reason": "Import an existing application account",
  "user": {
    "email": "person@example.com",
    "first_name": "Alex",
    "locale": "en"
  }
}
```

The `201` response contains `user`, `identity_id`, `provider: "google"`, and
`created_user: true`. Save the returned P93 UUID in your application's mapping.
New users are active, with unverified email and no password, roles, workspace,
or session. Optional profile fields are `first_name`, `last_name`, `username`,
`locale`, and `custom_attributes`. Verification flags cannot be asserted here.

For an existing user, replace `user` with `user_id`. Exactly one is required.
The existing profile is unchanged, and successful linkage returns `200` with
`created_user: false`. Repeating the same linkage is a no-op. Existing users must
be active and belong to the selected application. A different Google identity
already attached to the target is a conflict, not a replacement operation.

Email or identity collisions return `409`; no account is silently selected by
email and no identity is reassigned. Use the explicit existing-user variant after
verifying the intended target. Retry creation with the original idempotency key
and identical body; using the key with different details is rejected. Keys follow
the normal 24-hour idempotency retention policy.

## Next sign-in

The normal Google flow verifies the provider response and resolves the identity
by application, provider, and subject, preserving the provisioned UUID even if
the Google email changes. Linked users can sign in to invite-only applications.
Google must be configured and enabled for the application. State, nonce, PKCE,
MFA, and active-account checks are unchanged. Provisioning does not log anyone in
or bypass provider consent. Unrelated same-email accounts still require explicit
linking.

Only authorized control-plane administrators may call this endpoint. Application
users, application machine clients, PATs, and delegated application sessions
cannot use it. No dashboard or bulk-import workflow is provided.

## Events and messages

The transaction emits `user.created` for a new account and
`user.identity.provisioned` version `1.0` for a new linkage, alongside an audit
record and outbox entries. The provisioning event contains only `user_id`,
`identity_id`, `provider`, and `created_user`, not the Google subject or email.

P93 queues no email or invitation. Existing external subscribers to lifecycle
events may independently send messages; review those automations before importing.
