# Recurring Checkout Policy

Recurring prices can opt into `checkout_config.single_subscription` and
`checkout_config.trial_once_per_subject` (both booleans). Apply consistently to
all prices of the same product. Eligibility is scoped to application, product,
and billing subject, not email address or a caller-provided idempotency key.

The admin product detail's immutable-price form accepts a Checkout configuration
JSON object. Set `trial_period_days` and the policy flags before creating each
price; existing prices do not inherit later edits. Tax/address configuration can
be included in the same object. Invalid JSON and non-object values are rejected
before submission.

Eligibility and the pending reservation are committed in one short transaction.
No database connection is held during provider I/O. Conflicting operations return
409 and may be retried. `single_subscription` rejects active, trialing, past-due,
paused, incomplete and unpaid subscriptions for that product. The trial-once flag
alone does not prohibit multiple paid subscriptions. Pending/open checkout and
unresolved completed enrollment block conflicting enrollment until reconciled;
elapsed time alone never proves that a purchase did not complete.
Failed and expired sessions do not consume a trial. Completed trial checkout
or a recorded subscription trial prevents a second trial, including after
cancellation. Subsequent subscriptions omit trial days and charge immediately.

Use `Idempotency-Key` and the same request body when retrying checkout. Platform93
stores its secret-free provider request before sending it and replays the exact
form/provider key after an ambiguous failure. Definitive provider 4xx rejections
are failed attempts, except retryable 408, 409 and 429. Older unknown outcomes
are looked up by customer and checkout correlation rather than replaying a
possibly expired provider idempotency key. If an outcome cannot be established,
checkout fails closed pending administrative reconciliation. Pre-upgrade unknown
requests are never assumed safe to repeat. Recovery may return HTTP 200 instead
of the initial HTTP 201. Failed and expired attempts do not consume trials.

For an unresolved request with no provider session ID, a Platform administrator
must investigate the provider account/customer and checkout correlation first.
If investigation confirms no provider session was created, POST
`/v1/control/applications/{application_id}/billing/checkout-sessions/{session_id}/resolve-not-created`
with `Idempotency-Key` and
`{"confirm_no_provider_session":true,"reason":"Describe the provider investigation"}`.
Only pending attempts older than 25 hours without provider session IDs qualify;
the confirmation, reason and state change are audited atomically. This changes
the attempt to failed, not completed, and creates no payment or entitlement.
Never attest absence from age alone or while a provider purchase may exist.
Automatic POST replay stops at 23 hours as a margin before Stripe may prune a
24-hour idempotency key. Between 23 and 25 hours, an unknown result can remain
blocked pending provider evidence; administrative attestation opens at 25 hours.
This safety interval is intentional, not proof that a provider session exists.
Known sessions must be reconciled/expired normally. Retry any pending subject
cancellation afterwards to clear its temporary checkout block.

The user-facing `POST /v1/applications/{application_id}/billing/subscriptions/{subscription_id}/cancel`
requires an active user session and verifies the subscription's subject. Workspace
billing management is required for workspace subscriptions. The body supports
`at_period_end` (default true); cancellations never revoke independent manual grants.

Machine clients with application `billing:write` can POST
`/v1/applications/{application_id}/subjects/workspace/{workspace_id}/billing/cancel`.
This requires `Idempotency-Key`. Unfinished checkout is reconciled/expired first,
then subscriptions are cancelled or scheduled with stable per-operation keys.
A partial failure temporarily blocks new checkout and can be retried using the
same `at_period_end` value. Successful cancellation removes that temporary block:
an active workspace may subscribe again, without a second consumed trial.
Immediate cancellation is not permanent billing closure or workspace archival.

Archival is separate and rejects unsettled billing with
`409 workspace_billing_unsettled`. Cancel subscriptions and reconcile/expire
unfinished checkout before archiving. Archived workspaces cannot create new
checkout. This guard prevents silent continuing billing; it does not automatically
perform financial cancellation as a side effect of archiving.

The machine subject billing summary returns provider connection/subscription IDs
and `past_due_since`. Signed webhook timestamps anchor observed past-due episodes;
repeated failures preserve the anchor, recovery/cancellation clears it, and older
subscription observations cannot restore stale status. Reconciliation without
historical event timestamps uses its observation time. This timestamp does not
change the immutable price's entitlement/grace policy.

Released migrations 00001-00008 are unchanged. New migrations 00009 (checkout
recovery and temporary cancellation state) and 00010 (subscription observations)
must be applied before the new binary starts. Development databases that used
this PR's earlier conflicting migration numbers must be recreated; those
unreleased revisions are not an upgrade target.
