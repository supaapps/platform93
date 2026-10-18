# Recurring Checkout Policy

Recurring prices can opt into `checkout_config.single_subscription` and
`checkout_config.trial_once_per_subject` (both booleans). Apply consistently to
all prices of the same product. Eligibility is scoped to application, product,
and billing subject, not email address or a caller-provided idempotency key.

Requests serialize while the provider session is created. An active, trialing,
past-due, paused, or incomplete subscription, or a recent pending/open checkout,
returns `409 subscription_exists`. Checkout sessions may live for 24 hours;
the local pending-record safety window is 25 hours to cover delayed delivery.
Failed and expired sessions do not consume a trial. Completed trial checkout
or a recorded subscription trial prevents a second trial, including after
cancellation. Subsequent subscriptions omit trial days and charge immediately.

The user-facing `POST /v1/applications/{application_id}/billing/subscriptions/{subscription_id}/cancel`
requires an active user session and verifies the subscription's subject. Workspace
billing management is required for workspace subscriptions. The body supports
`at_period_end` (default true); cancellations never revoke independent manual grants.
