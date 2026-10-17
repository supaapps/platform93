# Optional Creation Values and Errors

Creation APIs normalize omitted or JSON-null optional OAuth client arrays to
`[]`, and optional feature/product metadata, price checkout configuration, user
custom attributes, and notification-template variable schemas to `{}`. Supplied
values are preserved. This creation defaulting does not change PATCH behavior:
omitted fields still preserve existing values.

For Checkout, omitted, null, or empty payment methods use the price's configured
methods. If that policy does not specify methods, Platform93 stores `[]` and
omits Stripe's `payment_method_types` fields, leaving selection to Stripe.
It does not silently force cards. Explicit card/TWINT rules remain unchanged.

Expected uniqueness conflicts return HTTP 409. Unexpected database, event, or
transaction failures return a redacted HTTP 500, not a misleading duplicate-key
message. Invalid user input and catalog feature references return HTTP 422.
Organization limits retain their existing 409 responses. Applications should
inspect the HTTP status as well as the RFC 9457 problem code.

In particular, an existing price key now returns `409 price_conflict` rather
than the former generic `price_creation_failed`. The latter code is used for
unexpected creation failures with HTTP 500. Concurrent template-version
creation returns `409 notification_template_version_conflict` rather than the
generic creation-failed code. These are corrections to previously overbroad
conflict responses; callers matching the older codes should update accordingly.

Migration 00006 repairs existing JSON-null values in the five object columns
without changing supplied objects. Its Down migration intentionally retains
repaired values because an intentional empty object cannot be distinguished
from a corrected one. Released migration history is not rewritten.
