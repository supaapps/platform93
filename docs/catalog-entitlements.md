# Catalog And Entitlements

Platform93 authorizes features and limits by stable feature keys, never by product
names. An application first defines each feature as a `boolean`, `quantity`, or
`free_form` value. Free-form features declare a `text`, `csv`, or `json` format so
the administrator and API can validate their values before storing them. Products
then assign default values to those definitions and may include an additional
free-form `entitlement_config` object.

## Snapshot Lifecycle

1. Product feature values and `entitlement_config` are editable defaults.
2. Creating a price without explicit values copies the current product defaults.
3. The price feature values and configuration are immutable commercial terms.
4. Checkout and local entitlement requests use the selected price snapshot.
5. Grants copy that snapshot and `/me/entitlements` returns effective values and
   provenance for the user or explicit workspace.

Changing a product therefore affects only prices created afterward. It never changes
an existing price, subscription, local request, or entitlement grant.

Boolean access is additive: any active grant with `true` enables the feature. Numeric
limits use the maximum active value. Explicit `false` and `0` remain visible when no
active grant provides a stronger value. Free-form features preserve text and CSV as
strings and JSON as its parsed value; their declared format is returned with catalog
feature values.

## Provider Metadata

Stripe Checkout Sessions, Subscriptions, and PaymentIntents receive stable
`platform93_application_id`, `platform93_checkout_id`, `platform93_product_id`,
`platform93_price_id`, and subject identifiers. Platform93 does not duplicate the
entitlement JSON into Stripe metadata because it would become mutable, size-limited,
and eventually inconsistent. Applications read effective access from Platform93 or
react to its signed entitlement events.
