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

## Manual Access Grants

In the application admin, open **Entitlements**, then **Grant entitlement**.
Search for an active user or workspace, select a product, and optionally select
one of its active prices. IDs are submitted internally; administrators do not
need to copy UUIDs.

A product-only grant starts with the product's current features and configuration.
A price-based grant starts with that immutable price's snapshot. Feature controls
and the JSON-object configuration editor support grant-only overrides and reset
to defaults. Overrides never edit the catalog or another recipient's access.

Choose an expiry date and time, or quick-fill one month, three months, six months,
or one year. Calendar offsets clamp to the final day of the target month. The
form displays local time and submits UTC. Review the recipient, catalog selection,
effective values, and expiry before confirming. This is access without a charge,
Stripe subscription, invoice, or automatic renewal.

API callers retain support for explicit product-free grants and no-expiry grants.
When `feature_values` or `configuration` is omitted, the server snapshots the
selected price's defaults, otherwise the product's defaults, independently for
each omitted map. Supplying a map replaces the corresponding defaults completely;
`{}` explicitly clears that map. Feature keys must be defined in the application
and their values must match the feature types. Supplied expiry must follow the
start time. Existing grants are never changed by later catalog edits.

## Searchable Admin References

Role assignments, direct scopes, workspace owners/members, invitations, and grants
use application-scoped searchable selectors. Role selectors submit role IDs or
keys as required by the existing endpoint; invitation/member roles support multiple
selection. New resource keys, OAuth client identifiers, external provider IDs, and
invitation email addresses remain text fields because they are not references to
existing Platform93 entities.

Control lists for users, workspaces, roles, clients, and products accept `query`,
`limit` (1-100, default 20), and `cursor`. Search is case-insensitive literal text
or an exact UUID and never expands the caller's authorized application boundary.
When search parameters are present, results use ascending UUID order; continue
the same query using `next_cursor` until it is null. Calls without these parameters
retain existing list behavior.

## Provider Metadata

Stripe Checkout Sessions, Subscriptions, and PaymentIntents receive stable
`platform93_application_id`, `platform93_checkout_id`, `platform93_product_id`,
`platform93_price_id`, and subject identifiers. Platform93 does not duplicate the
entitlement JSON into Stripe metadata because it would become mutable, size-limited,
and eventually inconsistent. Applications read effective access from Platform93 or
react to its signed entitlement events.
