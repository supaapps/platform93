# Events And Webhooks

Platform93 provides an application-scoped event registry and a transactional event
pipeline. The registry lists built-in platform events and application-defined events,
including their descriptions, schema versions, JSON schemas, occurrence counts, and
last occurrence times. Every registry entry also contains an example subject, example
data, and a complete webhook envelope that can be inspected and copied from the admin.

`schema_version` uses `major.minor`. A major increment means consumers must explicitly
adopt a potentially incompatible data shape. A minor increment is additive and remains
compatible with consumers supporting the same major version. Platform93 event versions
are controlled by releases and snapshotted into each event when it is emitted.

## Custom Events

An organization owner or administrator first registers a custom event type in the
application control plane. Names use lowercase dot-separated segments, for example
`vehicle.created`. Registration requires an object-root JSON Schema, example subject,
and example data that validates against the schema. A custom type must be active before
it can be published or selected as a new webhook filter.

Changing a custom data schema requires a schema-version change. Platform93 rejects
custom publications whose `data` does not validate against the active definition.

Applications publish custom events with a user, personal API key, or OAuth machine
token that has `/applications/{application_id}/events/publish`. Assigning the built-in
`event_publisher` role grants only that permission. Every publication requires an
`Idempotency-Key` header and commits the domain event and outbox record atomically.

```ts
const platform = new Platform93Client({
  baseUrl: "https://platform93.example.com",
  applicationId,
  accessToken: () => machineAccessToken,
});

await platform.application().publishEvent({
  type: "vehicle.created",
  subject: "vehicle/veh_123",
  data: { vehicle_id: "veh_123", make: "Volvo" },
}, "vehicle-created-veh_123");
```

The optional `correlation_id` and `causation_id` fields are UUIDs and are preserved
through storage and delivery.

## Subscriptions And Delivery

The administrator UI loads active registry entries when creating or updating a
webhook. An empty filter list subscribes to every event; otherwise, delivery uses exact
event-type matches. Unknown or misspelled filters are rejected instead of silently
creating a subscription that never receives data.

Deliveries use CloudEvents structured JSON and include the event ID, application
source, type, subject, schema version, actor, correlation and causation IDs, timestamp,
and data. `contract_source` is `platform93` for a built-in typed contract and
`application` for application-defined JSON. Platform93 signs the exact raw body with the endpoint secret and retries
failed delivery through the PostgreSQL-backed worker. Delivery history supports replay.

## Consumer Packages

The TypeScript events package exposes `KnownPlatform93Event`,
`Platform93EventDataMap`, `CustomPlatform93Event`, version checks, and a typed
`routePlatform93Event` dispatcher. Go exposes a structured `Event`, typed data
structures, `VerifyAndDecode`, `DecodeData`, and known-version checks. PHP and Python
expose the same built-in/custom discrimination and major-version guard after signature
verification.

```ts
const event = verifyWebhook(rawBody, signature, endpointSecret);

await routePlatform93Event(event, {
  "user.created": async ({ data }) => provisionProfile(data.user_id),
}, async (custom) => {
  // custom.data is the JSON object defined in this application's registry
  await processApplicationEvent(custom.type, custom.schema_version, custom.data);
});
```
