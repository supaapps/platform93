# Admin Design System

The admin retains Platform93's dark navigation, light content surfaces and mint
accent. Shared controls use React Aria Components for selection, keyboard
interaction and floating overlays, with local brand styles rather than a second
visual theme.

## Controls

- Use `SelectControl` for a fixed set of choices. Supply a readable `label` and
  preserve the endpoint's actual values. Its native form adapter handles names,
  required fields, disabled fieldsets and form resets.
- Use `ReferencePicker` for existing users, workspaces, roles, clients and
  products. Only selected resources populate submitted identifiers; typed search
  text does not. Lookups remain scoped to the existing authorized APIs.
- Keep overlays outside layout flow. Lists scroll within a bounded floating
  surface; opening a search must not move the form below it.
- Use `Toggle` for binary settings. It preserves native checkbox form values,
  controlled/default checked state and disabled behavior, while exposing the
  accessible `switch` role. Always provide an associated label.
- Keep expiry shortcuts compact beside the date field label: `1m`, `3m`, `6m`,
  `1y`. Accessible names and tooltips describe the full duration. They calculate
  calendar offsets from now; users can still enter an exact date and time.
- Use 44 px field controls, consistent labels and spacing, and visible keyboard
  focus. Keep primary actions labeled. Reuse the existing `IconButton` and
  `ActionGroup` for compact actions.
- Use existing success/error toasts and pending states. Disable mutations while
  requests are pending without collapsing control dimensions.

## Resource Presentation

Lists lead with meaningful resource names or activity summaries, not UUIDs.
`ResourceSummary` renders audit actions, actors, targets and timestamps; role
assignments show roles, recipients and workspace context; grants show catalog
sources, recipients and validity. Billing and delivery records show their
provider references, amounts or delivery status. Full record IDs remain in a
collapsed, selectable disclosure for debugging.

Audit rows distinguish Platform users, application users, machine clients and
system activity. Targets are resolved only within the current application's
authorized catalog. Billing amounts use the currency's minor-unit precision;
delivery rows include attempts, response status and available failure messages.
Invitation rows show recipient, workspace, assigned roles and expiry.

`ResourceLabels` resolves referenced users, workspaces, products and roles only
through existing application-scoped authorized searches. Lookups are deduplicated
and limited to four concurrent requests. Removed or inaccessible references retain
a resource-type/short-ID fallback without hiding the record or emitting a toast.

Organization cards show authoritative policy usage (active applications and
provisioned users). Application cards use the existing statistics API. List hints
describe the currently loaded page and never imply installation-wide totals.
Unavailable counts are labeled unavailable rather than displayed as zero.

## Preview And Verification

The static `/design-system/` page demonstrates selects, searches, multiple
selection, disabled fields, validation, buttons, feedback and table styles. It
uses synthetic local resources and does not send application API requests.

Build the admin and serve `web/out` before running the browser tests. Set
`PLATFORM93_E2E_URL` to that server. To generate a clickable screenshot gallery,
also set `PLATFORM93_DESIGN_GALLERY_DIR` and run `design-review.spec.ts`.

The gallery covers installation, organization and application screens at desktop
and mobile widths, including forms and drawers. API fixtures contain synthetic
records. These screenshots validate rendering, not live provider operations.
Browser checks cover overlay positioning, layout stability, keyboard selection,
form submission and reset, search failures, stale responses and accessibility.
