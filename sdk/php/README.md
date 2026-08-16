# supaapps/platform93

Framework-neutral Platform93 JWT and webhook verification, an optional Laravel
guard, and a backend-only `MachineClient` for application service APIs.

The machine client exchanges OAuth client credentials and caches the short-lived
token. It supports template notifications, invitations, user/workspace reads,
entitlements, billing summaries, and custom events. Store its client secret in the
backend secret manager; never include it in a browser bundle, URL, or log.
