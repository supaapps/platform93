# supaapps/platform93

Framework-neutral Platform93 JWT and webhook verification, an optional Laravel
guard, and a backend-only `MachineClient` for application service APIs.

The machine client exchanges OAuth client credentials and caches the short-lived
token. It supports template notifications, invitations, user/workspace reads,
entitlements, billing summaries, and custom events. Store its client secret in the
backend secret manager; never include it in a browser bundle, URL, or log.

## Protected Resources

Ordinary `Verifier::verify` rejects resource tokens. A resource backend instead calls
`$verifier->authorizeResource($token, $resource, $capability, $machineClient, $workspaceId)`.
Use a configured HTTPS resource URI and a relative capability such as
`documents:read`; omit the workspace argument for personal access. The machine
client needs the application's `resource_access:check` permission.

Every call verifies locally and performs a fresh live check. Denial, malformed
decisions, and service failures throw; there is no signature-only fallback or
positive decision cache. Resource JWTs are limited to 16 KiB.

`ResourceAuthorization::metadata($resource, $issuer, $applicationId, $capabilities)`
builds discovery metadata. `ResourceAuthorization::challenge($metadataUri, $error,
$description)` builds a validated and escaped `WWW-Authenticate` value.
