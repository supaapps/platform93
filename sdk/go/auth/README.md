# Platform93 Server Authorization

`Verifier.Verify` validates ordinary application JWTs and deliberately rejects
`resource_access` tokens. Resource backends instead use `ResourceAuthorizer`:

```go
authorizer := auth.ResourceAuthorizer{
    Verifier: verifier,
    Resource: "https://resource.example/api",
    MachineClient: machineClient,
}
claims, err := authorizer.Authorize(ctx, bearerToken, "documents:read", workspaceID)
```

Use an empty workspace ID for personal access. `machineClient` is a
`sdk/go/client.Client` granted the application's `resource_access:check` permission.
Every successful call includes local JWT validation and a fresh live check. Denial,
malformed decisions, and service failures return errors, never authorized claims.
There is no offline fallback or positive decision cache. Resource JWTs are limited
to 16 KiB.

`ResourceMetadata` builds protected-resource discovery metadata with canonical
capability scopes. `ResourceChallenge` validates and escapes a `WWW-Authenticate`
value. Both reject non-HTTPS, query-bearing, or fragment-bearing resource URIs.
