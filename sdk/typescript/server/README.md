# @supaapps/platform93-server

Strict Node.js verification for Platform93 JWTs and rotating JWKS.

```bash
npm install @supaapps/platform93-server
```

The verifier enforces issuer, audience, actor type, application boundary, and token
expiry rather than only checking the signature.

Application backends can also use `Platform93MachineClient`. It exchanges OAuth
client credentials, caches the short-lived machine token, and exposes typed methods
for notifications, invitations, users, workspaces, entitlements, billing summaries,
and custom events.

```ts
import { Platform93MachineClient } from "@supaapps/platform93-server";

const platform93 = new Platform93MachineClient({
  baseUrl: process.env.PLATFORM93_URL!,
  applicationId: process.env.PLATFORM93_APPLICATION_ID!,
  clientId: process.env.PLATFORM93_CLIENT_ID!,
  clientSecret: process.env.PLATFORM93_CLIENT_SECRET!,
});

await platform93.sendNotification({
  template_key: "account.activity",
  user_id: userId,
  variables: { activity: "report_ready" },
}, crypto.randomUUID());
```

Machine credentials belong only in backend secret storage. Do not import this
client or expose its secret in browser bundles.

## Protected Resources

`createVerifier` deliberately rejects `resource_access` tokens. Use
`createResourceAuthorizer` in a resource backend instead:

```ts
import { createResourceAuthorizer } from "@supaapps/platform93-server";

const authorize = createResourceAuthorizer({
  issuer, applicationId, resource: "https://resource.example/api",
  machineClient: platform93,
});
const claims = await authorize(bearerToken, "documents:read", workspaceId);
```

The machine client needs the application's `resource_access:check` permission.
Every authorization verifies the JWT locally and performs a fresh live check;
denials, malformed responses, and unavailable services throw. There is no offline
fallback or positive decision cache. Omit `workspaceId` for personal access.

`protectedResourceMetadata(resource, issuer, applicationId, capabilities)` builds
discovery metadata with canonical capability scopes. `resourceChallenge(metadataURI,
error?, description?)` builds a validated and escaped `WWW-Authenticate` value.
