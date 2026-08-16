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
