# Native mobile authentication

Expo and React Native applications use a dedicated Platform93 public OAuth client.
Register the app's exact callback URI, for example `sampleapp://auth/callback`, in that
client's `redirect_uris` and allow `authorization_code` and `refresh_token`.

Platform93 accepts custom schemes only for public clients. Redirect matching is exact;
there are no scheme, host, or path wildcards. HTTPS remains required for normal web
origins, while HTTP is limited to loopback development addresses. Unsafe schemes such
as `javascript`, `data`, and `file` are rejected.

The application-wide flow configuration may continue to point at the web client. A
native application passes its own client ID and redirect URI to
`createAuthorizationRequest`, or uses `@supaapps/platform93-expo` for Google and Apple:

```ts
import * as SecureStore from "expo-secure-store";
import * as WebBrowser from "expo-web-browser";
import { makeRedirectUri } from "expo-auth-session";
import { Platform93ExpoAuth } from "@supaapps/platform93-expo";

const redirectUri = makeRedirectUri({ scheme: "sampleapp", path: "auth/callback" });
const auth = new Platform93ExpoAuth({
  baseUrl: "https://platform93.example.com",
  applicationId: "019...",
  redirectUri,
  secureStore: SecureStore,
  webBrowser: WebBrowser,
});

await auth.initialize();
await auth.signInWithGoogle({ flow: "automatic" });
```

Google and Apple redirect to Platform93's fixed provider callback first. Platform93
then redirects to the native URI with a short-lived, single-use exchange credential.
The adapter exchanges it immediately and stores only the rotating refresh credential
in SecureStore. No OAuth client secret belongs in the mobile application.

For a direct OIDC authorization-code flow, retain the returned verifier and state:

```ts
const request = await auth.auth.createAuthorizationRequest({
  clientId: "mobile",
  redirectUri,
});
```

The consuming app must also register the custom scheme in its Expo/app configuration.
Production apps should prefer an HTTPS universal/app link when their deployment can
prove domain ownership, because operating systems cannot guarantee exclusive ownership
of arbitrary custom schemes.
