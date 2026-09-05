# `@supaapps/platform93-expo`

Expo and React Native authentication support for Platform93. It stores rotating
refresh credentials in Expo SecureStore and completes Google, Apple, Microsoft,
Facebook, or LinkedIn login through an Expo WebBrowser authentication session.

Register the exact native callback URI on a Platform93 **public** OAuth client first.
Custom schemes are never wildcarded.

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

Provider callbacks remain on Platform93. Platform93 redirects the app only with a
short-lived, single-use exchange credential, which the adapter immediately exchanges
for the application session. Microsoft, Facebook, and LinkedIn may instead return an
email-verification continuation when Platform93 cannot trust the provider email claim.
