import assert from "node:assert/strict";
import test from "node:test";

import { Platform93ExpoAuth, Platform93NativeAuthSessionError } from "../dist/index.js";

const tokens = { access_token: "access", refresh_token: "refresh", token_type: "Bearer", expires_in: 300 };

test("Google login opens an auth session and stores the exchanged refresh token", async () => {
  const values = new Map();
  const secureStore = {
    getItemAsync: async (key) => values.get(key) ?? null,
    setItemAsync: async (key, value) => { values.set(key, value); },
    deleteItemAsync: async (key) => { values.delete(key); },
  };
  const webBrowser = {
    openAuthSessionAsync: async (url, redirectUri) => {
      assert.equal(url, "https://accounts.google.test/authorize");
      assert.equal(redirectUri, "sampleapp://auth/callback");
      return { type: "success", url: "sampleapp://auth/callback?external_auth_exchange=once" };
    },
  };
  const fetch = async (input, init = {}) => {
    if (String(input).endsWith("/auth/providers/google/start")) {
      assert.deepEqual(JSON.parse(init.body), { redirect_uri: "sampleapp://auth/callback", flow: "automatic" });
      return Response.json({ provider: "google", authorize_url: "https://accounts.google.test/authorize", expires_in: 600 }, { status: 201 });
    }
    if (String(input).endsWith("/auth/providers/google/exchange")) return Response.json(tokens);
    throw new Error(`unexpected request ${input}`);
  };
  const auth = new Platform93ExpoAuth({ baseUrl: "https://platform93.test", applicationId: "application", redirectUri: "sampleapp://auth/callback", secureStore, webBrowser, fetch });
  await auth.signInWithGoogle({ flow: "automatic" });
  assert.equal(values.get("platform93.application.refresh_token"), "refresh");
  assert.equal(auth.snapshot().status, "authenticated");
});

test("cancelled native authentication is reported without exchanging credentials", async () => {
  const auth = new Platform93ExpoAuth({
    baseUrl: "https://platform93.test",
    applicationId: "application",
    redirectUri: "sampleapp://auth/callback",
    secureStore: { getItemAsync: async () => null, setItemAsync: async () => {}, deleteItemAsync: async () => {} },
    webBrowser: { openAuthSessionAsync: async () => ({ type: "cancel" }) },
    fetch: async () => Response.json({ provider: "apple", authorize_url: "https://appleid.apple.com/auth/authorize", expires_in: 600 }, { status: 201 }),
  });
  await assert.rejects(() => auth.signInWithApple(), (error) => error instanceof Platform93NativeAuthSessionError && error.resultType === "cancel");
});
