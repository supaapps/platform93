import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
  let codeChallenge = "";
  const fetch = async (input, init = {}) => {
    if (String(input).endsWith("/auth/providers/google/start")) {
      const body = JSON.parse(init.body);
      assert.equal(body.redirect_uri, "sampleapp://auth/callback");
      assert.equal(body.flow, "automatic");
      assert.match(body.code_challenge, /^[A-Za-z0-9_-]{43}$/);
      codeChallenge = body.code_challenge;
      return Response.json({ provider: "google", authorize_url: "https://accounts.google.test/authorize", expires_in: 600 }, { status: 201 });
    }
    if (String(input).endsWith("/auth/providers/google/exchange")) {
      const body = JSON.parse(init.body);
      assert.equal(createHash("sha256").update(body.code_verifier).digest("base64url"), codeChallenge);
      return Response.json(tokens);
    }
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
