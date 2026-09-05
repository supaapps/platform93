import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  BFFCookieSessionAdapter,
  MemoryAuthorizationStateStore,
  MemoryTokenStore,
  Platform93Auth,
  TokenStoreSessionAdapter,
} from "../dist/index.js";

const tokens = (suffix) => ({ access_token: `access-${suffix}`, refresh_token: `refresh-${suffix}`, token_type: "Bearer", expires_in: 300 });

test("MFA challenge remains anonymous until verification returns tokens", async () => {
  const calls = [];
  const fetch = async (input, init = {}) => {
    calls.push([String(input), init]);
    if (String(input).endsWith("/auth/password/sign-in")) {
      return Response.json({ mfa_required: true, challenge_id: "challenge", methods: ["totp"], expires_in: 300 }, { status: 202 });
    }
    if (String(input).endsWith("/auth/mfa/verify")) return Response.json(tokens("one"));
    if (String(input).endsWith("/auth/logout")) return new Response(null, { status: 204 });
    throw new Error(`unexpected request ${input}`);
  };
  const store = new MemoryTokenStore();
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false, adapter: new TokenStoreSessionAdapter(store) });
  const challenge = await auth.signIn({ email: "user@example.test", password: "correct horse battery staple" });
  assert.equal(challenge.mfa_required, true);
  assert.equal(auth.snapshot().status, "anonymous");
  await auth.verifyMFA({ challenge_id: "challenge", code: "123456" });
  assert.equal(auth.snapshot().status, "authenticated");
  assert.equal(await store.loadRefreshToken(), "refresh-one");
  await auth.logout();
  assert.equal(auth.snapshot().status, "anonymous");
  assert.equal(await store.loadRefreshToken(), null);
  assert.equal(calls.length, 3);
});

test("BFF adapter keeps refresh handling behind same-origin cookie endpoints", async () => {
  const calls = [];
  const fetch = async (input, init = {}) => {
    calls.push([String(input), init.method]);
    if (String(input) === "/session" && init.method === "POST") return new Response(null, { status: 204 });
    if (String(input) === "/refresh") return Response.json(tokens("two"));
    if (String(input) === "/session" && init.method === "DELETE") return new Response(null, { status: 204 });
    throw new Error(`unexpected request ${input}`);
  };
  const adapter = new BFFCookieSessionAdapter({ fetch, sessionPath: "/session", refreshPath: "/refresh", logoutPath: "/session" });
  await adapter.accept(tokens("one"));
  assert.equal((await adapter.refresh()).access_token, "access-two");
  await adapter.clear();
  assert.deepEqual(calls, [["/session", "POST"], ["/refresh", "POST"], ["/session", "DELETE"]]);
});

test("configured application authorization creates an S256 PKCE request", async () => {
  const fetch = async (input) => {
    assert.equal(String(input), "https://platform93.test/v1/applications/application/public-config");
    return Response.json({
      schema_version: "1.0",
      api_base: "https://platform93.test/v1",
      issuer: "https://platform93.test/oidc",
      application_id: "application",
      auth: { flows: { oauth_client_id: "web", sign_in_redirect_uri: "https://app.test/auth/callback", invitation_redirect_uri: "https://app.test/invitations/accept" } },
    });
  };
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false });
  const request = await auth.createAuthorizationRequest({ state: "fixed-state" });
  const authorization = new URL(request.authorizationUrl);
  assert.equal(authorization.pathname, "/oidc/authorize");
  assert.equal(authorization.searchParams.get("client_id"), "web");
  assert.equal(authorization.searchParams.get("redirect_uri"), "https://app.test/auth/callback");
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.equal(authorization.searchParams.get("state"), "fixed-state");
  assert.match(request.codeVerifier, /^[A-Za-z0-9_-]{43}$/);
  assert.match(authorization.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
});

test("native authorization can select a separately registered public client", async () => {
  const fetch = async () => Response.json({
    issuer: "https://platform93.test/oidc",
    auth: { flows: { oauth_client_id: "web", sign_in_redirect_uri: "https://app.test/auth/callback" } },
  });
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false });
  const request = await auth.createAuthorizationRequest({ clientId: "mobile", redirectUri: "sampleapp://auth/callback" });
  const authorization = new URL(request.authorizationUrl);
  assert.equal(authorization.searchParams.get("client_id"), "mobile");
  assert.equal(authorization.searchParams.get("redirect_uri"), "sampleapp://auth/callback");
});

test("external provider redirects exchange their one-time credential", async () => {
  const calls = [];
  const fetch = async (input, init = {}) => {
    calls.push([String(input), JSON.parse(init.body ?? "{}")]);
    if (String(input).endsWith("/auth/providers/google/start")) {
      return Response.json({ provider: "google", authorize_url: "https://accounts.google.test/authorize", expires_in: 600 }, { status: 201 });
    }
    if (String(input).endsWith("/auth/providers/google/exchange")) return Response.json(tokens("native"));
    throw new Error(`unexpected request ${input}`);
  };
  const authorizationStateStore = new MemoryAuthorizationStateStore();
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false, authorizationStateStore });
  const start = await auth.startGoogleAuth({ redirectUri: "sampleapp://auth/callback", flow: "automatic" });
  assert.equal(start.authorize_url, "https://accounts.google.test/authorize");
  const reloadedAuth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false, authorizationStateStore });
  await reloadedAuth.completeExternalAuthRedirect("google", "sampleapp://auth/callback?external_auth_exchange=exchange-value");
  assert.equal(reloadedAuth.snapshot().status, "authenticated");
  assert.equal(calls[0][1].redirect_uri, "sampleapp://auth/callback");
  assert.equal(calls[0][1].flow, "automatic");
  assert.match(calls[0][1].code_challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(calls[1][1].exchange, "exchange-value");
  assert.match(calls[1][1].code_verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(createHash("sha256").update(calls[1][1].code_verifier).digest("base64url"), calls[0][1].code_challenge);
});

test("external provider exchange fails locally when PKCE state is missing", async () => {
  let calls = 0;
  const auth = new Platform93Auth({
    baseUrl: "https://platform93.test",
    applicationId: "application",
    channelName: false,
    fetch: async () => {
      calls += 1;
      throw new Error("the exchange API must not be called");
    },
  });

  await assert.rejects(
    auth.exchangeExternalAuth("google", "exchange-value"),
    /google authentication is missing its PKCE verifier/,
  );
  assert.equal(calls, 0);
});

test("external provider starts cannot overwrite an in-flight PKCE verifier", async () => {
  let releaseStart;
  const startResponse = new Promise((resolve) => { releaseStart = resolve; });
  const calls = [];
  const fetch = async (input, init = {}) => {
    calls.push([String(input), JSON.parse(init.body ?? "{}")]);
    if (String(input).endsWith("/auth/providers/google/start")) {
      await startResponse;
      return Response.json({ provider: "google", authorize_url: "https://accounts.google.test/authorize", expires_in: 600 }, { status: 201 });
    }
    if (String(input).endsWith("/auth/providers/google/exchange")) return Response.json(tokens("concurrent"));
    throw new Error(`unexpected request ${input}`);
  };
  const authorizationStateStore = new MemoryAuthorizationStateStore();
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false, authorizationStateStore });

  const firstStart = auth.startGoogleAuth({ redirectUri: "sampleapp://auth/callback" });
  await assert.rejects(
    auth.startGoogleAuth({ redirectUri: "sampleapp://auth/callback" }),
    /google authentication already has a request in progress/,
  );
  releaseStart();
  await firstStart;
  await auth.completeExternalAuthRedirect("google", "sampleapp://auth/callback?external_auth_exchange=exchange-value");

  assert.equal(calls.filter(([url]) => url.endsWith("/auth/providers/google/start")).length, 1);
  assert.equal(createHash("sha256").update(calls[1][1].code_verifier).digest("base64url"), calls[0][1].code_challenge);
});

test("untrusted provider signup keeps email completion bound to the original PKCE verifier", async () => {
  const calls = [];
  const authorizationState = new Map();
  const authorizationStateKeys = [];
  const authorizationStateStore = {
    getItem: (key) => authorizationState.get(key) ?? null,
    setItem: (key, value) => {
      authorizationStateKeys.push(key);
      authorizationState.set(key, value);
    },
    removeItem: (key) => authorizationState.delete(key),
  };
  const fetch = async (input, init = {}) => {
    const body = JSON.parse(init.body ?? "{}");
    calls.push([String(input), body]);
    if (String(input).endsWith("/auth/providers/microsoft/start")) {
      return Response.json({ provider: "microsoft", authorize_url: "https://login.microsoftonline.test/authorize", expires_in: 600 }, { status: 201 });
    }
    if (String(input).endsWith("/auth/external-email/start")) {
      return Response.json({ challenge_id: "challenge", provider: "microsoft", expires_in: 600 }, { status: 202 });
    }
    if (String(input).endsWith("/auth/external-email/verify")) return Response.json(tokens("email-complete"));
    throw new Error(`unexpected request ${input}`);
  };
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false, authorizationStateStore });
  await auth.startMicrosoftAuth({ redirectUri: "sampleapp://auth/callback", flow: "sign_up" });
  const callbackAuth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false, authorizationStateStore });
  const continuation = await callbackAuth.completeExternalAuthRedirect("microsoft", "sampleapp://auth/callback?external_auth_email_enrollment=enrollment-id%3Asecret-credential");
  assert.equal(continuation.kind, "email_verification_required");
  assert.equal(authorizationStateKeys.some((key) => key.includes("secret-credential")), false);
  assert.equal(authorizationStateKeys.some((key) => key.endsWith(".enrollment.enrollment-id")), true);
  const enrollmentAuth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false, authorizationStateStore });
  await enrollmentAuth.startExternalEmailEnrollment(continuation, "person@example.test", "code");
  assert.equal(calls[1][1].code_verifier.length, 43);
  assert.equal(createHash("sha256").update(calls[1][1].code_verifier).digest("base64url"), calls[0][1].code_challenge);
  await enrollmentAuth.verifyExternalEmailEnrollment(continuation, { code: "abcd2345" });
  assert.equal(enrollmentAuth.snapshot().status, "authenticated");
  assert.equal(calls[2][1].code, "ABCD2345");
});

test("access token retrieval refreshes only when the current token expires", async () => {
  let refreshes = 0;
  const store = new MemoryTokenStore();
  await store.saveRefreshToken("existing-refresh");
  const fetch = async (input) => {
    if (!String(input).endsWith("/auth/token/refresh")) throw new Error(`unexpected request ${input}`);
    refreshes += 1;
    return Response.json(tokens(`refresh-${refreshes}`));
  };
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false, adapter: new TokenStoreSessionAdapter(store) });
  assert.equal(await auth.getAccessToken(), "access-refresh-1");
  assert.equal(await auth.getAccessToken(), "access-refresh-1");
  assert.equal(refreshes, 1);
});
