import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  BFFCookieSessionAdapter,
  BrowserSessionAuthorizationStateStore,
  ExternalAuthRecoveryError,
  MemoryAuthorizationStateStore,
  MemoryTokenStore,
  Platform93Auth,
  TokenStoreSessionAdapter,
} from "../dist/index.js";

const tokens = (suffix) => ({ access_token: `access-${suffix}`, refresh_token: `refresh-${suffix}`, token_type: "Bearer", expires_in: 300 });

const googleAuthorization = () => Response.json({ provider: "google", authorize_url: "https://accounts.google.test/authorize", expires_in: 600 }, { status: 201 });
const recoveryAuth = (fetch, authorizationStateStore = new MemoryAuthorizationStateStore(), applicationId = "application", adapter) => new Platform93Auth({
  baseUrl: "https://platform93.test", applicationId, fetch, authorizationStateStore, channelName: false, adapter,
});
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };

test("abandoned invitation provider requests can be cancelled after reload before normal login", async () => {
  const store = new MemoryAuthorizationStateStore();
  const bodies = [];
  const fetch = async (url, init) => { bodies.push([String(url), JSON.parse(init.body)]); return googleAuthorization(); };
  const auth = recoveryAuth(fetch, store);
  const invitation = await auth.startApplicationInvitationProvider("google", { email: "invited@example.test", code: "ABCD2345" });
  const reloaded = recoveryAuth(fetch, store);
  assert.equal(reloaded.pendingExternalAuth("google").requestId, invitation.requestId);
  await assert.rejects(reloaded.startGoogleAuth({ redirectUri: "https://app.test/callback" }), /request in progress/);
  assert.equal(reloaded.cancelExternalAuth("google", invitation.requestId), true);
  assert.equal(reloaded.cancelExternalAuth("google", invitation.requestId), false);
  const normal = await reloaded.startGoogleAuth({ redirectUri: "https://app.test/callback" });
  assert.notEqual(normal.requestId, invitation.requestId);
  assert.notEqual(bodies[0][1].code_challenge, bodies[1][1].code_challenge);
  assert.equal(reloaded.cancelExternalAuth("google", invitation.requestId), false);
  assert.equal(reloaded.pendingExternalAuth("google").requestId, normal.requestId);
});

test("explicit restart gets a fresh PKCE verifier and stale request IDs cannot replace it", async () => {
  const calls = [];
  const auth = recoveryAuth(async (_url, init) => { calls.push(JSON.parse(init.body)); return googleAuthorization(); });
  const first = await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
  const second = await auth.restartExternalAuth("google", { redirectUri: "https://app.test/callback" }, first.requestId);
  assert.notEqual(first.requestId, second.requestId);
  assert.notEqual(calls[0].code_challenge, calls[1].code_challenge);
  assert.throws(() => auth.restartExternalAuth("google", { redirectUri: "https://app.test/callback" }, first.requestId), (error) => error.recovery === "cancelled");
  await assert.rejects(auth.completeExternalAuthRedirect("google", "https://app.test/callback?external_auth_error=access_denied", first.requestId), (error) => error.recovery === "cancelled");
  assert.equal(auth.pendingExternalAuth("google").requestId, second.requestId);
});

for (const outcome of ["success", "failure"]) {
  test(`late start ${outcome} cannot erase or overwrite a restarted request`, async () => {
    const pending = deferred();
    let calls = 0;
    const auth = recoveryAuth(async () => ++calls === 1 ? pending.promise : googleAuthorization());
    const first = auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
    const rejected = assert.rejects(first, (error) => error.recovery === "cancelled");
    const oldID = auth.pendingExternalAuth("google").requestId;
    const second = await auth.restartExternalAuth("google", { redirectUri: "https://app.test/callback" }, oldID);
    if (outcome === "success") pending.resolve(googleAuthorization()); else pending.reject(new TypeError("offline"));
    await rejected;
    assert.equal(auth.pendingExternalAuth("google").requestId, second.requestId);
  });
}

for (const outcome of ["success", "terminal", "network"]) {
  test(`late exchange ${outcome} preserves a newer request and never accepts cancelled tokens`, async () => {
    const pending = deferred();
    const auth = recoveryAuth(async (url) => String(url).endsWith("/exchange") ? pending.promise : googleAuthorization());
    const first = await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
    const exchange = auth.exchangeGoogleAuth("old-exchange");
    const rejected = assert.rejects(exchange, (error) => error instanceof ExternalAuthRecoveryError && error.recovery === "cancelled");
    const second = await auth.restartExternalAuth("google", { redirectUri: "https://app.test/callback" }, first.requestId);
    if (outcome === "success") pending.resolve(Response.json(tokens("old")));
    else if (outcome === "network") pending.reject(new TypeError("offline"));
    else pending.resolve(Response.json({ status: 401, title: "Expired exchange", code: "invalid_exchange" }, { status: 401 }));
    await rejected;
    assert.equal(auth.pendingExternalAuth("google").requestId, second.requestId);
    assert.equal(auth.snapshot().status, "anonymous");
  });
}

for (const status of [400, 401, 403, 404, 409, 422]) {
  test(`terminal exchange HTTP ${status} clears only its own verifier and permits a fresh login`, async () => {
    const auth = recoveryAuth(async (url) => String(url).endsWith("/exchange")
      ? Response.json({ status, title: "Exchange rejected", code: "invalid_exchange" }, { status }) : googleAuthorization());
    await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
    await assert.rejects(auth.exchangeGoogleAuth("expired-or-replayed"), (error) => error.recovery === "restart" && error.cause.problem.status === status);
    assert.equal(auth.pendingExternalAuth("google"), null);
    await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
  });
}

for (const failure of ["network", 408, 429, 500, 503]) {
  test(`retryable exchange ${failure} preserves original PKCE for one-time exchange retry`, async () => {
    let failed = false;
    const verifiers = [];
    const auth = recoveryAuth(async (url, init) => {
      if (!String(url).endsWith("/exchange")) return googleAuthorization();
      verifiers.push(JSON.parse(init.body).code_verifier);
      if (!failed) {
        failed = true;
        if (failure === "network") throw new TypeError("offline");
        return Response.json({ status: failure, title: "Try later", code: "unavailable" }, { status: failure });
      }
      return Response.json(tokens("retried"));
    });
    const start = await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
    await assert.rejects(auth.exchangeGoogleAuth("one-time"), (error) => error.recovery === "retry");
    assert.equal(auth.pendingExternalAuth("google").requestId, start.requestId);
    await auth.exchangeGoogleAuth("one-time");
    assert.equal(verifiers[0], verifiers[1]);
    assert.equal(auth.pendingExternalAuth("google"), null);
    assert.equal(auth.snapshot().status, "authenticated");
  });
}

test("a consumed exchange is not retried when saving the BFF session fails", async () => {
  const auth = recoveryAuth(async (url) => String(url).endsWith("/exchange") ? Response.json(tokens("consumed")) : googleAuthorization(),
    undefined, "application", { accept: async () => { throw new TypeError("BFF offline"); }, clear: async () => {}, refresh: async () => null });
  await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
  await assert.rejects(auth.exchangeGoogleAuth("consumed"), (error) => error.recovery === "restart");
  assert.equal(auth.pendingExternalAuth("google"), null);
  assert.equal(auth.snapshot().status, "anonymous");
});

test("request expiry and application boundaries remain enforced", async (t) => {
  const store = new MemoryAuthorizationStateStore();
  const auth = recoveryAuth(async () => googleAuthorization(), store);
  const other = recoveryAuth(async () => googleAuthorization(), store, "other-application");
  const start = await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
  assert.equal(other.pendingExternalAuth("google"), null);
  assert.equal(other.cancelExternalAuth("google", start.requestId), false);
  await other.startGoogleAuth({ redirectUri: "https://app.test/callback" });
  const now = Date.now();
  t.mock.method(Date, "now", () => now + 601_000);
  assert.equal(auth.pendingExternalAuth("google"), null);
  await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
});

test("successful session storage writes do not resurrect state removed by another instance", () => {
  const storage = new MemoryAuthorizationStateStore();
  const first = new BrowserSessionAuthorizationStateStore(storage);
  const second = new BrowserSessionAuthorizationStateStore(storage);
  first.setItem("state", "value");
  second.removeItem("state");
  assert.equal(first.getItem("state"), null);
});

test("invitation restart and provider cancellation do not affect other providers", async () => {
  const auth = recoveryAuth(async (url) => Response.json({ provider: String(url).includes("apple") ? "apple" : "google", authorize_url: "https://provider.test/authorize", expires_in: 600 }));
  const apple = await auth.startAppleAuth({ redirectUri: "https://app.test/callback" });
  const first = await auth.startApplicationInvitationProvider("google", { email: "invited@example.test", code: "ABCD2345" });
  const next = await auth.restartApplicationInvitationProvider("google", { email: "invited@example.test", code: "ABCD2345" }, first.requestId);
  assert.notEqual(next.requestId, first.requestId);
  auth.cancelExternalAuth("google", next.requestId);
  assert.equal(auth.pendingExternalAuth("apple").requestId, apple.requestId);
});

test("a provider cancellation callback permits starting again", async () => {
  const auth = recoveryAuth(async () => googleAuthorization());
  const start = await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
  await assert.rejects(auth.completeExternalAuthRedirect("google", "https://app.test/callback?external_auth_error=access_denied", start.requestId), (error) => error.recovery === "restart");
  assert.equal(auth.pendingExternalAuth("google"), null);
  await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
});

test("session storage fallback remains usable when browser writes are denied", () => {
  const state = new BrowserSessionAuthorizationStateStore({ getItem: () => null, setItem: () => { throw new Error("denied"); }, removeItem: () => {} });
  state.setItem("state", "value");
  assert.equal(state.getItem("state"), "value");
  state.removeItem("state");
  assert.equal(state.getItem("state"), null);
});

test("email enrollment allows correcting a code and supports explicit cancellation", async () => {
  let attempts = 0;
  const auth = recoveryAuth(async (url) => {
    if (!String(url).endsWith("/auth/external-email/verify")) return Response.json({ provider: "microsoft", authorize_url: "https://provider.test/authorize", expires_in: 600 });
    if (++attempts === 1) return Response.json({ status: 401, code: "invalid_external_email_verification", title: "Invalid code" }, { status: 401 });
    return Response.json(tokens("enrolled"));
  });
  await auth.startMicrosoftAuth({ redirectUri: "https://app.test/callback" });
  const continuation = await auth.completeExternalAuthRedirect("microsoft", "https://app.test/callback?external_auth_email_enrollment=enrollment%3Acredential");
  await assert.rejects(auth.verifyExternalEmailEnrollment(continuation, { code: "WRONG123" }), (error) => error.recovery === "retry");
  await auth.verifyExternalEmailEnrollment(continuation, { code: "ABCD2345" });
  assert.equal(auth.snapshot().status, "authenticated");
  assert.equal(auth.cancelExternalEmailEnrollment(continuation), false);
  await auth.startMicrosoftAuth({ redirectUri: "https://app.test/callback" });
  const second = await auth.completeExternalAuthRedirect("microsoft", "https://app.test/callback?external_auth_email_enrollment=second%3Acredential");
  assert.equal(auth.cancelExternalEmailEnrollment(second), true);
  await assert.rejects(auth.verifyExternalEmailEnrollment(second, { code: "ABCD2345" }), (error) => error.recovery === "restart");
  assert.equal(attempts, 2);
});

test("cancelled email enrollment cannot accept a late successful verification", async () => {
  const pending = deferred();
  const auth = recoveryAuth(async (url) => String(url).endsWith("/auth/external-email/verify") ? pending.promise : Response.json({ provider: "microsoft", authorize_url: "https://provider.test/authorize", expires_in: 600 }));
  await auth.startMicrosoftAuth({ redirectUri: "https://app.test/callback" });
  const continuation = await auth.completeExternalAuthRedirect("microsoft", "https://app.test/callback?external_auth_email_enrollment=enrollment%3Acredential");
  const verification = auth.verifyExternalEmailEnrollment(continuation, { code: "ABCD2345" });
  const rejected = assert.rejects(verification, (error) => error.recovery === "cancelled");
  auth.cancelExternalEmailEnrollment(continuation);
  pending.resolve(Response.json(tokens("cancelled-enrollment")));
  await rejected;
  assert.equal(auth.snapshot().status, "anonymous");
});

test("legacy PKCE records can be cancelled without exposing or extending their verifier", async () => {
  const store = new MemoryAuthorizationStateStore();
  const expiresAt = Date.now() + 60_000;
  store.setItem("platform93.application.pkce.provider.google", JSON.stringify({ verifier: "a".repeat(43), expiresAt }));
  const auth = recoveryAuth(async () => googleAuthorization(), store);
  const pending = auth.pendingExternalAuth("google");
  assert.equal(pending.expiresAt, expiresAt);
  assert.equal("verifier" in pending, false);
  assert.equal(auth.cancelExternalAuth("google", pending.requestId), true);
  await auth.startGoogleAuth({ redirectUri: "https://app.test/callback" });
});

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

test("a malformed provider redirect releases its in-flight PKCE verifier", async () => {
  let starts = 0;
  const fetch = async (input) => {
    if (!String(input).endsWith("/auth/providers/google/start")) throw new Error(`unexpected request ${input}`);
    starts += 1;
    return Response.json({ provider: "google", authorize_url: "https://accounts.google.test/authorize", expires_in: 600 }, { status: 201 });
  };
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", fetch, channelName: false });

  await auth.startGoogleAuth({ redirectUri: "sampleapp://auth/callback" });
  await assert.rejects(
    auth.completeExternalAuthRedirect("google", "sampleapp://auth/callback"),
    /redirect is missing its one-time exchange credential/,
  );
  await auth.startGoogleAuth({ redirectUri: "sampleapp://auth/callback" });

  assert.equal(starts, 2);
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

test("external email link verification requires an explicit URL outside browsers", () => {
  const auth = new Platform93Auth({ baseUrl: "https://platform93.test", applicationId: "application", channelName: false });
  assert.throws(
    () => auth.verifyExternalEmailEnrollmentLink({ kind: "email_verification_required", provider: "microsoft", enrollment: "enrollment-id:credential" }),
    /requires an explicit link URL outside a browser/,
  );
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
