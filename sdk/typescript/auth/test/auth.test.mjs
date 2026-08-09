import assert from "node:assert/strict";
import test from "node:test";

import {
  BFFCookieSessionAdapter,
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
