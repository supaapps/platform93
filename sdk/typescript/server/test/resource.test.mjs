import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createResourceAuthorizer, createVerifier, Platform93MachineClient, capabilityScope, protectedResourceMetadata, resourceChallenge } from "../dist/index.js";

const app = "01900000-0000-7000-8000-000000000093";
const id = "01900000-0000-7000-8000-000000000094";
const resource = "https://resource.example/api";
const issuer = "https://issuer.example";
const key = await generateKeyPair("RS256");
const jwk = { ...await exportJWK(key.publicKey), kid: "primary", alg: "RS256", use: "sig" };
const scope = capabilityScope(app, "documents:read");
const fixture = JSON.parse(await readFile(new URL("../../../../conformance/resource-jwt.json", import.meta.url), "utf8"));

async function token(changes = {}, omit = []) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: issuer, exp: now + 300, iat: now, nbf: now - 1, ...fixture.claims, ...changes };
  for (const name of omit) delete claims[name];
  return new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "primary", typ: "JWT" }).sign(key.privateKey);
}

function setup() {
  const state = { checks: 0, exchanges: 0, body: null, response: { allowed: true, reason: "allowed", user_id: id, connection_id: id }, status: 200 };
  const fetch = async (input, init = {}) => {
    if (String(input) === `${issuer}/jwks.json`) return Response.json({ keys: [jwk] });
    if (String(input).endsWith("/oidc/token")) {
      state.exchanges++;
      assert.match(init.headers.Authorization, /^Basic /);
      return Response.json({ access_token: "machine", expires_in: 300 });
    }
    assert.equal(String(input), `${issuer}/v1/applications/${app}/service/resource-access/check`);
    assert.equal(init.method, "POST");
    assert.equal(init.headers.Authorization, "Bearer machine");
    state.checks++;
    state.body = JSON.parse(init.body);
    return Response.json(state.response, { status: state.status });
  };
  const machineClient = new Platform93MachineClient({ baseUrl: issuer, applicationId: app, clientId: "backend", clientSecret: "test", fetch });
  return { state, fetch, authorize: createResourceAuthorizer({ issuer, resource, applicationId: app, machineClient, fetch }) };
}

for (const entry of fixture.cases) test(`shared resource JWT conformance: ${entry.name}`, async () => {
  const { state, authorize } = setup();
  let accepted = true;
  try { await authorize(await token(entry.changes, entry.omit), fixture.capability); } catch { accepted = false; }
  assert.equal(accepted, entry.accept);
  assert.equal(state.checks, entry.accept ? 1 : 0);
});

test("resource authorization uses exact local context and a fresh machine check every time", async () => {
  const { state, authorize } = setup();
  const credential = await token();
  assert.equal((await authorize(credential, "documents:read")).connection_id, id);
  await authorize(credential, "documents:read");
  assert.equal(state.checks, 2);
  assert.equal(state.exchanges, 1);
  assert.deepEqual(state.body, { token: credential, resource, capability: "documents:read" });
  state.response = { allowed: true, reason: "allowed", workspace_id: id };
  await authorize(credential, "documents:read", id);
  assert.equal(state.body.workspace_id, id);
  state.response = { allowed: false, reason: "revoked" };
  await assert.rejects(authorize(credential, "documents:read"));
});

const invalid = {
  application: { application_id: id }, issuer: { iss: resource }, audience: { aud: `${resource}/other` },
  multiple_audiences: { aud: [resource, issuer] }, duplicate_audience: { aud: [resource, resource] },
  machine: { actor_type: "client" }, ordinary: { token_kind: "access" },
  connection: { connection_id: "bad" }, session: { sid: "bad" }, client: { client_id: "" },
  newline_id: { connection_id: `${id}\n` }, newline_client: { client_id: "client\n" },
  roles: { roles: { application: ["member"], workspaces: {} } }, workspace_roles: { roles: { application: [], workspaces: { [id]: [] } } },
  workspace_ids: { workspace_ids: [id] }, workspace_id: { workspace_id: id }, delegated: { act: null },
  empty_scope: { scope: "" }, duplicate_scope: { scope: `${scope} ${scope}` }, injected_scope: { scope: `${scope}\t${scope}` },
  wildcard: { scope: `/applications/${app}/*` }, unknown_protocol: { scope: `${scope} admin` }, only_protocol: { scope: "openid offline_access" }, encoded: { scope: `${scope}%20` },
  role_scope: { scope: `${scope} /applications/${app}/roles/member` },
  newline_scope: { scope: `${scope} /applications/${app}/other/read\n` },
  cross_application: { scope: `/applications/${id}/documents/read` }, workspace_scope: { scope: `${scope} /applications/${app}/workspaces/${id}/read` },
  expired: { exp: 1 }, future: { iat: Math.floor(Date.now() / 1000) + 1000 },
};
for (const [name, changes] of Object.entries(invalid)) test(`local rejection before live request: ${name}`, async () => {
  const { state, authorize } = setup();
  await assert.rejects(authorize(await token(changes), "documents:read"));
  assert.equal(state.checks, 0);
});
for (const claim of ["sub", "sid", "client_id", "connection_id", "roles", "scope", "exp", "iat", "nbf"]) test(`missing ${claim}`, async () => {
  const { state, authorize } = setup();
  await assert.rejects(authorize(await token({}, [claim]), "documents:read"));
  assert.equal(state.checks, 0);
});

test("ordinary verifier still rejects resource token even with resource audience configured", async () => {
  const { fetch } = setup();
  await assert.rejects(createVerifier({ issuer, applicationId: app, audience: resource, fetch })(await token()));
});

test("resource token size is bounded before JWKS or live requests", async () => {
  let requests = 0;
  const authorize = createResourceAuthorizer({ issuer, applicationId: app, resource,
    fetch: async () => { requests++; throw Error("unexpected JWKS request"); },
    machineClient: { checkResourceAccess: async () => { requests++; throw Error("unexpected live check"); } } });
  await assert.rejects(authorize(await token({ padding: "a".repeat(16_384) }), "documents:read"), /16 KiB/);
  assert.equal(requests, 0);
});

test("invalid signatures and protected headers never reach live authorization", async () => {
  const credential = await token();
  const [header, payload, signature] = credential.split(".");
  const wrongSignature = `${header}.${payload}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  const invalid = [wrongSignature];
  for (const changes of [{ alg: "HS256" }, { typ: "other" }, { kid: "unknown" }, { kid: "" }]) {
    invalid.push(`${Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "primary", ...changes })).toString("base64url")}.${payload}.${signature}`);
  }
  for (const value of invalid) {
    const { state, authorize } = setup();
    await assert.rejects(authorize(value, "documents:read"));
    assert.equal(state.checks, 0);
  }
});

test("denial, malformed decisions, HTTP failures and unavailable checks fail closed", async () => {
  const { state, authorize } = setup();
  const credential = await token();
  for (const response of [null, {}, { allowed: "true", reason: "ok" }, { allowed: true }, { allowed: true, reason: null }, { allowed: true, reason: "ok", user_id: app }, { allowed: true, reason: "ok", connection_id: null }, { allowed: true, reason: "ok", workspace_id: id }]) {
    state.response = response;
    await assert.rejects(authorize(credential, "documents:read"));
  }
  state.status = 503;
  await assert.rejects(authorize(credential, "documents:read"));
  const offline = createResourceAuthorizer({ issuer, applicationId: app, resource, fetch: setup().fetch, machineClient: { checkResourceAccess: async () => { throw Error("offline"); } } });
  await assert.rejects(offline(credential, "documents:read"));
});

test("metadata canonicalizes capability keys and challenges escape quoted strings", () => {
  assert.deepEqual(protectedResourceMetadata(resource, issuer, app, ["documents:read", "documents:read"]), { resource, authorization_servers: [issuer], scopes_supported: [scope] });
  assert.equal(resourceChallenge(resource, "invalid_token", 'a"b\\c'), `Bearer resource_metadata="${resource}", error="invalid_token", error_description="a\\"b\\\\c"`);
  for (const uri of ["http://resource.example", "https://user@resource.example", "https://resource.example/#fragment", "https://resource.example/?query=1", "https://resource.example/\r\nInjected"]) assert.throws(() => protectedResourceMetadata(uri, issuer, app, []));
  assert.throws(() => resourceChallenge(resource, "invalid_token", "bad\r\nheader"));
  for (const capability of ["*", "a:*", "a::b", "../read", "a%20b", "a b", "roles:member", "workspaces:read", "read\n:write"]) assert.throws(() => capabilityScope(app, capability));
});
