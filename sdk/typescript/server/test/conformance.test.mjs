import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createVerifier, hasPermission } from "../dist/index.js";

const fixture = JSON.parse(await readFile(new URL("../../../../conformance/jwt.json", import.meta.url), "utf8"));
const primary = await generateKeyPair("RS256", { modulusLength: 2048 });
const wrong = await generateKeyPair("RS256", { modulusLength: 2048 });
const publicJWK = { ...(await exportJWK(primary.publicKey)), kid: "primary", alg: "RS256", use: "sig" };
const issuer = "https://issuer.platform93.test";
const verify = createVerifier({
  issuer,
  audience: fixture.audience,
  applicationId: fixture.application_id,
  fetch: async () => new Response(JSON.stringify({ keys: [publicJWK] }), { status: 200, headers: { "content-type": "application/json" } }),
});

for (const testCase of fixture.cases) {
  test(`JWT conformance: ${testCase.name}`, async () => {
    const token = await fixtureToken(testCase.mutation);
    let accepted = true;
    try { await verify(token); } catch { accepted = false; }
    assert.equal(accepted, testCase.accept);
  });
}

test("permission matching supports global and namespace wildcards", () => {
  assert.equal(hasPermission({ application_id: fixture.application_id, token_kind: "access", actor_type: "user", scope: "*" }, "/applications/app/billing/refund"), true);
  assert.equal(hasPermission({ application_id: fixture.application_id, token_kind: "access", actor_type: "user", scope: "/applications/app/billing/*" }, "/applications/app/billing/refund"), true);
});

async function fixtureToken(mutation) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: "primary" };
  const claims = { iss: issuer, sub: "user-1", aud: [fixture.audience], exp: now + 300, iat: now, nbf: now - 1,
    application_id: fixture.application_id, token_kind: "access", actor_type: "user", scope: "/applications/app/profile/read" };
  let signingKey = primary.privateKey;
  switch (mutation) {
    case "machine": claims.token_kind = "machine"; claims.actor_type = "client"; break;
    case "delegated": claims.act = { sub: "operator-1", type: "operator" }; break;
    case "wrong_issuer": claims.iss = "https://wrong.example"; break;
    case "wrong_audience": claims.aud = ["wrong-api"]; break;
    case "wrong_application": claims.application_id = "01900000-0000-7000-8000-000000000000"; break;
    case "expired": claims.exp = now - 60; break;
    case "future_nbf": claims.nbf = now + 300; break;
    case "future_iat": claims.iat = now + 300; break;
    case "missing_sub": delete claims.sub; break;
    case "missing_application": delete claims.application_id; break;
    case "missing_token_kind": delete claims.token_kind; break;
    case "missing_actor_type": delete claims.actor_type; break;
    case "operator_actor": claims.actor_type = "operator"; break;
    case "missing_kid": delete header.kid; break;
    case "unknown_kid": header.kid = "unknown"; break;
    case "wrong_signature": signingKey = wrong.privateKey; break;
    case "delegated_wrong_actor_type": claims.act = { sub: "operator-1", type: "user" }; break;
  }
  const token = await new SignJWT(claims).setProtectedHeader(header).sign(signingKey);
  if (mutation !== "wrong_algorithm") return token;
  const parts = token.split(".");
  parts[0] = Buffer.from(JSON.stringify({ ...header, alg: "HS256" })).toString("base64url");
  return parts.join(".");
}
