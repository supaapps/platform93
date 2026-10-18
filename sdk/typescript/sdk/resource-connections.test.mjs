import assert from "node:assert/strict";
import test from "node:test";
import { Platform93Client } from "./dist/index.js";

test("connection helpers use user auth, scoped paths and mandatory If-Match", async () => {
  const calls = [];
  const client = new Platform93Client({ baseUrl: "https://issuer.example", applicationId: "app", accessToken: () => "user-token", fetch: async (url, init) => {
    calls.push({ url, ...init });
    return init.method === "DELETE" ? new Response(null, { status: 204 }) : Response.json({ items: [], next_cursor: null });
  } }).application();
  await client.listConnections();
  await client.getConnection("connection/id");
  await client.revokeConnection("connection/id", '"3"');
  assert.equal(calls[0].url, "https://issuer.example/v1/applications/app/me/connections");
  assert.equal(calls[1].url, "https://issuer.example/v1/applications/app/me/connections/connection%2Fid");
  assert.equal(calls[2].method, "DELETE");
  assert.equal(calls[2].headers["If-Match"], '"3"');
  assert.ok(calls.every(call => call.headers.Authorization === "Bearer user-token"));
  assert.throws(() => client.revokeConnection("id", ""));
  assert.throws(() => client.revokeConnection("id", '"1"\r\nX: injected'));
  assert.equal(calls.length, 3);
});
