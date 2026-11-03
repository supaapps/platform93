import assert from "node:assert/strict";
import test from "node:test";
import { Platform93MachineClient } from "../dist/index.js";

test("machine client caches tokens and invalidates after secret rotation", async () => {
  let tokenRequests = 0;
  const fetch = async (input, init = {}) => {
    const url = String(input);
    if (url.endsWith("/oidc/token")) {
      tokenRequests += 1;
      assert.match(String(init.headers.Authorization), /^Basic /);
      return Response.json({ access_token: "machine-token", expires_in: 300 });
    }
    assert.equal(init.headers.Authorization, "Bearer machine-token");
    return Response.json({ items: [], next_cursor: null });
  };
  const client = new Platform93MachineClient({ baseUrl: "https://platform93.example", applicationId: "app", clientId: "client", clientSecret: "secret", fetch });
  await client.listUsers();
  await client.listUsers();
  assert.equal(tokenRequests, 1);
  client.updateSecret("rotated");
  await client.listUsers();
  assert.equal(tokenRequests, 2);
});

test("machine billing summary and cancellation preserve typed data and idempotency", async () => {
  const fetch = async (input, init = {}) => {
    const url = String(input);
    if (url.endsWith("/oidc/token")) return Response.json({ access_token: "machine-token", expires_in: 300 });
    assert.equal(init.headers.Authorization, "Bearer machine-token");
    if (url.endsWith("/billing/cancel")) {
      assert.equal(init.headers["Idempotency-Key"], "cancel-fixture-key");
      assert.deepEqual(JSON.parse(init.body), { at_period_end: false });
      assert.equal(url, "https://platform93.example/v1/applications/app/subjects/workspace/workspace/billing/cancel");
      return new Response(null, { status: 204 });
    }
    return Response.json({ subject_type: "workspace", subject_id: "workspace", billing_profile: { id: "profile", subject_type: "workspace", subject_id: "workspace", version: 1 }, subscriptions: [{ id: "subscription", provider_subscription_id: "sub_fixture", past_due_since: "2026-10-01T00:00:00Z" }] });
  };
  const client = new Platform93MachineClient({ baseUrl: "https://platform93.example", applicationId: "app", clientId: "client", clientSecret: "secret", fetch });
  const summary = await client.getBilling("workspace", "workspace");
  assert.equal(summary.subscriptions[0].provider_subscription_id, "sub_fixture");
  assert.equal(summary.subscriptions[0].past_due_since, "2026-10-01T00:00:00Z");
  assert.equal(await client.cancelWorkspaceBilling("workspace", "cancel-fixture-key", false), undefined);
});
