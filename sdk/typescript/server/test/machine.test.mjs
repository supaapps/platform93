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
