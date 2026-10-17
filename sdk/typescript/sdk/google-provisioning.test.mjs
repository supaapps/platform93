import assert from "node:assert/strict";
import test from "node:test";
import { Platform93Client, Platform93Error } from "./dist/index.js";

test("Google provisioning uses the control endpoint and caller's idempotency key", async () => {
  const input = { google_sub: "opaque-sub", reason: "Import", user: { email: "user@example.test" } };
  const result = { user: { id: "user-id" }, identity_id: "identity-id", provider: "google", created_user: true };
  const client = new Platform93Client({
    baseUrl: "https://platform93.test", accessToken: () => "control-token",
    fetch: async (url, init) => {
      assert.equal(url, "https://platform93.test/v1/control/applications/application-id/users/provision-google");
      assert.equal(init.method, "POST");
      assert.equal(init.headers.Authorization, "Bearer control-token");
      assert.equal(init.headers["Idempotency-Key"], "import-record-key");
      assert.deepEqual(JSON.parse(init.body), input);
      return Response.json(result, { status: 201 });
    },
  });
  assert.deepEqual(await client.provisionGoogleUser("application-id", input, "import-record-key"), result);
});

test("Google provisioning preserves structured conflict errors", async () => {
  const problem = { status: 409, code: "google_identity_conflict", title: "Conflict" };
  const client = new Platform93Client({ baseUrl: "https://platform93.test", fetch: async () => Response.json(problem, { status: 409 }) });
  await assert.rejects(client.provisionGoogleUser("application-id", { google_sub: "opaque-sub", reason: "Import", user_id: "user-id" }, "import-record-key"), error => error instanceof Platform93Error && error.problem.code === problem.code);
});
