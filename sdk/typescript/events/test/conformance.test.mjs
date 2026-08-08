import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { isKnownPlatform93Event, routePlatform93Event, verifyWebhook } from "../dist/index.js";

test("verifies the shared webhook fixture", async () => {
  const fixture = JSON.parse(await readFile(new URL("../../../../conformance/webhook.json", import.meta.url), "utf8"));
  const event = verifyWebhook(Buffer.from(fixture.raw_body), fixture.signature, fixture.secret, 1_000_000_000);
  assert.equal(event.id, "01900000-0000-7000-8000-000000000001");
  assert.equal(isKnownPlatform93Event(event), true);
  let userID;
  assert.equal(await routePlatform93Event(event, {
    "user.created": (created) => { userID = created.data.user_id; },
  }), true);
  assert.equal(userID, "01900000-0000-7000-8000-000000000002");
});
