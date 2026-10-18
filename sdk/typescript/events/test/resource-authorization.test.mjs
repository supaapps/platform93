import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { isKnownPlatform93Event, platform93EventVersions, routePlatform93Event } from "../dist/index.js";

const schemaRoot = new URL("../../../../schemas/events/", import.meta.url);
const readJSON = async (path) => JSON.parse(await readFile(new URL(path, schemaRoot), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateEnvelope = ajv.compile(await readJSON("envelope.schema.json"));

for (const [kind, actions] of [["resource", ["created", "updated"]], ["connection", ["approved", "revoked"]]]) {
  const schema = await readJSON(`${kind}-1.0.schema.json`);
  const validate = ajv.compile(schema);
  for (const action of actions) {
    const type = `${kind}.${action}`;
    test(`${type} v1.0 validates and dispatches its public example`, async () => {
      const event = await readJSON(`examples/${kind}-${action}-1.0.json`);
      assert.equal(event.type, type);
      assert.equal(validateEnvelope(event), true, JSON.stringify(validateEnvelope.errors));
      assert.equal(validate(event.data), true, JSON.stringify(validate.errors));
      assert.equal(isKnownPlatform93Event(event), true);
      assert.equal(platform93EventVersions[type], event.schema_version);
      assert.equal(event.subject, `${kind}/${event.data[`${kind}_id`]}`);
      let received;
      assert.equal(await routePlatform93Event(event, { [type]: (value) => { received = value.data; } }), true);
      assert.deepEqual(received, event.data);
      await assert.rejects(routePlatform93Event({ ...event, schema_version: "2.0" }, {}), /Unsupported/);
    });
  }

  test(`${kind} event data requires identifiers and a positive integer version, without private fields`, () => {
    for (const example of schema.examples) assert.equal(validate(example), true);
    const example = schema.examples[0];
    for (const key of schema.required) {
      const incomplete = { ...example };
      delete incomplete[key];
      assert.equal(validate(incomplete), false);
    }
    for (const version of [0, -1, 1.5, "1"]) assert.equal(validate({ ...example, version }), false);
    for (const key of schema.required.filter((key) => key.endsWith("_id"))) {
      assert.equal(validate({ ...example, [key]: "not-a-uuid" }), false);
    }
    for (const key of ["email", "user_id", "session_id", "client_id", "token", "capabilities", "workspace_ids"]) {
      assert.equal(validate({ ...example, [key]: "private" }), false);
    }
  });
}
