import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFile } from "node:fs/promises";

const schemaPath = new URL("../schemas/events/envelope.schema.json", import.meta.url);
const schema = JSON.parse(await readFile(schemaPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });

addFormats(ajv);
ajv.compile(schema);
console.log("Event envelope schema is valid JSON Schema 2020-12.");
