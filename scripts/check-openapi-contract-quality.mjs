import { readFileSync } from "node:fs";
import yaml from "js-yaml";

const document = yaml.load(readFileSync("api/openapi/platform93.yaml", "utf8"));
const methods = new Set(["get", "post", "put", "patch", "delete", "options", "head"]);
const operationIDs = new Set();
const problems = [];

for (const [path, pathItem] of Object.entries(document.paths ?? {})) {
  for (const [method, operation] of Object.entries(pathItem ?? {})) {
    if (!methods.has(method) || !operation) continue;
    const label = `${method.toUpperCase()} ${path}`;
    const operationID = operation.operationId;
    if (!operationID) problems.push(`${label}: missing operationId`);
    else if (operationIDs.has(operationID)) problems.push(`${label}: duplicate operationId ${operationID}`);
    else operationIDs.add(operationID);

    const requestRef = operation.requestBody?.$ref;
    if (requestRef === "#/components/requestBodies/Object") {
      problems.push(`${label}: generic Object request body is forbidden`);
    }
    const requestSchema = operation.requestBody?.content?.["application/json"]?.schema;
    if (requestSchema?.type === "object" && !requestSchema.$ref) {
      problems.push(`${label}: inline object request body must be a named schema`);
    }

    for (const [status, response] of Object.entries(operation.responses ?? {})) {
      if (!/^2\d\d$/.test(status) || status === "204" || response?.$ref) continue;
      const schema = response?.content?.["application/json"]?.schema;
      if (!schema) problems.push(`${label}: ${status} response must define an application/json schema`);
      else if (schema.$ref === "#/components/schemas/Page") problems.push(`${label}: generic Page response is forbidden`);
      else if (schema.type === "object" && !schema.$ref) problems.push(`${label}: ${status} response must use a named schema`);
    }
  }
}

if (document.components?.requestBodies?.Object) {
  problems.push("components.requestBodies.Object must be removed");
}

for (const [name, schema] of Object.entries(document.components?.schemas ?? {})) {
  if (schema?.type === "object" && schema.additionalProperties !== false) {
    problems.push(`components.schemas.${name} must explicitly reject unknown top-level properties`);
  }
}

if (problems.length) {
  console.error(problems.join("\n"));
  console.error(`OpenAPI contract quality failed with ${problems.length} problem(s).`);
  process.exit(1);
}

console.log(`Validated ${operationIDs.size} strongly typed OpenAPI operations.`);
