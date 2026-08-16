import { readFileSync, writeFileSync } from "node:fs";
import yaml from "js-yaml";

const sourcePath = "api/openapi/platform93.yaml";
const outputPath = "api/openapi/platform93.openapi30.yaml";
const document = yaml.load(readFileSync(sourcePath, "utf8"));

function project(value) {
  if (Array.isArray(value)) return value.map(project);
  if (!value || typeof value !== "object") return value;

  const result = Object.fromEntries(Object.entries(value).map(([key, item]) => [key, project(item)]));
  if (Array.isArray(result.type) && result.type.includes("null")) {
    const concreteTypes = result.type.filter((type) => type !== "null");
    if (concreteTypes.length !== 1) throw new Error(`Unsupported nullable type union: ${result.type.join(", ")}`);
    result.type = concreteTypes[0];
    result.nullable = true;
  }
  if (Object.hasOwn(result, "const")) {
    result.enum = [result.const];
    delete result.const;
  }
  return result;
}

const projected = project(document);
projected.openapi = "3.0.3";
writeFileSync(
  outputPath,
  `# Generated from platform93.yaml; do not edit.\n${yaml.dump(projected, { noRefs: true, lineWidth: 160, noCompatMode: true, sortKeys: false })}`,
);
