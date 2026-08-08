import { readFileSync, writeFileSync } from "node:fs";

const sourcePath = "api/openapi/platform93.yaml";
const outputPath = "api/openapi/platform93.openapi30.yaml";
const source = readFileSync(sourcePath, "utf8");
const projected = source
  .replace("openapi: 3.1.0", "# Generated from platform93.yaml; do not edit.\nopenapi: 3.0.3")
  .replaceAll('type: [string, "null"]', "type: string, nullable: true")
  .replaceAll('type: [object, "null"]', "type: object, nullable: true")
  .replaceAll('type: [integer, "null"]', "type: integer, nullable: true")
  .replace(/const: ([^ }]+)/g, "enum: [$1]");
writeFileSync(outputPath, projected);
