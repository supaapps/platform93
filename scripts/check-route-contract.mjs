import { readFileSync } from "node:fs";

const server = readFileSync("internal/httpapi/server.go", "utf8");
const specification = readFileSync("api/openapi/platform93.yaml", "utf8");
const mounted = new Set();
const routePattern = /r(?:\.With\([^\n]*?\))?\.(Get|Post|Put|Patch|Delete)\("([^"]+)"/g;
for (const match of server.matchAll(routePattern)) {
  let path = match[2];
  if (!path.startsWith("/")) continue;
  if (/^\/(setup|control|management|applications|auth)(\/|$)/.test(path)) {
    path = `/v1${path}`;
  }
  mounted.add(`${match[1].toUpperCase()} ${path}`);
}

const documented = new Set();
let currentPath = "";
for (const line of specification.split("\n")) {
  const path = line.match(/^  (\/[^:]+):\s*$/);
  if (path) {
    currentPath = path[1];
    continue;
  }
  const method = line.match(/^    (get|post|put|patch|delete):/);
  if (currentPath && method) {
    documented.add(`${method[1].toUpperCase()} ${currentPath}`);
  }
}

const missing = [...mounted].filter((route) => !documented.has(route)).sort();
const stale = [...documented].filter((route) => !mounted.has(route)).sort();
if (missing.length || stale.length) {
  if (missing.length) console.error(`Mounted routes missing from OpenAPI:\n${missing.join("\n")}`);
  if (stale.length) console.error(`OpenAPI operations not mounted by the server:\n${stale.join("\n")}`);
  process.exit(1);
}
console.log(`${mounted.size} mounted operations match the OpenAPI contract.`);
