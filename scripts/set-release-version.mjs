import { readFileSync, writeFileSync } from "node:fs";

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  throw new Error("usage: node scripts/set-release-version.mjs <semver>");
}

const manifests = ["sdk", "auth", "react", "server", "events"].map(
  (name) => `sdk/typescript/${name}/package.json`,
);
for (const path of manifests) {
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  manifest.version = version;
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
}
