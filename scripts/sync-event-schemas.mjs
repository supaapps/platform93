import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const destination = resolve(repository, "sdk/typescript/events/schemas");
rmSync(destination, { force: true, recursive: true });
if (process.argv.includes("--clean")) process.exit(0);
mkdirSync(destination, { recursive: true });
cpSync(resolve(repository, "schemas/events"), destination, { recursive: true });
