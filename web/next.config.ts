import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const config: NextConfig = {
  output: "export",
  outputFileTracingRoot: repositoryRoot,
  trailingSlash: true,
  images: { unoptimized: true },
};
export default config;
