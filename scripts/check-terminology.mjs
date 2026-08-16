import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const retiredTerm = ["oper", "ator"].join("");
const files = execFileSync("git", ["ls-files", "-z"])
  .toString("utf8")
  .split("\0")
  .filter(Boolean);
const matches = [];

for (const file of files) {
  if (!existsSync(file)) continue;
  const content = readFileSync(file);
  if (content.includes(0)) continue;
  const lines = content.toString("utf8").split("\n");
  lines.forEach((line, index) => {
    if (line.toLowerCase().includes(retiredTerm)) matches.push(`${file}:${index + 1}:${line.trim()}`);
  });
}

if (matches.length > 0) {
  console.error(`Retired control-plane terminology found:\n${matches.join("\n")}`);
  process.exit(1);
}

console.log(`Checked ${files.length} tracked files for retired control-plane terminology.`);
