import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { parseArgs, promisify } from "node:util";

const execute = promisify(execFile);
export const npmPackages = ["sdk", "auth", "expo", "react", "server", "events"]
  .map((name) => `@supaapps/platform93-${name}`);
const npmRegistry = "https://registry.npmjs.org";
const requestTimeoutMs = 15_000;

export class PendingPublication extends Error {
  constructor(message, retryAfterMs = 0) {
    super(message);
    this.retryAfterMs = retryAfterMs;
  }
}

export function validateManifest(entries, version) {
  if (!Array.isArray(entries) || entries.length !== npmPackages.length) {
    throw new Error("The npm manifest must contain all six release packages.");
  }
  const names = new Set();
  for (const entry of entries) {
    if (!npmPackages.includes(entry?.name) || names.has(entry.name)
      || entry.version !== version || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity)) {
      throw new Error("The npm release manifest has an unexpected package, version or integrity.");
    }
    names.add(entry.name);
  }
  return entries;
}

// One deadline covers all probes and retries, not ten minutes per package.
export async function waitForReadiness(probes, {
  timeoutMs = 600_000,
  now = () => performance.now(),
  pause = sleep,
  log = console.log,
} = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 600_000 || probes.length === 0) {
    throw new Error("Readiness requires probes and a deadline of at most ten minutes.");
  }
  const deadline = now() + timeoutMs;
  const pending = new Map(probes.map((probe) => [probe.label, { probe, reason: "not checked" }]));
  if (pending.size !== probes.length) throw new Error("Readiness probe labels must be unique.");
  let round = 0;
  while (pending.size > 0) {
    let retryAfterMs = 0;
    for (const [label, item] of pending) {
      const remaining = deadline - now();
      if (remaining <= 0) break;
      try {
        await item.probe.check({ timeoutMs: Math.min(requestTimeoutMs, remaining) });
        if (now() >= deadline) break;
        pending.delete(label);
        log(`Ready: ${label}`);
      } catch (error) {
        if (!(error instanceof PendingPublication)) throw error;
        item.reason = error.message;
        retryAfterMs = Math.max(retryAfterMs, error.retryAfterMs || 0);
        log(`Pending: ${label}: ${item.reason}`);
      }
    }
    if (pending.size === 0) return;
    const remaining = deadline - now();
    if (remaining <= 0) {
      throw new Error(`Release readiness timed out: ${[...pending].map(([label, item]) => `${label} (${item.reason})`).join("; ")}`);
    }
    const backoff = [2_000, 5_000, 10_000, 20_000, 30_000][Math.min(round++, 4)];
    await pause(Math.min(Math.max(backoff, retryAfterMs), remaining));
  }
}

async function withResponse(url, timeoutMs, fetcher, consume) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetcher(url, {
      signal: controller.signal,
      redirect: "error",
      cache: "no-store",
      headers: { "Cache-Control": "no-cache" },
    });
    if (!response.ok) {
      await response.body?.cancel();
      if ([404, 408, 425, 429].includes(response.status) || response.status >= 500) {
        const header = response.headers.get("Retry-After");
        const retryAfterMs = header === null ? 0 : /^\d+$/.test(header)
          ? Number(header) * 1_000 : Math.max(0, Date.parse(header) - Date.now()) || 0;
        throw new PendingPublication(`registry HTTP ${response.status}`, retryAfterMs);
      }
      throw new Error(`Registry access failed with HTTP ${response.status}.`);
    }
    return await consume(response);
  } catch (error) {
    if (controller.signal.aborted || error instanceof TypeError) {
      throw new PendingPublication("registry request timed out or failed to connect");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function readJSON(response) {
  if (!response.body) throw new Error("Registry metadata body is missing.");
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 1_048_576) throw new Error("Registry metadata exceeds the size limit.");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export function npmProbe(entry, fetcher = fetch) {
  return {
    label: `npm ${entry.name}@${entry.version}`,
    async check({ timeoutMs }) {
      const start = performance.now();
      const metadata = await withResponse(`${npmRegistry}/${encodeURIComponent(entry.name)}/${encodeURIComponent(entry.version)}`, timeoutMs, fetcher, readJSON);
      if (metadata.name !== entry.name || metadata.version !== entry.version || metadata.dist?.integrity !== entry.integrity) {
        throw new Error(`Published npm metadata/integrity does not match ${entry.name}@${entry.version}.`);
      }
      const tarball = new URL(metadata.dist.tarball);
      if (tarball.origin !== npmRegistry || tarball.username || tarball.password || tarball.search || tarball.hash) {
        throw new Error(`Unexpected npm tarball location for ${entry.name}.`);
      }
      const remaining = timeoutMs - (performance.now() - start);
      if (remaining <= 0) throw new PendingPublication("registry request timed out");
      await withResponse(tarball.href, remaining, fetcher, async (response) => {
        const hash = createHash("sha512");
        let size = 0;
        for await (const chunk of response.body) {
          size += chunk.length;
          if (size > 67_108_864) throw new Error(`npm tarball exceeds the size limit for ${entry.name}.`);
          hash.update(chunk);
        }
        if (`sha512-${hash.digest("base64")}` !== entry.integrity) {
          throw new Error(`Downloaded npm tarball integrity does not match ${entry.name}@${entry.version}.`);
        }
      });
    },
  };
}

export function pypiProbe(name, version, fetcher = fetch) {
  return {
    label: `PyPI ${name}@${version}`,
    async check({ timeoutMs }) {
      const metadata = await withResponse(`https://pypi.org/pypi/${name}/${encodeURIComponent(version)}/json`, timeoutMs, fetcher, readJSON);
      if (metadata.info?.name !== name || metadata.info?.version !== version) {
        throw new Error(`Published PyPI metadata does not match ${name}@${version}.`);
      }
      if (!Array.isArray(metadata.urls) || metadata.urls.length === 0) {
        throw new PendingPublication("distribution files are not yet listed");
      }
    },
  };
}

export function commandProbe(label, command, args, validate, run = execute) {
  return {
    label,
    async check({ timeoutMs }) {
      let result;
      try {
        result = await run(command, args, { timeout: Math.max(1, Math.floor(timeoutMs)), killSignal: "SIGKILL", maxBuffer: 1_048_576 });
      } catch (error) {
        const detail = String(error.stderr ?? "");
        if (/\b(401|403)\b|unauthorized|forbidden|access denied|permission denied/i.test(detail) || error.code === "ENOENT") {
          throw new Error(`${label}: registry authorization failed or required command is unavailable.`);
        }
        if (error.killed || error.code === "ETIMEDOUT"
          || /\b(404|408|425|429|5\d\d)\b|manifest_unknown|not found|too many requests|connection (reset|refused)|timed? out|temporary failure|no such host|network is unreachable/i.test(detail)) {
          throw new PendingPublication("registry artifact is unavailable or the request failed temporarily");
        }
        // Never expose raw CLI output, which could include registry credentials.
        throw new Error(`${label}: registry command failed (exit ${error.code ?? "unknown"}).`);
      }
      validate(result.stdout);
    },
  };
}

export function registryProbes(manifest, version, pythonVersion, { fetcher = fetch, run = execute } = {}) {
  validateManifest(manifest, version);
  return [
    ...manifest.map((entry) => npmProbe(entry, fetcher)),
    ...["supaapps-platform93-auth", "supaapps-platform93-webhooks"].map((name) => pypiProbe(name, pythonVersion, fetcher)),
    commandProbe(`Helm platform93@${version}`, "helm", ["show", "chart", "oci://ghcr.io/supaapps/charts/platform93", "--version", version], (output) => {
      const field = (name) => output.match(new RegExp(`^${name}:\\s*["']?([^"'\\s]+)["']?\\s*$`, "m"))?.[1];
      if (field("name") !== "platform93" || field("version") !== version || field("appVersion") !== version) {
        throw new Error("Published Helm chart does not match the release version.");
      }
    }, run),
    commandProbe(`OCI platform93@${version}`, "crane", ["manifest", `ghcr.io/supaapps/platform93:${version}`], (output) => {
      const manifest = JSON.parse(output);
      if (!Array.isArray(manifest.manifests) || manifest.manifests.length === 0) {
        throw new Error("Published OCI image index is missing platform manifests.");
      }
    }, run),
  ];
}

async function main() {
  const { values } = parseArgs({ options: {
    version: { type: "string" },
    "python-version": { type: "string" },
    "npm-manifest": { type: "string" },
    "timeout-seconds": { type: "string", default: "600" },
  } });
  const version = values.version;
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version ?? "") || !values["python-version"] || !values["npm-manifest"]) {
    throw new Error("Provide --version, --python-version and --npm-manifest for this release.");
  }
  const manifest = (await readFile(values["npm-manifest"], "utf8")).trim().split("\n").map((line) => JSON.parse(line));
  await waitForReadiness(registryProbes(manifest, version, values["python-version"]), {
    timeoutMs: Number(values["timeout-seconds"]) * 1_000,
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`Release readiness failed: ${error.message}`);
    process.exitCode = 1;
  });
}
