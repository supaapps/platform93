import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  PendingPublication, commandProbe, npmPackages, npmProbe, pypiProbe,
  registryProbes, validateManifest, waitForReadiness,
} from "./release-readiness.mjs";

const version = "0.5.0-rc.1";
const tarball = Buffer.from("synthetic packaged release bytes");
const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;
const entries = npmPackages.map((name) => ({ name, version, integrity }));
const metadata = (entry = entries[0]) => ({ ...entry, dist: {
  integrity: entry.integrity,
  tarball: `https://registry.npmjs.org/${entry.name}/-/fixture.tgz`,
} });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status });
function clock() {
  let time = 0;
  const sleeps = [];
  return {
    now: () => time,
    pause: async (ms) => { sleeps.push(ms); time += ms; },
    tick: (ms) => { time += ms; },
    sleeps,
    log: () => {},
  };
}

test("late npm metadata becomes ready without publishing again", async () => {
  let requests = 0;
  const probe = npmProbe(entries[0], async (url, options) => {
    assert.equal(options.cache, "no-store");
    assert.equal(options.headers["Cache-Control"], "no-cache");
    assert.equal(options.redirect, "error");
    requests++;
    if (requests <= 2) return json({}, 404);
    return url.endsWith(".tgz") ? new Response(tarball) : json(metadata());
  });
  const time = clock();
  await waitForReadiness([probe], time);
  assert.equal(requests, 4);
  assert.deepEqual(time.sleeps, [2_000, 5_000]);
});

test("metadata visibility alone is not sufficient when tarball is delayed", async () => {
  let tarballRequests = 0;
  const probe = npmProbe(entries[0], async (url) => {
    if (!url.endsWith(".tgz")) return json(metadata());
    return ++tarballRequests === 1 ? json({}, 404) : new Response(tarball);
  });
  await waitForReadiness([probe], clock());
  assert.equal(tarballRequests, 2);
});

test("all probes share one deadline and ready packages are not repeatedly queried", async () => {
  const time = clock();
  const calls = [0, 0, 0];
  await waitForReadiness(calls.map((_, index) => ({
    label: `package ${index}`,
    async check() {
      calls[index]++;
      if (calls[index] <= index) throw new PendingPublication("processing");
    },
  })), time);
  assert.deepEqual(calls, [1, 2, 3]);
  assert.deepEqual(time.sleeps, [2_000, 5_000]);
});

test("deadline bounds retries and identifies each unfinished artifact", async () => {
  const time = clock();
  await assert.rejects(waitForReadiness(["npm", "PyPI"].map((label) => ({
    label,
    async check() { throw new PendingPublication("HTTP 404"); },
  })), { ...time, timeoutMs: 1_000 }), /timed out: npm \(HTTP 404\); PyPI \(HTTP 404\)/);
  assert.equal(time.now(), 1_000);
  assert.deepEqual(time.sleeps, [1_000]);
});

test("slow checks consume the shared deadline, including successful checks", async () => {
  const time = clock();
  const budgets = [];
  await assert.rejects(waitForReadiness([{
    label: "slow",
    async check({ timeoutMs }) { budgets.push(timeoutMs); time.tick(700); throw new PendingPublication("waiting"); },
  }, {
    label: "too late",
    async check({ timeoutMs }) { budgets.push(timeoutMs); time.tick(400); },
  }], { ...time, timeoutMs: 1_000 }), /timed out/);
  assert.deepEqual(budgets, [1_000, 300]);
  assert.deepEqual(time.sleeps, []);
});

test("invalid deadlines and duplicate probe labels fail before checking", async () => {
  const probe = { label: "duplicate", check: () => assert.fail("must not check") };
  for (const timeoutMs of [0, -1, Infinity, NaN, 600_001]) {
    await assert.rejects(waitForReadiness([probe], { timeoutMs }), /deadline/);
  }
  await assert.rejects(waitForReadiness([probe, probe]), /unique/);
  await assert.rejects(waitForReadiness([]), /probes/);
});

test("publication HTTP 404, throttling and server failures are retryable", async () => {
  for (const status of [404, 408, 425, 429, 500, 502, 503]) {
    await assert.rejects(npmProbe(entries[0], async () => json({}, status)).check({ timeoutMs: 1_000 }), PendingPublication);
  }
});

test("authorization and unexpected HTTP errors stop immediately", async () => {
  for (const status of [400, 401, 403]) {
    const time = clock();
    let calls = 0;
    await assert.rejects(waitForReadiness([npmProbe(entries[0], async () => { calls++; return json({}, status); })], time), new RegExp(`HTTP ${status}`));
    assert.equal(calls, 1);
    assert.deepEqual(time.sleeps, []);
  }
});

test("registry Retry-After is respected without extending the total deadline", async () => {
  const time = clock();
  const probe = npmProbe(entries[0], async () => new Response("processing", { status: 429, headers: { "Retry-After": "120" } }));
  await assert.rejects(waitForReadiness([probe], { ...time, timeoutMs: 60_000 }), /timed out/);
  assert.deepEqual(time.sleeps, [60_000]);
});

test("network failures and hanging HTTP requests are bounded and retryable", async () => {
  await assert.rejects(npmProbe(entries[0], async () => { throw new TypeError("fetch failed"); }).check({ timeoutMs: 1_000 }), PendingPublication);
  await assert.rejects(npmProbe(entries[0], async (_, { signal }) => new Promise((_, reject) => {
    signal.addEventListener("abort", () => reject(signal.reason), { once: true });
  })).check({ timeoutMs: 10 }), PendingPublication);
});

test("wrong npm metadata, corrupt tarballs and malformed JSON are terminal", async () => {
  for (const wrong of [
    { ...metadata(), name: "unexpected" },
    { ...metadata(), version: "0.0.1" },
    { ...metadata(), dist: { ...metadata().dist, integrity: "wrong" } },
  ]) {
    await assert.rejects(npmProbe(entries[0], async () => json(wrong)).check({ timeoutMs: 1_000 }), /does not match/);
  }
  await assert.rejects(npmProbe(entries[0], async (url) => url.endsWith(".tgz") ? new Response("corrupted") : json(metadata())).check({ timeoutMs: 1_000 }), /tarball integrity does not match/);
  await assert.rejects(npmProbe(entries[0], async () => new Response("invalid json")).check({ timeoutMs: 1_000 }), SyntaxError);
  await assert.rejects(npmProbe(entries[0], async () => new Response(null)).check({ timeoutMs: 1_000 }), /body is missing/);
});

test("npm integrity mismatch is never retried or treated as temporary", async () => {
  const time = clock();
  await assert.rejects(waitForReadiness([npmProbe(entries[0], async (url) => url.endsWith(".tgz") ? new Response("wrong") : json(metadata()))], time), /integrity does not match/);
  assert.deepEqual(time.sleeps, []);
});

test("unexpected npm tarball origins and URL credentials are not followed", async () => {
  for (const location of ["http://registry.npmjs.org/file.tgz", "https://other.example/file.tgz", "https://user:secret@registry.npmjs.org/file.tgz"]) {
    let requests = 0;
    await assert.rejects(npmProbe(entries[0], async () => {
      requests++;
      return json({ ...metadata(), dist: { ...metadata().dist, tarball: location } });
    }).check({ timeoutMs: 1_000 }), /Unexpected npm tarball location/);
    assert.equal(requests, 1);
  }
});

test("manifest must bind all six packages to their exact version and sha512", () => {
  assert.deepEqual(validateManifest(entries, version), entries);
  for (const value of [[], entries.slice(1), [...entries.slice(1), entries[1]], entries.map((e) => ({ ...e, version: "wrong" })), entries.map((e) => ({ ...e, integrity: "sha512-invalid" })), entries.map((e) => ({ ...e, name: "unknown" }))]) {
    assert.throws(() => validateManifest(value, version), /manifest/);
  }
});

test("PyPI waits for the exact normalized version and distribution files", async () => {
  const name = "supaapps-platform93-auth";
  let calls = 0;
  const probe = pypiProbe(name, "0.5.0rc1", async (url) => {
    assert.ok(url.endsWith("/0.5.0rc1/json"));
    calls++;
    return calls === 1 ? json({}, 404) : json({ info: { name, version: "0.5.0rc1" }, urls: calls === 2 ? [] : [{ filename: "fixture.whl" }] });
  });
  await waitForReadiness([probe], clock());
  assert.equal(calls, 3);
  await assert.rejects(pypiProbe(name, "0.5.0rc1", async () => json({ info: { name, version: "0.5.0" }, urls: [{}] })).check({ timeoutMs: 1_000 }), /does not match/);
});

test("CLI probes retry temporary registry failures but not authorization or missing tools", async () => {
  for (const error of [
    { code: 1, stderr: "404 not found" }, { code: 1, stderr: "MANIFEST_UNKNOWN" },
    { code: 1, stderr: "429 Too Many Requests" }, { code: 1, stderr: "503 Service Unavailable" },
    { code: 1, stderr: "connection reset by peer" }, { killed: true },
  ]) {
    await assert.rejects(commandProbe("fixture", "helm", [], () => {}, async () => { throw error; }).check({ timeoutMs: 1_000 }), PendingPublication);
  }
  for (const error of [{ code: "ENOENT" }, { code: 1, stderr: "403 secret-value" }, { code: 1, stderr: "unauthorized secret-value" }, { code: 1, stderr: "unexpected secret-value" }]) {
    await assert.rejects(commandProbe("fixture", "helm", [], () => {}, async () => { throw error; }).check({ timeoutMs: 1_000 }), (result) => {
      assert.ok(!(result instanceof PendingPublication));
      assert.ok(!result.message.includes("secret-value"));
      return true;
    });
  }
});

test("CLI timeouts receive the remaining budget, capped at fifteen seconds", async () => {
  let options;
  const probe = commandProbe("fixture", "crane", [], () => {}, async (_, __, value) => { options = value; return { stdout: "ready" }; });
  await waitForReadiness([probe], { ...clock(), timeoutMs: 25_000 });
  assert.equal(options.timeout, 15_000);
  assert.equal(options.killSignal, "SIGKILL");
});

test("registry set validates Helm and OCI and never invokes a publishing command", async () => {
  const commands = [];
  const fetcher = async (url) => {
    const target = new URL(url);
    if (target.origin === "https://pypi.org") {
      const name = target.pathname.split("/")[2];
      return json({ info: { name, version: "0.5.0rc1" }, urls: [{}] });
    }
    if (url.endsWith(".tgz")) return new Response(tarball);
    return json(metadata(entries.find((e) => url.includes(encodeURIComponent(e.name)))));
  };
  const run = async (command, args) => {
    commands.push([command, ...args]);
    return { stdout: command === "helm" ? `name: platform93\nversion: ${version}\nappVersion: '${version}'\n` : JSON.stringify({ manifests: [{ digest: "fixture" }] }) };
  };
  const probes = registryProbes(entries, version, "0.5.0rc1", { fetcher, run });
  assert.equal(probes.length, 10);
  await waitForReadiness(probes, clock());
  assert.deepEqual(commands, [
    ["helm", "show", "chart", "oci://ghcr.io/supaapps/charts/platform93", "--version", version],
    ["crane", "manifest", `ghcr.io/supaapps/platform93:${version}`],
  ]);
});

test("wrong chart versions and invalid image manifests cannot finalize", async () => {
  const probes = registryProbes(entries, version, "0.5.0rc1", {
    run: async (command) => ({ stdout: command === "helm" ? "name: platform93\nversion: 0.0.1\nappVersion: 0.0.1\n" : JSON.stringify({ manifests: [] }) }),
  });
  await assert.rejects(probes[8].check({ timeoutMs: 1_000 }), /chart does not match/);
  await assert.rejects(probes[9].check({ timeoutMs: 1_000 }), /missing platform manifests/);
});

test("workflow passes publish integrity to the bounded barrier before finalizing", async () => {
  const workflow = await readFile(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  const finalize = workflow.slice(workflow.indexOf("\n  finalize:"));
  assert.match(finalize, /needs: \[artifacts, image, npm, pypi, helm\]/);
  assert.match(finalize, /timeout-minutes: 15/);
  assert.match(workflow, /name: npm-release-manifest/);
  assert.match(workflow, /if-no-files-found: error/);
  assert.match(finalize, /actions\/download-artifact@v4/);
  assert.ok(finalize.indexOf("node scripts/release-readiness.mjs") < finalize.indexOf("sha256sum --check"));
  assert.ok(finalize.indexOf("sha256sum --check") < finalize.indexOf("gh release edit"));
  assert.ok(!finalize.includes("npm view"));
  assert.ok(!finalize.includes("npm publish"));
});
