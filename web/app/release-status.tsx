"use client";

import { useEffect, useState } from "react";

const latestReleaseURL = "https://api.github.com/repos/supaapps/platform93/releases/latest";
const releasesURL = "https://github.com/supaapps/platform93/releases";

function parseVersion(value: unknown) {
  if (typeof value !== "string") return null;
  const match = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$/.exec(value);
  return match ? { parts: match.slice(1, 4).map(BigInt), prerelease: match[4] } : null;
}

type ReleaseState = { label: string; kind: "checking" | "current" | "update" | "unknown"; detail?: string; href?: string };

export function ReleaseStatus({ baseUrl }: { baseUrl: string }) {
  const [state, setState] = useState<ReleaseState>({ label: "Checking version…", kind: "checking" });
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    async function check() {
      try {
        // Both endpoints are public. Never send control credentials to GitHub.
        const options = { credentials: "omit" as const, signal: controller.signal, redirect: "error" as const };
        const [versionResponse, releaseResponse] = await Promise.all([
          fetch(`${baseUrl.replace(/\/$/, "")}/version`, options),
          fetch(latestReleaseURL, { ...options, headers: { Accept: "application/vnd.github+json" } }),
        ]);
        if (!versionResponse.ok || !releaseResponse.ok) throw new Error("Version check failed");
        const running = await versionResponse.json();
        const release = await releaseResponse.json();
        const current = parseVersion(running.version);
        const latest = parseVersion(release.tag_name);
        if (!latest || latest.prerelease || release.draft !== false || release.prerelease !== false) throw new Error("Invalid stable release");
        if (!current) {
          if (running.version !== "dev") throw new Error("Invalid running version");
          setState({ label: "Development build", kind: "unknown", href: releasesURL });
          return;
        }
        let comparison = 0;
        for (let i = 0; i < 3; i++) {
          if (current.parts[i] !== latest.parts[i]) {
            comparison = current.parts[i]! < latest.parts[i]! ? -1 : 1;
            break;
          }
        }
        if (comparison === 0 && current.prerelease) comparison = -1;
        const href = `${releasesURL}/tag/${encodeURIComponent(release.tag_name)}`;
        setState({
          label: comparison < 0 ? `Update available (${running.version})` : comparison > 0 ? `Ahead of latest release (${running.version})` : `Latest version (${running.version})`,
          kind: comparison < 0 ? "update" : comparison > 0 ? "unknown" : "current",
          detail: `Running ${running.version} · latest ${release.tag_name}`,
          href,
        });
      } catch {
        if (active) setState({ label: "Version check unavailable", kind: "unknown", href: releasesURL });
      } finally {
        window.clearTimeout(timeout);
      }
    }
    void check();
    return () => { active = false; controller.abort(); window.clearTimeout(timeout); };
  }, [baseUrl]);

  return <div className={`release-status release-status-${state.kind}`} role="status" title={state.detail}>
    <span className="release-status-dot" aria-hidden="true" />
    {state.href ? <a href={state.href} target="_blank" rel="noopener noreferrer">{state.label}</a> : <span>{state.label}</span>}
  </div>;
}
