"use client";

import { useEffect, useState, type FormEvent } from "react";
import type { Platform93Client } from "@supaapps/platform93-sdk";

type SenderApplication = { version: number; internal_config?: { email_sender_name?: string } };

export function ApplicationEmailSender({ api, basePath, onMessage, onError }: {
  api: Platform93Client;
  basePath: string;
  onMessage: (message: string) => void;
  onError: (error: unknown) => void;
}) {
  const [application, setApplication] = useState<SenderApplication | null>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let current = true;
    api.request<SenderApplication>("GET", basePath).then((value) => {
      if (!current) return;
      setApplication(value);
      setName(value.internal_config?.email_sender_name ?? "");
      setError("");
    }).catch(() => { if (current) setError("Could not load the application email sender. Retry before saving."); });
    return () => { current = false; };
  }, [api, basePath, reload]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!application) return;
    setBusy(true);
    setError("");
    try {
      await api.request("PATCH", `${basePath}/internal-config`, { email_sender_name: name }, {
        headers: { "If-Match": `"v${application.version.toString(16)}"` },
      });
      onMessage(name.trim() ? "Application email sender name saved. Shared SMTP settings are unchanged." : "Application email sender name reset to the provider default.");
      setApplication(null);
      setReload((value) => value + 1);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save the email sender name. Reload and try again.");
      onError(failure);
    } finally { setBusy(false); }
  }

  return <section className="provider-configuration" aria-label="Application email sender">
    <h4>Application email sender</h4>
    <p>Override the display name for this app, including inherited SMTP. The sender address and credentials stay with the provider. Leave blank to use the provider name.</p>
    {error && <p role="alert">{error} <button type="button" className="outline" disabled={busy} onClick={() => setReload((value) => value + 1)}>Reload sender settings</button></p>}
    <form onSubmit={(event) => void save(event)}>
      <label>App sender name<input value={name} maxLength={200} placeholder="Use provider default" disabled={!application || busy} onChange={(event) => setName(event.target.value)} /></label>
      <button disabled={!application || busy}>{busy ? "Saving sender name..." : "Save sender name"}</button>
    </form>
  </section>;
}
