"use client";

import { useEffect, useState, type CSSProperties, type FormEvent } from "react";
import type { Platform93Client } from "@supaapps/platform93-sdk";

type Branding = {
  display_name?: string; logo_url?: string; favicon_url?: string;
  accent_color?: string; background_color?: string; layout?: "centered" | "split";
  privacy_url?: string; terms_url?: string; support_url?: string; default_locale?: string;
  copy?: Record<string, { heading?: string; help?: string }>;
};
type Settings = { configuration: Branding; effective?: Branding; version: number };

function validateSettings(value: Settings): Settings {
  if (!value || !value.configuration || typeof value.configuration !== "object" || Array.isArray(value.configuration) || !Number.isInteger(value.version) || value.version < 0) {
    throw new Error("Branding settings returned an invalid response. Reload to try again.");
  }
  return value;
}

export function HostedBrandingEditor({ api, basePath, scope, onMessage }: {
  api: Platform93Client; basePath: string; scope: string; onMessage: (message: string) => void;
}) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Branding>({});
  const [copy, setCopy] = useState("{}");
  const [busy, setBusy] = useState(false);
  const [mobile, setMobile] = useState(false);
  const [error, setError] = useState("");
  const [assets, setAssets] = useState<{ id: string; filename: string; public_url: string }[]>([]);
  const path = `${basePath}/auth-branding`;
  useEffect(() => {
    let active = true;
    void api.request<Settings>("GET", path).then((value) => {
      if (!active) return;
      validateSettings(value);
      setSettings(value); setDraft(value.configuration); setCopy(JSON.stringify(value.configuration.copy ?? {}, null, 2)); setError("");
    }).catch((failure: unknown) => { if (active) setError(failure instanceof Error ? failure.message : "Branding could not be loaded."); });
    return () => { active = false; };
  }, [api, path]);

  async function save(reset = false) {
    if (!settings || busy) return;
    setBusy(true); setError("");
    try {
      const localized: unknown = JSON.parse(copy);
      if (!localized || typeof localized !== "object" || Array.isArray(localized)) throw new Error("Localized copy must be a JSON object keyed by language tag.");
      const body = reset ? {} : { ...draft, copy: localized };
      await api.request("PUT", path, body, { headers: { "If-Match": `"v${settings.version.toString(16)}"` } });
      const value = validateSettings(await api.request<Settings>("GET", path));
      setSettings(value); setDraft(value.configuration); setCopy(JSON.stringify(value.configuration.copy ?? {}, null, 2));
      onMessage(reset ? "Hosted branding reset to inherited defaults." : "Hosted authentication branding saved.");
    } catch (failure) { const message = failure instanceof Error ? failure.message : "Branding could not be saved."; setError(message); onMessage(message); }
    finally { setBusy(false); }
  }
  function submit(event: FormEvent) { event.preventDefault(); void save(); }
  const effective = { display_name: "Platform93", accent_color: "#17261f", background_color: "#f6f8fa", ...settings?.effective, ...draft };
  const previewCopy = { ...settings?.effective?.copy };
  try {
    const parsed: unknown = JSON.parse(copy);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      for (const [locale, fields] of Object.entries(parsed)) {
        if (fields && typeof fields === "object" && !Array.isArray(fields)) {
          previewCopy[locale] = { ...previewCopy[locale], ...fields };
        }
      }
    }
  } catch { /* Keep the last valid inherited preview while JSON is being edited. */ }
  const previewLocale = effective.default_locale ?? "en";
  const previewText = previewCopy?.[previewLocale] ?? previewCopy?.en;
  const previewHeading = typeof previewText?.heading === "string" ? previewText.heading : "Sign in";
  const previewHelp = typeof previewText?.help === "string" ? previewText.help : "Continue to your application";
  const inherited = (key: keyof Branding) => draft[key] === undefined ? "Inherited default" : "Local override";
  return <details className="control-scope">
    <summary>Hosted authentication branding</summary>
    <p>Optional application sign-in pages. {scope} overrides do not change email templates or registration policy.</p>
    {error && <p role="alert">{error}</p>}
    {!settings ? !error && <p role="status">Loading branding...</p> : <>
      <form className="detail-form" onSubmit={submit}>
        {scope!=="organization" && <div className="full-field"><button type="button" className="outline" onClick={() => void api.request<{ items: { id: string; filename: string; public_url?: string; status: string }[] }>("GET",`${basePath}/storage/objects`).then((page) => setAssets(page.items.filter((item): item is typeof item & { public_url: string } => item.status==="ready" && !!item.public_url))).catch(() => setError("Managed public assets are unavailable. You can still use external HTTPS image URLs."))}>Browse managed public assets</button>{assets.length>0 && <label>Use managed logo<select defaultValue="" onChange={(event)=>setDraft((value)=>({...value,logo_url:event.target.value||undefined}))}><option value="">Select an image</option>{assets.map((asset)=><option key={asset.id} value={asset.public_url}>{asset.filename}</option>)}</select></label>}</div>}
        {([['display_name', 'Display name'], ['logo_url', 'Logo HTTPS URL'], ['favicon_url', 'Favicon HTTPS URL'], ['accent_color', 'Accent color'], ['background_color', 'Background color'], ['privacy_url', 'Privacy URL'], ['terms_url', 'Terms URL'], ['support_url', 'Support URL'], ['default_locale', 'Default language tag']] as const).map(([key, label]) => <label key={key}><span>{label}</span><input type={key.endsWith("_url") ? "url" : "text"} value={draft[key] ?? ""} placeholder={String(settings.effective?.[key] ?? "Inherited default")} onChange={(event) => setDraft((value) => { const next = { ...value }; if (event.target.value) next[key] = event.target.value; else delete next[key]; return next; })} /><small>{inherited(key)}</small></label>)}
        <label><span>Layout</span><select value={draft.layout ?? ""} onChange={(event) => setDraft((value) => ({ ...value, layout: event.target.value ? event.target.value as Branding["layout"] : undefined }))}><option value="">Inherited default</option><option value="centered">Centered</option><option value="split">Split</option></select></label>
        <label className="full-field"><span>Localized heading and help</span><textarea value={copy} onChange={(event) => setCopy(event.target.value)} placeholder={'{"en":{"heading":"Welcome","help":"Sign in securely."}}'} /><small>Plain text only. Language-tag keys; heading and help fields. Security disclosures cannot be customized.</small></label>
        <button disabled={busy}>{busy ? "Saving..." : "Save branding"}</button>
        <button type="button" className="outline" disabled={busy} onClick={() => { if (window.confirm("Remove local branding overrides?")) void save(true); }}>Reset to inherited defaults</button>
      </form>
      <div className="action-group" role="group" aria-label="Preview viewport"><button type="button" className="outline" onClick={() => setMobile(false)}>Desktop preview</button><button type="button" className="outline" onClick={() => setMobile(true)}>Mobile preview</button></div>
      <div aria-label="Hosted sign-in preview" style={{ background: effective.background_color, color: "#111827", padding: 24, maxWidth: mobile ? 375 : 800, margin: "16px auto", border: "1px solid #cbd5e1" } as CSSProperties}>
        <div style={{ display: "grid", gridTemplateColumns: !mobile && effective.layout === "split" ? "1fr 1fr" : "1fr", gap: 24, alignItems: "center" }}><div>{effective.logo_url?.startsWith("https://") && <img src={effective.logo_url} alt="" referrerPolicy="no-referrer" style={{ maxWidth: 160, maxHeight: 64, objectFit: "contain" }} />}<strong style={{ display: "block" }}>{effective.display_name}</strong><p>{previewHelp}</p></div><section style={{ background: "white", padding: 24, margin: "16px auto", maxWidth: 400, width: "100%" }}><h3>{previewHeading}</h3><p>Continue to your application</p><label>Email<input disabled placeholder="you@example.com" /></label><button type="button" disabled style={{ background: effective.accent_color, color: "white" }}>Continue</button><small>Requested identity information and consent remain visible.</small></section></div>
      </div>
    </>}
  </details>;
}
