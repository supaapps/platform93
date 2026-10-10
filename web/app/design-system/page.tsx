"use client";
import { Toggle } from "../ui/toggle";

import { useState } from "react";
import Link from "next/link";
import { ReferencePicker, type ReferenceRequest } from "../reference-picker";
import { SelectControl } from "../ui/select";

const request: ReferenceRequest = async (path) => {
  await new Promise((resolve) => setTimeout(resolve, 150));
  const query = new URL(path, "https://example.test").searchParams.get("query")?.toLowerCase() ?? "";
  const items = [
    { id: "01900000-0000-7000-8000-000000000001", first_name: "Alex", last_name: "Morgan", email: "alex@example.test", status: "active" },
    { id: "01900000-0000-7000-8000-000000000002", first_name: "Alex", last_name: "River", email: "alex.river@example.test", status: "active" },
    { id: "01900000-0000-7000-8000-000000000003", first_name: "Sam", last_name: "Lee", email: "sam@example.test", status: "active" },
  ].filter((item) => `${item.first_name} ${item.last_name} ${item.email} ${item.id}`.toLowerCase().includes(query));
  return { items, next_cursor: null };
};

export default function DesignSystem() {
  const [type, setType] = useState("user");
  const [selected, setSelected] = useState<string[]>([]);
  const [multiple, setMultiple] = useState<string[]>([]);
  const [disabled, setDisabled] = useState(false);
  const [result, setResult] = useState("");
  return <main className="design-reference">
    <header className="design-reference-header"><Link href="/">p93 / Platform93</Link><span>Component reference</span></header>
    <section className="design-intro"><span className="design-eyebrow">FOUNDATION / 01</span><h1>Calm controls.<br />Clear decisions.</h1><p>The same field rhythm, selection behaviour, and feedback across every boundary.</p></section>
    <section className="design-block"><header><span>01</span><h2>Form controls</h2><p>44px controls. Persistent labels. No shifting overlays.</p></header>
      <form className="create-panel open" onSubmit={(event) => { event.preventDefault(); setResult(JSON.stringify(Object.fromEntries(new FormData(event.currentTarget)))); }}>
        <fieldset disabled={disabled}><div className="create-fields">
          <label>Recipient type<SelectControl label="Recipient type" name="subject_type" value={type} onValueChange={setType}><option value="user">User</option><option value="workspace">Workspace</option></SelectControl></label>
          <ReferencePicker label="Recipient" kind="users" basePath="/demo" request={request} value={selected} onChange={setSelected} name="subject_id" required />
          <label>Plan<SelectControl label="Plan" name="plan" defaultValue="standard"><option value="standard">Standard</option><option value="pro">Professional</option><option value="enterprise" disabled>Enterprise — unavailable</option></SelectControl></label>
          <label>Display name<input name="display_name" placeholder="e.g. Design team" /></label>
          <label>Expires at<input type="datetime-local" name="expires_at" /><small>Europe/Berlin · submitted as UTC by application forms</small></label>
          <label>Description<textarea name="description" placeholder="Optional context for your team" /></label>
        </div><div className="design-action-row"><button className="ui-primary" type="submit">Save changes</button><button type="reset" onClick={() => { setSelected([]); setType("user"); }}>Reset form</button></div></fieldset>
        {result && <p role="status" className="design-notice">Saved demo values: {result}</p>}
      </form>
      <label className="design-disable"><Toggle checked={disabled} onChange={(event) => setDisabled(event.target.checked)} />Preview disabled fieldset</label>
    </section>
    <section className="design-block"><header><span>02</span><h2>Selections & states</h2><p>Readable identities, compact tags, and explicit feedback.</p></header><div className="design-state-grid">
      <div className="design-surface"><ReferencePicker label="Team members" kind="users" basePath="/demo" request={request} multiple value={multiple} onChange={setMultiple} /><p className="design-caption">Multi-selection keeps each identity independently removable.</p></div>
      <div className="design-surface"><label>Unavailable provider<SelectControl label="Unavailable provider" disabled defaultValue="none"><option value="none">Configure a provider first</option></SelectControl></label><label>Invalid value<input aria-invalid="true" defaultValue="not-a-valid-email" aria-describedby="demo-error" /><small id="demo-error" className="design-error">Enter a valid email address.</small></label><form onSubmit={(event) => event.preventDefault()}><label>Required choice<SelectControl label="Required choice" required defaultValue=""><option value="">Choose an option</option><option value="standard">Standard</option></SelectControl></label><button type="submit">Validate choice</button></form></div>
      <div className="design-surface"><div className="design-action-row"><button className="ui-primary">Primary action</button><button>Secondary</button><button className="ui-danger">Archive</button><button disabled>Saving…</button></div><p className="design-notice">Changes saved successfully.</p><p className="design-warning">Update available (0.2.9)</p><p className="design-error">The request could not be completed. Try again.</p></div>
    </div></section>
    <section className="design-block"><header><span>03</span><h2>Data & hierarchy</h2><p>Compact summaries and restrained table actions.</p></header><div className="design-metrics">{[["Users", "128"], ["Workspaces", "24"], ["Active grants", "86"], ["Delivery rate", "99.8%"]].map(([label, number]) => <article key={label}><span>{label}</span><strong>{number}</strong></article>)}</div><div className="table"><div className="table-head"><span>APPLICATIONS</span><span>2 RECORDS</span></div>{["Customer portal", "Team dashboard"].map((name) => <article key={name}><div><strong>{name}</strong><p className="design-caption">Active · public registration</p></div><button aria-label={`Open ${name}`} title={`Open ${name}`}>↗</button></article>)}</div></section>
    <footer>Local demonstration data only. No API credentials or live mutations.</footer>
  </main>;
}
