"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { followRoute, navigate, routeHref, useAdminRoute } from "./navigation";
import { SelectControl } from "./ui/select";
import { Toggle } from "./ui/toggle";
import "./oauth-resources.css";

type Capability = { key: string; name: string; context: "personal" | "workspace"; permissions: string[] };
type Resource = { id: string; application_id: string; uri: string; name: string; enabled: boolean; allow_client_metadata: boolean; client_ids: string[]; capabilities: Capability[]; version: number; created_at: string; updated_at: string };
type Connection = { id: string; application_id: string; resource_id: string; resource_version: number; user_id: string; client_id: string; session_id: string; capabilities: string[]; personal_access: boolean; workspace_ids: string[]; expires_at: string; revoked_at: string | null; version: number; created_at: string; updated_at: string };
type Page<T> = { items: T[]; next_cursor?: string | null };
export type ResourceRequest = <T>(method: "GET" | "POST" | "PATCH" | "DELETE", path: string, body?: unknown, options?: { idempotencyKey?: string; headers?: Record<string, string> }) => Promise<T>;
const versionHeaders = (version: number) => ({ "If-Match": `"v${version.toString(16)}"` });
const split = (value: string) => [...new Set(value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean))];
const relativeSegment = String.raw`[a-z0-9][a-z0-9._\-]{0,63}`;
const relativePermission = `${relativeSegment}(?::${relativeSegment})*`;
const capabilityKey = `(?!roles(?::|$)|workspaces(?::|$))${relativePermission}`;
const message = (error: unknown) => error instanceof Error ? error.message : "Request failed. Reload and try again.";

export function OAuthResources({ applicationID, enabled, request }: { applicationID: string; enabled: boolean; request: ResourceRequest }) {
  const route = useAdminRoute();
  const base = `/v1/control/applications/${encodeURIComponent(applicationID)}/oauth-resources`;
  const [resources, setResources] = useState<Page<Resource>>({ items: [] });
  const [resource, setResource] = useState<Resource | null>(null);
  const [connections, setConnections] = useState<Page<Connection>>({ items: [] });
  const [connection, setConnection] = useState<Connection | null>(null);
  const [creating, setCreating] = useState(false);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const selected = route.id ? `${base}/${encodeURIComponent(route.id)}` : "";
  useEffect(() => {
    let current = true;
    void (async () => {
      await Promise.resolve();
      if (!current) return;
      setLoading(true); setError(""); setResource(null); setConnection(null); setConnections({ items: [] });
      try {
        const list = await request<Page<Resource>>("GET", base);
        if (!current) return;
        setResources(list);
        if (selected) {
          const item = await request<Resource>("GET", selected);
          const links = await request<Page<Connection>>("GET", `${selected}/connections`);
          const link = route.connection_id ? await request<Connection>("GET", `${selected}/connections/${encodeURIComponent(route.connection_id)}`) : null;
          if (current) { setResource(item); setConnections(links); setConnection(link); }
        }
      } catch (failure) { if (current) setError(message(failure)); }
      finally { if (current) setLoading(false); }
    })();
    return () => { current = false; };
  }, [base, selected, route.connection_id, revision, request]);

  async function more(kind: "resources" | "connections") {
    const page = kind === "resources" ? resources : connections;
    if (!page.next_cursor) return;
    setBusy(true); setError("");
    try {
      const path = kind === "resources" ? base : `${selected}/connections`;
      const next = await request<Page<Resource> & Page<Connection>>("GET", `${path}?cursor=${encodeURIComponent(page.next_cursor)}`);
      if (kind === "resources") setResources((old) => ({ ...next, items: [...old.items, ...next.items] }));
      else setConnections((old) => ({ ...next, items: [...old.items, ...next.items] }));
    } catch (failure) { setError(message(failure)); }
    finally { setBusy(false); }
  }

  async function revoke() {
    if (!connection || !confirm("Revoke this resource connection? Its delegated access will stop.")) return;
    setBusy(true); setError("");
    try {
      await request("DELETE", `${selected}/connections/${encodeURIComponent(connection.id)}`, undefined, { headers: versionHeaders(connection.version) });
      setNotice("Resource connection revoked."); setRevision((value) => value + 1);
    } catch (failure) { setError(message(failure)); }
    finally { setBusy(false); }
  }

  return <section className="oauth-resources" aria-label="OAuth resources">
    {!enabled && <p className="config-warning">Resource authorization is disabled. Explicitly opt in under Settings, Runtime and access policy before using resource tokens.</p>}
    <p>Register resource audiences, map capabilities to relative permissions, and inspect delegated connections. Client IDs are OAuth identifiers, not database IDs.</p>
    {error && <p role="alert">{error} Reload before retrying a version conflict.</p>}{notice && <p role="status">{notice}</p>}
    <button className="outline" disabled={busy} onClick={() => setRevision((value) => value + 1)}>Reload resources</button>
    {loading ? <p role="status">Loading OAuth resources...</p> : resource ? <>
      <a href={routeHref({ id: undefined, connection_id: undefined })} onClick={(event) => followRoute(event, { id: undefined, connection_id: undefined })}>All OAuth resources</a>
      <h3>{resource.name}</h3><p><code>{resource.uri}</code> · Version {resource.version}</p>
      <ResourceEditor key={`${resource.id}:${resource.version}`} resource={resource} request={request} path={selected} onSaved={() => { setNotice("OAuth resource updated."); setRevision((value) => value + 1); }} />
      <section className="table" aria-label="Resource connections"><div className="table-head">Connections</div>
        {!connections.items.length && <p className="table-empty">No connections.</p>}
        {connections.items.map((item) => <article key={item.id}><div><strong>{item.client_id}</strong><p>User {item.user_id} · {item.revoked_at ? "Revoked" : "Not revoked"} · Expires {item.expires_at}</p></div><a href={routeHref({ connection_id: item.id })} onClick={(event) => followRoute(event, { connection_id: item.id })}>Inspect connection {item.id}</a></article>)}
        {connections.next_cursor && <button disabled={busy} onClick={() => void more("connections")}>Load more connections</button>}
      </section>
      {connection && <section aria-label="Connection detail"><h4>Connection detail</h4><pre>{JSON.stringify(connection, null, 2)}</pre><button disabled={busy || !!connection.revoked_at} onClick={() => void revoke()}>{connection.revoked_at ? "Connection revoked" : "Revoke connection"}</button><a href={routeHref({ connection_id: undefined })} onClick={(event) => followRoute(event, { connection_id: undefined })}>Close connection</a></section>}
    </> : !route.id ? <>
      <section className={`create-panel ${creating ? "open" : ""}`}><button className="create-toggle" onClick={() => setCreating((value) => !value)}>{creating ? "Close" : "Create OAuth resource"}</button>{creating && <ResourceEditor request={request} path={base} onSaved={(item) => { setCreating(false); navigate({ id: item.id, connection_id: undefined }); }} />}</section>
      <section className="table"><div className="table-head">OAuth resources</div>{!resources.items.length && <p className="table-empty">No OAuth resources yet.</p>}{resources.items.map((item) => <article key={item.id}><div><strong>{item.name}</strong><p>{item.uri} · {item.enabled ? "Enabled" : "Disabled"}</p></div><a href={routeHref({ id: item.id, connection_id: undefined })} onClick={(event) => followRoute(event, { id: item.id, connection_id: undefined })}>Manage {item.name}</a></article>)}{resources.next_cursor && <button disabled={busy} onClick={() => void more("resources")}>Load more resources</button>}</section>
    </> : null}
  </section>;
}

function ResourceEditor({ resource, path, request, onSaved }: { resource?: Resource; path: string; request: ResourceRequest; onSaved: (item: Resource) => void }) {
  const [capabilities, setCapabilities] = useState<Capability[]>(resource?.capabilities ?? []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const attempt = useRef<{ body: string; key: string } | null>(null);
  function update(index: number, patch: Partial<Capability>) { setCapabilities((items) => items.map((item, i) => i === index ? { ...item, ...patch } : item)); }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (!capabilities.length) { setError("Add at least one capability."); return; }
    if (new Set(capabilities.map((item) => item.key)).size !== capabilities.length) { setError("Capability keys must be unique."); return; }
    const body = { uri: String(form.get("uri")).trim(), name: String(form.get("name")).trim(), enabled: form.has("enabled"), allow_client_metadata: form.has("allow_client_metadata"), client_ids: split(String(form.get("client_ids"))), capabilities: capabilities.map((item) => ({ ...item, permissions: item.permissions.map((value) => value.trim()).filter(Boolean) })) };
    const serialized = JSON.stringify(body);
    if (attempt.current?.body !== serialized) attempt.current = { body: serialized, key: crypto.randomUUID() };
    setBusy(true); setError("");
    try {
      const item = await request<Resource>(resource ? "PATCH" : "POST", path, body, resource ? { headers: versionHeaders(resource.version) } : { idempotencyKey: attempt.current.key });
      onSaved(item);
    } catch (failure) { setError(`${message(failure)} Reload before retrying a version conflict.`); }
    finally { setBusy(false); }
  }
  return <form className="inline-editor" onSubmit={(event) => void submit(event)}><fieldset disabled={busy}><legend>{resource ? "Resource configuration" : "New OAuth resource"}</legend>
    {error && <p role="alert">{error}</p>}
    <div className="create-fields"><label>Name<input required name="name" defaultValue={resource?.name} /></label><label>Resource URI<input required type="url" name="uri" defaultValue={resource?.uri} /></label>
      <label>Allowed client IDs (comma or newline separated)<textarea name="client_ids" defaultValue={resource?.client_ids.join("\n") ?? ""} /><small>Explicit OAuth client identifiers. No dynamic client registration.</small></label>
      <label><Toggle name="enabled" defaultChecked={resource?.enabled ?? true} />Enabled</label><label><Toggle name="allow_client_metadata" defaultChecked={resource?.allow_client_metadata ?? false} />Allow client metadata</label>
    </div>
    <h4>Capability map</h4><p>Use relative colon-delimited keys and permissions, not canonical application paths.</p>
    {capabilities.map((item, index) => <fieldset key={index}><legend>Capability {index + 1}</legend><div className="create-fields">
      <label>Capability key<input required pattern={capabilityKey} title="No wildcards; roles and workspaces are reserved first segments." value={item.key} onChange={(event) => update(index, { key: event.target.value })} /></label>
      <label>Capability name<input required value={item.name} onChange={(event) => update(index, { name: event.target.value })} /></label>
      <label>Context<SelectControl label={`Capability ${index + 1} context`} value={item.context} onValueChange={(value) => update(index, { context: value as Capability["context"] })}><option value="personal">Personal</option><option value="workspace">Workspace</option></SelectControl></label>
      <label>Permissions (comma separated)<input pattern={`\\s*(?:${relativePermission}(?:\\s*,\\s*${relativePermission})*)?\\s*`} value={item.permissions.join(",")} onChange={(event) => update(index, { permissions: event.target.value.split(",") })} onBlur={() => update(index, { permissions: item.permissions.map((value) => value.trim()).filter(Boolean) })} /><small>Leave empty to require only an active user or workspace membership; application must enforce record ownership.</small></label>
    </div><button type="button" className="outline" onClick={() => setCapabilities((items) => items.filter((_, i) => i !== index))}>Remove capability {index + 1}</button></fieldset>)}
    <button type="button" className="outline" onClick={() => setCapabilities((items) => [...items, { key: "", name: "", context: "personal", permissions: [] }])}>Add capability</button>
    <button>{busy ? "Saving..." : resource ? "Save OAuth resource" : "Create resource"}</button>
  </fieldset></form>;
}
