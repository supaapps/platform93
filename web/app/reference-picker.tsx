"use client";
import { useEffect, useId, useRef, useState } from "react";

export type ReferenceItem = Record<string, unknown> & { id: string };
export type ReferencePage = { items: ReferenceItem[]; next_cursor: string | null };
export type ReferenceKind = "users" | "workspaces" | "roles" | "clients" | "products";
export type ReferenceRequest = (path: string) => Promise<ReferencePage>;

function describe(kind: ReferenceKind, item: ReferenceItem) {
  const name = kind === "users" ? [item.first_name, item.last_name].filter(Boolean).join(" ") || String(item.email) : String(item.name ?? item.key ?? item.id);
  const secondary = kind === "users" ? item.email : kind === "clients" ? item.client_id : item.key;
  return { name, secondary: [secondary, kind === "roles" ? item.scope : null, item.id].filter(Boolean).join(" · ") };
}

export function ReferencePicker({ kind, basePath, request, label, name, value = [], onChange, multiple = false, required = false, disabled = false, roleScope, machineOnly = false, hostedOnly = false, activeOnly = false, useKeys = false }: {
  kind: ReferenceKind; basePath: string; request: ReferenceRequest; label: string; name?: string;
  value?: string[]; onChange: (values: string[], items: ReferenceItem[]) => void;
  multiple?: boolean; required?: boolean; disabled?: boolean; roleScope?: string; machineOnly?: boolean; hostedOnly?: boolean; activeOnly?: boolean; useKeys?: boolean;
}) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ReferenceItem[]>([]);
  const [known, setKnown] = useState<Record<string, ReferenceItem>>({});
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(0);
  const [retry, setRetry] = useState(0);
  const [pageCursor, setPageCursor] = useState("");
  const key = (item: ReferenceItem) => String(useKeys ? item.key : item.id);
  useEffect(() => {
    let current = true;
    const timer = setTimeout(() => {
      setLoading(true); setError("");
      const params = new URLSearchParams({ query, limit: "20" });
      if (pageCursor) params.set("cursor", pageCursor);
      request(`${basePath}/${kind}?${params}`).then((page) => {
        if (!current) return;
        const results = page.items.filter((item) => (!roleScope || item.scope === roleScope)
          && (!machineOnly || item.client_type === "machine")
          && (!hostedOnly || item.authorization_ui === "hosted")
          && (!activeOnly || (kind === "users" || kind === "products" ? item.status === "active" : !item.deleted_at)));
        setItems((previous) => pageCursor ? [...previous, ...results] : results);
        setKnown((previous) => ({ ...previous, ...Object.fromEntries(results.map((item) => [String(useKeys ? item.key : item.id), item])) }));
        setCursor(page.next_cursor); setHighlight(0);
      }).catch((failure: unknown) => { if (current) setError(failure instanceof Error ? failure.message : "Search failed."); })
        .finally(() => { if (current) setLoading(false); });
    }, 250);
    return () => { current = false; clearTimeout(timer); };
  }, [basePath, kind, query, request, retry, pageCursor, roleScope, machineOnly, hostedOnly, activeOnly, useKeys]);
  function select(item: ReferenceItem) {
    if (disabled || input.current?.matches(":disabled")) return;
    const selectedKey = key(item);
    const values = multiple ? [...new Set([...value, selectedKey])] : [selectedKey];
    onChange(values, values.map((entry) => entry === selectedKey ? item : known[entry]).filter((entry): entry is ReferenceItem => !!entry));
    setQuery(""); setPageCursor(""); setOpen(multiple); input.current?.focus();
  }
  const options = items.filter((item) => !value.includes(key(item)));
  return <div className="reference-picker">
    <label htmlFor={id}>{label}</label>
    {name && <input type="hidden" name={name} value={value.join(",")} />}
<div className="reference-selection">{value.map((entry) => <span key={entry}>{known[entry] ? `${describe(kind, known[entry]).name} · ${String(known[entry].email ?? known[entry].client_id ?? known[entry].key ?? entry)}` : entry}<button type="button" disabled={disabled} aria-label={`Remove ${known[entry] ? describe(kind, known[entry]).name : entry}`} onClick={() => onChange(value.filter((candidate) => candidate !== entry), value.filter((candidate) => candidate !== entry).map((candidate) => known[candidate]).filter((entry): entry is ReferenceItem => !!entry))}>x</button></span>)}</div>
<input id={id} ref={(element) => { input.current = element; element?.setCustomValidity(required && value.length === 0 ? `Select ${label.toLowerCase()} from the results.` : ""); }} role="combobox" aria-autocomplete="list" aria-expanded={open} aria-controls={`${id}-results`} aria-activedescendant={open && options[highlight] ? `${id}-option-${highlight}` : undefined} disabled={disabled} value={query} placeholder={`Search ${label.toLowerCase()}`} onFocus={() => setOpen(true)} onChange={(event) => { setQuery(event.target.value); setPageCursor(""); setItems([]); setCursor(null); setLoading(true); setOpen(true); }} onKeyDown={(event) => {
      if (event.key === "Escape") { setOpen(false); return; }
      if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); setOpen(true); setHighlight((previous) => Math.max(0, Math.min(options.length - 1, previous + (event.key === "ArrowDown" ? 1 : -1)))); }
      if (event.key === "Enter") { event.preventDefault(); if (open && options[highlight]) select(options[highlight]); }
    }} />
    {open && <div className="reference-results">
      <div role="listbox" id={`${id}-results`} aria-label={`${label} results`} aria-multiselectable={multiple || undefined}>{options.map((item, index) => { const text = describe(kind, item); return <div role="option" id={`${id}-option-${index}`} aria-selected={index === highlight} key={item.id} onMouseDown={(event) => event.preventDefault()} onClick={() => select(item)}><strong>{text.name}</strong><small>{text.secondary}</small></div>; })}</div>
      {loading && <p role="status">Searching...</p>}
      {error && <p role="alert">{error} <button type="button" onClick={() => setRetry((previous) => previous + 1)}>Retry search</button></p>}
      {!loading && !error && options.length === 0 && <p>No matching resources.</p>}
      {cursor && <button type="button" disabled={loading} onClick={() => setPageCursor(cursor)}>Load more results</button>}
      <button type="button" onClick={() => setOpen(false)}>Close results</button>
    </div>}
  </div>;
}
