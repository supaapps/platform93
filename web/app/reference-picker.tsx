"use client";
import { useContext, useEffect, useEffectEvent, useId, useRef, useState } from "react";
import { Button, ComboBox, ComboBoxStateContext, FieldError, Input, Label, ListBox, ListBoxItem, Popover } from "react-aria-components";

function SearchInput({ input, searching, setSearching, query, placeholder, id }: {
  input: React.RefObject<HTMLInputElement | null>; searching: boolean; setSearching: (value: boolean) => void; query: string; placeholder: string; id: string;
}) {
  const state = useContext(ComboBoxStateContext);
  // Keep async result updates from dismissing a search or reopening it after selection.
  const synchronize = useEffectEvent(() => {
    if (searching) state?.open(null, "manual");
    else state?.close();
  });
  useEffect(() => { synchronize(); }, [searching, query, state?.isOpen]);
  return <Input ref={input} id={id} placeholder={placeholder}
    onPointerDown={() => setSearching(true)} onInput={() => setSearching(true)}
    onKeyDown={(event) => { if (event.key === "Escape" || event.key === "Tab") setSearching(false); else if (event.key === "ArrowDown" || event.key === "ArrowUp") setSearching(true); }}
    onBlur={(event) => { if (!(event.relatedTarget instanceof Element) || !event.relatedTarget.closest(".reference-results")) setSearching(false); }} />;
}

export type ReferenceItem = Record<string, unknown> & { id: string };
export type ReferencePage = { items: ReferenceItem[]; next_cursor: string | null };
export type ReferenceKind = "users" | "workspaces" | "roles" | "clients" | "products";
export type ReferenceRequest = (path: string) => Promise<ReferencePage>;

function describe(kind: ReferenceKind, item: ReferenceItem) {
  const name = kind === "users" ? [item.first_name, item.last_name].filter(Boolean).join(" ") || String(item.email) : String(item.name ?? item.key ?? item.id);
  const secondary = kind === "users" ? item.email : kind === "clients" ? item.client_id : item.key;
  return { name, secondary: [secondary ?? item.id, kind === "roles" ? item.scope : null].filter(Boolean).join(" · ") };
}

export function ReferencePicker({ kind, basePath, request, label, name, value = [], onChange, multiple = false, required = false, disabled = false, roleScope, machineOnly = false, activeOnly = false, useKeys = false }: {
  kind: ReferenceKind; basePath: string; request: ReferenceRequest; label: string; name?: string;
  value?: string[]; onChange: (values: string[], items: ReferenceItem[]) => void;
  multiple?: boolean; required?: boolean; disabled?: boolean; roleScope?: string; machineOnly?: boolean; activeOnly?: boolean; useKeys?: boolean;
}) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ReferenceItem[]>([]);
  const [known, setKnown] = useState<Record<string, ReferenceItem>>({});
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [pageCursor, setPageCursor] = useState("");
  const [searching, setSearching] = useState(false);
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
          && (!activeOnly || (kind === "users" || kind === "products" ? item.status === "active" : !item.deleted_at)));
        setItems((previous) => pageCursor ? [...previous, ...results] : results);
        setKnown((previous) => ({ ...previous, ...Object.fromEntries(results.map((item) => [String(useKeys ? item.key : item.id), item])) }));
        setCursor(page.next_cursor);
      }).catch((failure: unknown) => { if (current) setError(failure instanceof Error ? failure.message : "Search failed."); })
        .finally(() => { if (current) setLoading(false); });
    }, 250);
    return () => { current = false; clearTimeout(timer); };
  }, [basePath, kind, query, request, retry, pageCursor, roleScope, machineOnly, activeOnly, useKeys]);
  function select(item: ReferenceItem) {
    if (disabled || input.current?.matches(":disabled")) return;
    const selectedKey = key(item);
    const values = multiple ? [...new Set([...value, selectedKey])] : [selectedKey];
    onChange(values, values.map((entry) => entry === selectedKey ? item : known[entry]).filter((entry): entry is ReferenceItem => !!entry));
    setSearching(false); setQuery(""); setPageCursor("");
  }
  const options = items;
  return <div className="reference-picker">
    {name && <input type="hidden" name={name} value={value.join(",")} />}
    <ComboBox<ReferenceItem> className="ui-combobox" items={options} inputValue={query} allowsCustomValue allowsEmptyCollection menuTrigger="manual" isDisabled={disabled}
      isRequired={required && value.length === 0} validationBehavior="native" validate={() => required && value.length === 0 ? `Select ${label.toLowerCase()} from the results.` : null}
      defaultFilter={() => true}
      onInputChange={(text) => { if (text === query) return; setQuery(text); setPageCursor(""); setItems([]); setCursor(null); setLoading(true); }}
      onSelectionChange={(selected) => { const item = options.find((entry) => key(entry) === selected); if (item) select(item); }}>
      <Label className="ui-label">{label}</Label>
      <div className="ui-combobox-control">
        <SearchInput id={id} input={input} searching={searching} setSearching={setSearching} query={query} placeholder={value.length ? "Change selection…" : `Search ${label.toLowerCase()}`} />
        <Button className="ui-combobox-toggle" onPress={() => setSearching(!searching)} aria-label={`Show ${label.toLowerCase()} options`}><span aria-hidden="true">⌄</span></Button>
      </div>
      <FieldError className="ui-field-error" />
      <Popover className="ui-popover reference-results" placement="bottom start" offset={6} onOpenChange={(open) => { if (!open) setSearching(false); }}>
        <ListBox<ReferenceItem> items={options} className="ui-listbox" aria-label={`${label} results`} renderEmptyState={() => <div className="ui-empty">{loading ? "Searching…" : error ? "Search unavailable" : "No matching resources."}</div>}>
          {(item) => { const text = describe(kind, item); return <ListBoxItem id={key(item)} textValue={text.name} className="ui-option"><strong>{text.name}</strong><small>{text.secondary}</small></ListBoxItem>; }}
        </ListBox>
        {loading && options.length > 0 && <p className="ui-overlay-message" role="status">Searching…</p>}
        {error && <div className="ui-overlay-message" role="alert">{error}<Button className="ui-secondary" onPress={() => setRetry((previous) => previous + 1)}>Retry search</Button></div>}
        {cursor && <Button className="ui-overlay-footer" isDisabled={loading} onPress={() => setPageCursor(cursor)}>Load more results</Button>}
      </Popover>
    </ComboBox>
    <div className="reference-selection">{value.map((entry) => <span key={entry}><span>{known[entry] ? describe(kind, known[entry]).name : entry}<small>{known[entry] ? String(known[entry].email ?? known[entry].client_id ?? known[entry].key ?? "") : ""}</small></span><button type="button" disabled={disabled} aria-label={`Remove ${known[entry] ? describe(kind, known[entry]).name : entry}`} onClick={() => onChange(value.filter((candidate) => candidate !== entry), value.filter((candidate) => candidate !== entry).map((candidate) => known[candidate]).filter((entry): entry is ReferenceItem => !!entry))}>×</button></span>)}</div>
  </div>;
}
