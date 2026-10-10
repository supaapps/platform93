"use client";
import { useEffect, useRef, useState, type FormEvent } from "react";
import type { generated } from "@supaapps/platform93-sdk";
import { validateFreeFormInput } from "./free-form-validation";
import { ReferencePicker, type ReferenceItem, type ReferenceRequest } from "./reference-picker";

type Feature = { id: string; key: string; name: string; value_type: string; free_form_format?: string };
type FeatureValue = { key?: string; feature_id: string; boolean_value?: boolean; quantity_value?: number; free_form_value?: unknown };
type Price = generated.Price;

export function calendarExpiry(now: Date, months: number): Date {
  const date = new Date(now);
  const day = date.getDate();
  date.setDate(1); date.setMonth(date.getMonth() + months);
  const lastDay = new Date(date.getFullYear(), date.getMonth() + 1, 0).getDate();
  date.setDate(Math.min(day, lastDay));
  return date;
}
function localDateTime(date: Date) {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

export function priceLabel(price: Price): string {
  if (price.amount_minor == null || !Number.isSafeInteger(price.amount_minor) || price.amount_minor < 0) {
    return `${price.key} · Amount unavailable · ${price.currency} · ${price.mode}`;
  }
  const exponent = price.currency_exponent;
  const amount = Number.isInteger(exponent) && exponent >= 0 && exponent <= 6
    ? (price.amount_minor / 10 ** exponent).toFixed(exponent)
    : `${price.amount_minor} minor units`;
  return `${price.key} · ${amount} ${price.currency} · ${price.mode}`;
}

function FreeFormGrantInput({ feature, value, onChange }: { feature: Feature; value: string | undefined; onChange: (value: string | undefined) => void }) {
  const format = feature.free_form_format === "csv" ? "csv" : feature.free_form_format === "text" ? "text" : "json";
  const included = value !== undefined;
  const error = included && format === "json" && !value.trim() ? "Enter valid JSON or exclude this feature." : validateFreeFormInput(format, value ?? "");
  return <div>
    <label><input type="checkbox" checked={included} onChange={(event) => onChange(event.target.checked ? format === "json" ? "{}" : "" : undefined)} />Include {feature.name}</label>
    <label>{feature.name} ({feature.key})<textarea disabled={!included} value={value ?? ""} placeholder={format} aria-invalid={!!error} ref={(element) => element?.setCustomValidity(error)} onChange={(event) => onChange(event.target.value)} /></label>
    {error && <small role="alert">{error}</small>}
  </div>;
}

export function ManualGrantForm({ basePath, request, grant, onCreated, onMessage }: {
  basePath: string; request: ReferenceRequest; grant: (body: Record<string, unknown>, key: string) => Promise<unknown>; onCreated: () => void; onMessage: (message: string, error?: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const [subjectType, setSubjectType] = useState("user");
  const [subject, setSubject] = useState<string[]>([]);
  const [recipient, setRecipient] = useState<ReferenceItem | null>(null);
  const [product, setProduct] = useState<ReferenceItem | null>(null);
  const [priceID, setPriceID] = useState("");
  const [features, setFeatures] = useState<Feature[]>([]);
  const [featureError, setFeatureError] = useState("");
  const [featuresLoaded, setFeaturesLoaded] = useState(false);
  const [retry, setRetry] = useState(0);
  const [values, setValues] = useState<Record<string, string>>({});
  const [config, setConfig] = useState("{}");
  const [dirty, setDirty] = useState(false);
  const [expiry, setExpiry] = useState("");
  const [noExpiry, setNoExpiry] = useState(false);
  const [review, setReview] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const submittedRequest = useRef<{ body: string; key: string } | null>(null);
  useEffect(() => {
    let current = true;
    request(`${basePath}/features`).then((page) => { if (current) { setFeatures(page.items as unknown as Feature[]); setFeatureError(""); setFeaturesLoaded(true); } })
      .catch((failure) => { if (current) setFeatureError(String(failure)); });
    return () => { current = false; };
  }, [basePath, request, retry]);
  const prices = ((product?.prices ?? []) as Price[]).filter((price) => price.active);
  function defaults(nextProduct: ReferenceItem | null, nextPriceID: string) {
    const source = nextPriceID ? ((nextProduct?.prices ?? []) as Price[]).find((price) => price.id === nextPriceID) : nextProduct;
    const snapshot = (source?.features ?? []) as FeatureValue[];
    const nextValues: Record<string, string> = {};
    for (const value of snapshot) {
      const feature = features.find((entry) => entry.id === value.feature_id);
      if (!feature) continue;
      const raw = value.boolean_value ?? value.quantity_value ?? value.free_form_value;
      if (raw !== undefined) nextValues[feature.key] = feature.value_type === "free_form" && feature.free_form_format === "json" ? JSON.stringify(raw, null, 2) : String(raw);
    }
    setValues(nextValues); setConfig(JSON.stringify(source?.entitlement_config ?? {}, null, 2)); setDirty(false); setReview(null);
  }
  function canReset() { return !dirty || window.confirm("Discard grant-only overrides and load the selected defaults?"); }
  function edit() { setDirty(true); setReview(null); }
  function payload(form: HTMLFormElement) {
    const configuration: unknown = JSON.parse(config);
    if (!configuration || typeof configuration !== "object" || Array.isArray(configuration)) throw new Error("Configuration must be a JSON object.");
    const featureValues: Record<string, unknown> = {};
    for (const feature of features) {
      const raw = values[feature.key];
      if (raw === undefined || raw === "" && feature.value_type !== "free_form") continue;
      if (feature.value_type === "boolean") featureValues[feature.key] = raw === "true";
      else if (feature.value_type === "quantity") {
        const quantity = Number(raw);
        if (!Number.isSafeInteger(quantity) || quantity < 0) throw new Error(`${feature.name} must be a non-negative safe integer.`);
        featureValues[feature.key] = quantity;
      } else if (feature.free_form_format === "json") featureValues[feature.key] = JSON.parse(raw);
      else {
        const error = validateFreeFormInput(feature.free_form_format === "csv" ? "csv" : "text", raw);
        if (error) throw new Error(`${feature.name}: ${error}`);
        featureValues[feature.key] = raw;
      }
    }
    const expires = new Date(expiry);
    if (!noExpiry && (!expiry || !Number.isFinite(expires.getTime()) || expires <= new Date())) throw new Error("Choose an expiry after now.");
    if (!subject[0] || !product) throw new Error("Select a recipient and product.");
    const formData = new FormData(form);
    return { subject_type: subjectType, subject_id: subject[0], product_id: product.id, ...(priceID ? { price_id: priceID } : {}), feature_values: featureValues, configuration, ...(noExpiry ? {} : { expires_at: expires.toISOString() }), reason: formData.get("reason") || undefined, external_reference: formData.get("external_reference") || undefined };
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const body = payload(event.currentTarget);
      if (!review) { setReview(body); return; }
      setBusy(true);
      const serialized = JSON.stringify(body);
      const key = submittedRequest.current?.body === serialized ? submittedRequest.current.key : crypto.randomUUID();
      submittedRequest.current = { body: serialized, key };
      await grant(body, key);
      onMessage("Entitlement granted. No payment or automatic renewal was created."); onCreated(); setOpen(false);
      setSubject([]); setRecipient(null); setProduct(null); setPriceID(""); setExpiry(""); setNoExpiry(false); setValues({}); setConfig("{}"); setDirty(false); setReview(null); submittedRequest.current = null;
    } catch (failure) { onMessage(failure instanceof Error ? failure.message : "The entitlement could not be granted.", true); }
    finally { setBusy(false); }
  }
  let configError = "";
  try { const parsed = JSON.parse(config); if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) configError = "Enter a JSON object."; } catch { configError = "Invalid JSON."; }
  return <section className={`create-panel ${open ? "open" : ""}`}>
    <button type="button" disabled={busy} onClick={() => setOpen(!open)}>{open ? "Close" : "Grant entitlement"}</button>
    {open && <form onSubmit={(event) => void submit(event)} onChange={() => setReview(null)}>
      <fieldset disabled={busy}><div className="create-fields">
        <label>Recipient type<select value={subjectType} onChange={(event) => { setSubjectType(event.target.value); setSubject([]); setRecipient(null); setReview(null); }}><option value="user">User</option><option value="workspace">Workspace</option></select></label>
        <ReferencePicker key={subjectType} kind={subjectType === "user" ? "users" : "workspaces"} basePath={basePath} request={request} label="Recipient" required activeOnly value={subject} onChange={(ids, items) => { setSubject(ids); setRecipient(items[0] ?? null); setReview(null); }} />
        <ReferencePicker kind="products" basePath={basePath} request={request} label="Product" required activeOnly disabled={!featuresLoaded || !!featureError} value={product ? [product.id] : []} onChange={(_ids, items) => { if (!canReset()) return; const selected = items[0] ?? null; setProduct(selected); setPriceID(""); defaults(selected, ""); }} />
<label>Price<select aria-label="Price" disabled={!product} value={priceID} onChange={(event) => { if (!canReset()) return; setPriceID(event.target.value); defaults(product, event.target.value); }}><option value="">Current product defaults</option>{prices.map((price) => <option key={price.id} value={price.id}>{priceLabel(price)}</option>)}</select></label>
        <label><input type="checkbox" checked={noExpiry} onChange={(event) => { setNoExpiry(event.target.checked); setReview(null); }} />No expiry (until revoked)</label>
        <label>Expires at<input type="datetime-local" required={!noExpiry} disabled={noExpiry} value={expiry} onChange={(event) => setExpiry(event.target.value)} /><small>{Intl.DateTimeFormat().resolvedOptions().timeZone} · no automatic renewal</small></label>
        <div className="duration-actions">{[[1, "1 month"], [3, "3 months"], [6, "6 months"], [12, "1 year"]].map(([months, label]) => <button key={months} type="button" onClick={() => { setNoExpiry(false); setExpiry(localDateTime(calendarExpiry(new Date(), Number(months)))); setReview(null); }}>{label}</button>)}</div>
      </div>
      {featureError && <p role="alert">{featureError} <button type="button" onClick={() => setRetry(retry + 1)}>Retry features</button></p>}
{product && <><h4>Grant-only feature overrides</h4><div className="create-fields">{features.map((feature) => feature.value_type === "free_form" ? <FreeFormGrantInput key={feature.id} feature={feature} value={values[feature.key]} onChange={(value) => { const next = { ...values }; if (value === undefined) delete next[feature.key]; else next[feature.key] = value; setValues(next); edit(); }} /> : <label key={feature.id}>{feature.name} ({feature.key}){feature.value_type === "boolean" ? <select value={values[feature.key] ?? ""} onChange={(event) => { setValues({ ...values, [feature.key]: event.target.value }); edit(); }}><option value="">Not included</option><option value="true">Enabled</option><option value="false">Disabled</option></select> : feature.value_type === "quantity" ? <input type="number" min="0" step="1" value={values[feature.key] ?? ""} onChange={(event) => { setValues({ ...values, [feature.key]: event.target.value }); edit(); }} /> : <textarea aria-invalid={!!validateFreeFormInput(feature.free_form_format === "csv" ? "csv" : feature.free_form_format === "text" ? "text" : "json", values[feature.key] ?? "")} ref={(element) => element?.setCustomValidity(validateFreeFormInput(feature.free_form_format === "csv" ? "csv" : feature.free_form_format === "text" ? "text" : "json", values[feature.key] ?? ""))} value={values[feature.key] ?? ""} placeholder={feature.free_form_format ?? "json"} onChange={(event) => { setValues({ ...values, [feature.key]: event.target.value }); edit(); }} />}</label>)}</div><label>Configuration (JSON object)<textarea value={config} aria-invalid={!!configError} onChange={(event) => { setConfig(event.target.value); edit(); }} /></label>{configError && <p role="alert">{configError}</p>}<button type="button" onClick={() => { if (canReset()) defaults(product, priceID); }}>Reset to defaults</button></>}
      <div className="create-fields"><label>Reason<input name="reason" maxLength={500} /></label><label>External reference<input name="external_reference" maxLength={255} /></label></div>
      {review && <section aria-label="Grant review"><h4>Review grant</h4><p>{String(recipient?.email ?? recipient?.name)} · {String(product?.name)} · {prices.find((price) => price.id === priceID)?.key ?? "Current product defaults"}</p><p>{review.expires_at ? `Expires ${new Date(String(review.expires_at)).toLocaleString()}` : "No expiry (until revoked)"}</p><pre>{JSON.stringify({ feature_values: review.feature_values, configuration: review.configuration }, null, 2)}</pre></section>}
      <button disabled={busy || !!configError || !!featureError || !subject.length || !product}>{busy ? "Granting..." : review ? "Confirm grant" : "Review grant"}</button>
      </fieldset>
    </form>}
  </section>;
}
