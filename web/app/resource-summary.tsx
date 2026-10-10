"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

type Row = Record<string, unknown>;
type Lookup = (path: string) => Promise<{ items: Row[] }>;
const Labels = createContext<Record<string, string>>({});
const text = (value: unknown) => typeof value === "string" || typeof value === "number" ? String(value) : "";
const humanize = (value: unknown) => text(value).replace(/[._:-]+/g, " ");
const shortID = (value: unknown) => text(value).slice(-8);
const actorLabel = (value: unknown) => value === "control_user" ? "Platform user" : value === "client" ? "Machine client" : value === "system" || !text(value) ? "System" : humanize(value);
const references: Record<string, string> = { user_id: "users", owner_user_id: "users", workspace_id: "workspaces", product_id: "products", role_id: "roles", client_id: "clients" };

export function resourceName(item: Row): string {
  return text(item.name || item.display_name) || [text(item.first_name), text(item.last_name)].filter(Boolean).join(" ") || text(item.email || item.key || item.client_id);
}

/** Resolve only referenced records through their existing authorized, bounded searches. */
export function ResourceLabels({ items, basePath, lookup, children }: { items: Row[]; basePath: string; lookup: Lookup; children: ReactNode }) {
  const [result, setResult] = useState<{ items: Row[]; labels: Record<string, string> } | null>(null);
  useEffect(() => {
    let current = true;
    const requests = new Map<string, { kind: string; id: string }>();
    for (const item of items) {
      const fields = { ...references, ...(item.subject_type === "user" ? { subject_id: "users" } : item.subject_type === "workspace" ? { subject_id: "workspaces" } : item.subject_type === "client" ? { subject_id: "clients" } : {}), ...(item.actor_type === "user" ? { actor_id: "users" } : item.actor_type === "client" ? { actor_id: "clients" } : {}), ...(item.target_type === "user" ? { target_id: "users" } : item.target_type === "workspace" ? { target_id: "workspaces" } : item.target_type === "product" ? { target_id: "products" } : item.target_type === "role" ? { target_id: "roles" } : item.target_type === "client" ? { target_id: "clients" } : {}) };
      for (const [field, kind] of Object.entries(fields)) {
        const id = text(item[field]);
        if (id) requests.set(`${kind}:${id}`, { kind, id });
      }
    }
    const queue = [...requests.entries()];
    // Bound simultaneous requests; missing/deleted/forbidden names remain explicit ID fallbacks.
    const worker = async () => {
      while (current && queue.length) {
        const [key, { kind, id }] = queue.shift()!;
        try {
          const page = await lookup(`${basePath}/${kind}?query=${encodeURIComponent(id)}&limit=10`);
          const match = page.items.find((row) => row.id === id || row.client_id === id);
          const label = match && resourceName(match);
          if (current && label) setResult((existing) => ({ items, labels: { ...(existing?.items === items ? existing.labels : {}), [key]: label } }));
        } catch { /* A denied name lookup must not hide the original record. */ }
      }
    };
    void Promise.all(Array.from({ length: Math.min(4, queue.length) }, worker));
    return () => { current = false; };
  }, [items, basePath, lookup]);
  return <Labels.Provider value={result?.items === items ? result.labels : {}}>{children}</Labels.Provider>;
}

export function ResourceSummary({ item, resource }: { item: Row; resource: string }) {
  const labels = useContext(Labels);
  const ref = (kind: string, id: unknown) => !text(id) ? "" : labels[`${kind}:${text(id)}`] || `${humanize(kind).replace(/s$/, "")} · ${shortID(id)}`;
  const recipient = item.user_id ? ref("users", item.user_id) : item.client_id ? ref("clients", item.client_id) : ref(item.subject_type === "workspace" ? "workspaces" : "users", item.subject_id);
  let title = resourceName(item);
  const facts: string[] = [];
  const add = (...values: unknown[]) => facts.push(...values.map(text).filter(Boolean));
  if (resource.includes("audit")) {
    title = humanize(item.action) || "Audit activity";
    const targetKind = ({ user: "users", workspace: "workspaces", product: "products", role: "roles", client: "clients" } as Record<string, string>)[text(item.target_type)];
    const actorKind = item.actor_type === "user" ? "users" : item.actor_type === "client" ? "clients" : "";
    add(`Actor: ${actorKind && item.actor_id ? ref(actorKind, item.actor_id) : `${actorLabel(item.actor_type)}${item.actor_id ? ` · ${shortID(item.actor_id)}` : ""}`}`, item.target_type && `Target: ${targetKind && item.target_id ? ref(targetKind, item.target_id) : `${humanize(item.target_type)}${item.target_id ? ` · ${shortID(item.target_id)}` : ""}`}`, item.reason);
    const changes = item.changes as Row | undefined;
    if (changes) add([text(changes.method), text(changes.path)].filter(Boolean).join(" "));
  } else if (resource === "role-assignments") {
    title = text(item.role_key) || ref("roles", item.role_id) || "Role assignment";
    add(recipient, item.workspace_id ? ref("workspaces", item.workspace_id) : "Application access", item.role_scope);
  } else if (resource === "permission-grants") {
    title = text(item.permission) || "Direct permission";
    add(recipient, item.workspace_id ? ref("workspaces", item.workspace_id) : "Application access", item.status);
  } else if (resource === "entitlements" || resource === "local-entitlement-requests") {
    const snapshot = item.product_snapshot as Row | undefined;
    title = (snapshot && resourceName(snapshot)) || ref("products", item.product_id) || (resource === "entitlements" ? "Custom entitlement" : "Local entitlement request");
    add(recipient, item.status || (item.revoked_at ? "Revoked" : "Granted"), item.source_type, item.expires_at && `Expires ${formatDate(item.expires_at)}`, item.external_reference);
  } else if (resource.startsWith("billing/")) {
    title = text(item.provider_event_id || item.provider_invoice_id || item.provider_subscription_id || item.provider_payment_id || item.provider_refund_id || item.provider_dispute_id || item.external_reference) || humanize(resource.split("/").at(-1));
    const amount = item.amount_minor ?? item.total_minor ?? item.amount_due_minor;
    add(recipient, item.status, formatMoney(amount, item.currency), item.event_type, item.reason);
    if (resource.endsWith("reconciliation-runs")) add(item.finished_at ? `Finished ${formatDate(item.finished_at)}` : "Reconciliation in progress");
  } else if (resource === "events" || resource === "webhook-deliveries") {
    title = text(item.event_type || item.type) || (resource === "events" ? "Domain event" : "Webhook delivery");
    add(item.status, item.subject, item.endpoint_url || item.url, item.attempt_count !== undefined && `${text(item.attempt_count)} attempts`);
    if (resource === "webhook-deliveries") add(item.response_status && `HTTP ${text(item.response_status)}`, item.webhook_id && `Endpoint · ${shortID(item.webhook_id)}`, item.event_id && `Event · ${shortID(item.event_id)}`, item.last_error);
  } else if (resource === "notifications") {
    title = text(item.subject || item.template_key || item.recipient) || "Notification";
    add(item.recipient || recipient, item.status, item.locale, item.attempt_count !== undefined && `${text(item.attempt_count)} attempts`, item.last_error);
  } else if (resource === "invitations") {
    title = text(item.email || item.recipient_email) || "Invitation";
    add(item.status, item.workspace_id ? ref("workspaces", item.workspace_id) : "Application invitation", Array.isArray(item.application_role_keys) && item.application_role_keys.join(", "), Array.isArray(item.workspace_role_keys) && item.workspace_role_keys.join(", "), item.expires_at && `Expires ${formatDate(item.expires_at)}`);
  } else if (resource === "webhooks") {
    title ||= text(item.url || item.endpoint_url) || "Webhook endpoint";
    add(item.disabled_at ? "Disabled" : "Enabled", Array.isArray(item.event_filters) && item.event_filters.join(", "));
  } else if (resource === "notification-templates") {
    title = `${text(item.key)} · ${text(item.locale) || "en"}`;
    add(item.status, item.scope || "application", item.inherited && "Inherited");
  } else if (resource === "oauth-consents" || resource === "delegations") {
    title = recipient || humanize(resource);
    add(item.status, item.scope, item.expires_at && `Expires ${formatDate(item.expires_at)}`);
  } else {
    if (resource.includes("member")) { title ||= recipient; add(item.owner ? "Owner" : "Member", Array.isArray(item.role_keys) && item.role_keys.join(", ")); }
    title ||= text(item.hostname || item.email || item.user_agent || item.event_type || item.provider_event_id) || humanize(resource);
    add(item.email !== title && item.email, item.key !== title && item.key, item.client_type, item.status, item.scope, item.role, item.value_type, item.description, item.ip_address);
    if (resource.includes("session")) { title ||= "Session"; add(item.revoked_at ? "Revoked" : "Active", item.last_used_at && `Last used ${formatDate(item.last_used_at)}`); }
    if (resource.includes("address")) {
      title = text(item.name || item.line1 || item.street) || "Billing address";
      add(item.city, item.postal_code, item.country);
    }
    if (resource === "workspaces") add(item.owner_user_id && `Owner: ${ref("users", item.owner_user_id)}`);
    if (resource === "roles" && Array.isArray(item.permissions)) add(`${item.permissions.length} permissions`);
  }
  return <div className="resource-summary"><strong>{title}</strong>{facts.length > 0 && <small>{[...new Set(facts)].join(" · ")}</small>}{item.created_at ? <time dateTime={text(item.created_at)}>{formatDate(item.created_at)}</time> : null}</div>;
}

function formatDate(value: unknown) {
  const date = new Date(text(value));
  return Number.isNaN(date.getTime()) ? "Unknown date" : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function formatMoney(amount: unknown, currency: unknown) {
  if (typeof amount !== "number" || !Number.isSafeInteger(amount)) return "";
  const code = text(currency).toUpperCase();
  if (!/^[A-Z]{3}$/.test(code)) return `${amount} minor units`;
  try {
    const formatter = new Intl.NumberFormat(undefined, { style: "currency", currency: code });
    const digits = formatter.resolvedOptions().maximumFractionDigits ?? 2;
    return formatter.format(amount / 10 ** digits);
  } catch { return `${amount} minor units (${code})`; }
}

export function ListHints({ items, hasMore }: { items: Row[]; hasMore: boolean }) {
  const groups = new Map<string, number>();
  for (const item of items) {
    const value = text(item.status || item.actor_type || item.role_scope || item.scope);
    if (value) groups.set(value, (groups.get(value) || 0) + 1);
  }
  return <div className="list-hints" aria-label="Loaded records summary"><span>{items.length} loaded{hasMore ? " · more available" : ""}</span>{[...groups].slice(0, 5).map(([label, count]) => <span key={label}><strong>{count}</strong> {humanize(label)}</span>)}</div>;
}
