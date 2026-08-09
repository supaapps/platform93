import { createHmac, timingSafeEqual } from "node:crypto";

export type ContractSource = "platform93" | "application";
export type EventActor = { type: string; id?: string };

export type Platform93Event<
  Type extends string = string,
  Source extends ContractSource = ContractSource,
  Data extends Record<string, unknown> = Record<string, unknown>,
> = {
  specversion: "1.0";
  id: string;
  source: string;
  type: Type;
  contract_source: Source;
  time: string;
  application_id: string;
  schema_version: string;
  subject?: string | null;
  actor?: EventActor | null;
  correlation_id?: string | null;
  causation_id?: string | null;
  data: Data;
};

type ID = string;
type NamedData = { name: string; slug: string };
type UserIDData = { user_id: ID };
type UserStateData = UserIDData & { reason: string };
type VerificationData<Verified extends boolean> = UserIDData & { verified: Verified; reason: string };
type StorageObjectData = { object_id: ID; owner_type: "installation" | "application" | "user" | "workspace"; visibility: "public" | "private"; size_bytes: number };
type StorageProviderData = { provider_id: ID; scope: "installation" | "organization" | "application"; public_enabled: boolean; private_enabled: boolean };

export interface Platform93EventDataMap {
  "organization.created": NamedData;
  "organization.retired": { application_count: number };
  "organization.restored": { descendants_restored: boolean };
  "application.created": NamedData;
  "application.retired": { organization_id: ID; reason: string };
  "application.restored": { organization_id: ID; reason: string };
  "delegation.created": { delegation_id: ID; user_id: ID; workspace_id: ID | null; permissions: string[]; reason: string; expires_at: string };
  "delegation.exchanged": { delegation_id: ID; user_id: ID };
  "delegation.revoked": { delegation_id: ID };
  "entitlement.granted": { grant_id: ID; subject_type: "user" | "workspace"; subject_id: ID; reason: string };
  "local_entitlement_request.created": { request_id: ID; subject_type: "user" | "workspace"; subject_id: ID; price_id: ID };
  "local_entitlement_request.approved": { request_id: ID; grant_id: ID };
  "oauth.consent_revoked": { user_id: ID; client_id: ID; client_key: string };
  "platform93.webhook.test": { webhook_endpoint_id: ID; test: true };
  "storage.object.upload_requested": StorageObjectData;
  "storage.object.ready": StorageObjectData;
  "storage.object.deleted": StorageObjectData;
  "storage.provider.verified": StorageProviderData;
  "storage.provider.disabled": StorageProviderData;
  "user.created": UserIDData & { email_verified: boolean; is_org_verified: boolean };
  "user.email_verified": VerificationData<true>;
  "user.email_unverified": VerificationData<false>;
  "user.organization_verified": VerificationData<true>;
  "user.organization_unverified": VerificationData<false>;
  "user.email_changed": UserIDData;
  "user.password_reset": UserIDData;
  "user.pending_deletion": UserIDData;
  "user.anonymized": UserIDData;
  "user.deleted": UserIDData;
  "user.suspended": UserStateData;
  "user.restored": UserStateData;
  "workspace.invitation_created": { invitation_id: ID; workspace_id: ID; role_keys: string[] };
  "workspace.invitation_accepted": { invitation_id: ID; workspace_id: ID; user_id: ID };
  "workspace.owner_transferred": { workspace_id: ID; previous_owner_user_id: ID; new_owner_user_id: ID; previous_owner_disposition: "member" | "remove" };
}

export type Platform93EventType = keyof Platform93EventDataMap;
export type KnownPlatform93Event = {
  [Type in Platform93EventType]: Platform93Event<Type, "platform93", Platform93EventDataMap[Type]>;
}[Platform93EventType];
export type CustomPlatform93Event<Data extends Record<string, unknown> = Record<string, unknown>> = Platform93Event<string, "application", Data>;
export type AnyPlatform93Event = KnownPlatform93Event | CustomPlatform93Event;

export const platform93EventVersions: Readonly<Record<Platform93EventType, string>> = {
  "organization.created": "1.0", "organization.retired": "1.0", "organization.restored": "1.0",
  "application.created": "1.0", "application.retired": "1.0", "application.restored": "1.0",
  "delegation.created": "1.0", "delegation.exchanged": "1.0", "delegation.revoked": "1.0",
  "entitlement.granted": "1.0", "local_entitlement_request.created": "1.0", "local_entitlement_request.approved": "1.0",
  "oauth.consent_revoked": "1.0", "platform93.webhook.test": "1.0", "user.created": "1.0",
  "storage.object.upload_requested": "1.0", "storage.object.ready": "1.0", "storage.object.deleted": "1.0",
  "storage.provider.verified": "1.0", "storage.provider.disabled": "1.0",
  "user.email_verified": "1.0", "user.email_unverified": "1.0", "user.organization_verified": "1.0",
  "user.organization_unverified": "1.0", "user.email_changed": "1.0", "user.password_reset": "1.0",
  "user.pending_deletion": "1.0", "user.anonymized": "1.0", "user.deleted": "1.0",
  "user.suspended": "1.0", "user.restored": "1.0", "workspace.invitation_created": "1.0",
  "workspace.invitation_accepted": "1.0", "workspace.owner_transferred": "1.0",
};

export function isKnownPlatform93Event(event: AnyPlatform93Event): event is KnownPlatform93Event {
  return event.contract_source === "platform93" && Object.hasOwn(platform93EventVersions, event.type);
}

export function isCustomPlatform93Event(event: AnyPlatform93Event): event is CustomPlatform93Event {
  return event.contract_source === "application";
}

export function assertSupportedPlatform93Event(event: AnyPlatform93Event): asserts event is KnownPlatform93Event {
  if (!isKnownPlatform93Event(event)) throw new Error(`Unknown Platform93 event contract: ${event.type}`);
  const supported = platform93EventVersions[event.type];
  if (event.schema_version.split(".")[0] !== supported.split(".")[0]) {
    throw new Error(`Unsupported ${event.type} schema version ${event.schema_version}; this SDK supports ${supported}`);
  }
}

export type Platform93EventHandlers = {
  [Type in Platform93EventType]?: (event: Platform93Event<Type, "platform93", Platform93EventDataMap[Type]>) => void | Promise<void>;
};

export async function routePlatform93Event(
  event: AnyPlatform93Event,
  handlers: Platform93EventHandlers,
  onCustom?: (event: CustomPlatform93Event) => void | Promise<void>,
): Promise<boolean> {
  if (isCustomPlatform93Event(event)) {
    if (!onCustom) return false;
    await onCustom(event);
    return true;
  }
  assertSupportedPlatform93Event(event);
  const handler = handlers[event.type] as ((value: KnownPlatform93Event) => void | Promise<void>) | undefined;
  if (!handler) return false;
  await handler(event);
  return true;
}

export function verifyWebhook(rawBody: Uint8Array, header: string, secret: string, toleranceSeconds = 300): AnyPlatform93Event {
  const parts = Object.fromEntries(header.split(",").map((value) => value.split("=", 2)));
  const timestamp = Number(parts.t);
  if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > toleranceSeconds) throw new Error("Platform93 webhook timestamp rejected");
  const expected = createHmac("sha256", secret).update(`${timestamp}.`).update(rawBody).digest("hex");
  const actual = parts.v1 ?? "";
  if (actual.length !== expected.length || !timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) throw new Error("Platform93 webhook signature rejected");
  const event = JSON.parse(Buffer.from(rawBody).toString("utf8")) as Partial<AnyPlatform93Event>;
  if (event.specversion !== "1.0" || typeof event.type !== "string" || !["platform93", "application"].includes(String(event.contract_source)) || typeof event.schema_version !== "string" || !event.data || typeof event.data !== "object" || Array.isArray(event.data)) {
    throw new Error("Platform93 webhook envelope rejected");
  }
  return event as AnyPlatform93Event;
}
