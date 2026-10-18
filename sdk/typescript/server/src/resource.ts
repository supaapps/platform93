import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload } from "jose";
import type { ResourceAccessCheckRequest, ResourceAccessCheckResponse } from "@supaapps/platform93-sdk";
import type { VerifierOptions } from "./index.js";

export type ResourceClaims = JWTPayload & {
  application_id: string; actor_type: "user"; token_kind: "resource_access";
  sub: string; sid: string; client_id: string; connection_id: string; scope: string;
  roles: { application: []; workspaces: Record<string, never> };
};
// Explicit end-of-input avoids JavaScript's `$` match before a trailing newline.
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/;
const segment = /^[a-z0-9][a-z0-9._-]{0,63}(?![\s\S])/;
const protocolScopes = new Set(["openid", "profile", "email", "offline_access"]);

function httpsURI(value: string) {
  if (typeof value !== "string" || /[^\x21-\x7e]|["\\]/.test(value)) throw new Error("Invalid HTTPS resource URI");
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || value.includes("#") || value.includes("?")) throw new Error("Invalid HTTPS resource URI");
  return value;
}

export function capabilityScope(applicationId: string, capability: string) {
  if (!uuid.test(applicationId) || typeof capability !== "string" || capability.length > 160 || ["roles", "workspaces"].includes(capability.split(":")[0] ?? "") || !capability.split(":").every(part => segment.test(part))) {
    throw new Error("Invalid resource capability");
  }
  return `/applications/${applicationId}/${capability.replaceAll(":", "/")}`;
}

export function protectedResourceMetadata(resource: string, issuer: string, applicationId: string, capabilities: string[]) {
  return { resource: httpsURI(resource), authorization_servers: [httpsURI(issuer)], scopes_supported: [...new Set(capabilities.map(value => capabilityScope(applicationId, value)))] };
}

export function resourceChallenge(metadataURI: string, error?: "invalid_token" | "insufficient_scope", description?: string) {
  const quote = (value: string) => {
    if (typeof value !== "string" || /[^\x20-\x7e]/.test(value)) throw new Error("Invalid challenge value");
    return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
  };
  if (error !== undefined && error !== "invalid_token" && error !== "insufficient_scope") throw new Error("Invalid challenge error");
  return `Bearer resource_metadata=${quote(httpsURI(metadataURI))}${error ? `, error=${quote(error)}` : ""}${description !== undefined ? `, error_description=${quote(description)}` : ""}`;
}

/** Every successful call includes a fresh machine-authenticated authorization check. */
export function createResourceAuthorizer(options: Omit<VerifierOptions, "audience"> & {
  resource: string;
  machineClient: { checkResourceAccess(input: ResourceAccessCheckRequest): Promise<ResourceAccessCheckResponse> };
}) {
  const resource = httpsURI(options.resource);
  if (!uuid.test(options.applicationId)) throw new Error("Invalid application ID");
  const issuer = options.issuer.replace(/\/$/, "");
  const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks.json`), {
    ...(options.fetch ? { [customFetch]: options.fetch } : {}),
    timeoutDuration: options.timeoutMs ?? 5_000, cacheMaxAge: 300_000, cooldownDuration: 30_000,
  });
  return async (token: string, capability: string, workspaceId?: string): Promise<ResourceClaims> => {
    if (typeof token !== "string" || new TextEncoder().encode(token).length > 16_384) throw new Error("Resource token exceeds 16 KiB");
    const expected = capabilityScope(options.applicationId, capability);
    if (workspaceId !== undefined && !uuid.test(workspaceId)) throw new Error("Invalid workspace ID");
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer, audience: resource, algorithms: ["RS256"], typ: "JWT", clockTolerance: options.clockToleranceSeconds ?? 30,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat", "nbf", "application_id", "token_kind", "actor_type", "scope", "roles", "sid", "client_id", "connection_id"],
    });
    const audience = payload.aud;
    const roles = payload.roles as ResourceClaims["roles"] | undefined;
    const prefix = `/applications/${options.applicationId}/`;
    const scopes = typeof payload.scope === "string" && payload.scope !== "" ? payload.scope.split(" ") : [];
    if (typeof protectedHeader.kid !== "string" || !protectedHeader.kid ||
      !(audience === resource || Array.isArray(audience) && audience.length === 1 && audience[0] === resource) ||
      payload.application_id !== options.applicationId || payload.actor_type !== "user" || payload.token_kind !== "resource_access" ||
      ![payload.sub, payload.sid, payload.connection_id].every(value => typeof value === "string" && uuid.test(value)) ||
      typeof payload.client_id !== "string" || payload.client_id === "" || /[^\x21-\x7e]/.test(payload.client_id) ||
      ["act", "workspace_id", "workspace_ids", "workspaces"].some(key => key in payload) ||
      typeof payload.iat !== "number" || payload.iat > Date.now() / 1000 + (options.clockToleranceSeconds ?? 30) ||
      typeof payload.scope !== "string" || !scopes.length || new Set(scopes).size !== scopes.length ||
      !scopes.every(value => protocolScopes.has(value) || value.startsWith(prefix) && value.slice(prefix.length).split("/").every(part => segment.test(part)) && value.slice(prefix.length).replaceAll("/", ":").length <= 160 && !["roles", "workspaces"].includes(value.slice(prefix.length).split("/")[0] ?? "")) ||
      !scopes.includes(expected) || !roles || Object.keys(roles).sort().join(",") !== "application,workspaces" ||
      !Array.isArray(roles.application) || roles.application.length !== 0 || !roles.workspaces || typeof roles.workspaces !== "object" || Array.isArray(roles.workspaces) || Object.keys(roles.workspaces).length !== 0) {
      throw new Error("Platform93 resource token rejected");
    }
    const result = await options.machineClient.checkResourceAccess({ token, resource, capability, ...(workspaceId === undefined ? {} : { workspace_id: workspaceId }) });
    if (!result || result.allowed !== true || typeof result.reason !== "string" ||
      ![result.user_id, result.connection_id, result.workspace_id].every(value => value === undefined || typeof value === "string" && uuid.test(value)) ||
      result.user_id !== undefined && result.user_id !== payload.sub || result.connection_id !== undefined && result.connection_id !== payload.connection_id ||
      result.workspace_id !== undefined && result.workspace_id !== workspaceId) throw new Error("Platform93 resource access denied");
    return payload as ResourceClaims;
  };
}
