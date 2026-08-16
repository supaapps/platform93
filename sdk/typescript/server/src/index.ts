import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload } from "jose";
import {
  Platform93Client,
  Platform93Error,
  generated,
  type CreateInvitation,
  type Invitation,
  type Page,
  type PublishCustomEvent,
  type PublishedEvent,
  type User,
} from "@supaapps/platform93-sdk";

export type Platform93Claims = JWTPayload & {
  application_id: string;
  token_kind: "access" | "machine";
  actor_type: "user" | "client";
  scope: string;
  roles: { application: string[]; workspaces: Record<string, string[]> };
  locale?: string;
  email_verified?: boolean;
  is_org_verified?: boolean;
  custom_claims?: Record<string, unknown>;
  act?: { sub: string; type: string };
};

export type VerifierOptions = {
  issuer: string;
  audience: string;
  applicationId: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  clockToleranceSeconds?: number;
};

export function createVerifier(options: VerifierOptions) {
  const issuer = options.issuer.replace(/\/$/, "");
  const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks.json`), {
    ...(options.fetch ? { [customFetch]: options.fetch } : {}),
    timeoutDuration: options.timeoutMs ?? 5_000,
    cacheMaxAge: 300_000,
    cooldownDuration: 30_000,
  });
  return async (token: string) => {
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer,
      audience: options.audience,
      algorithms: ["RS256"],
      typ: "JWT",
      clockTolerance: options.clockToleranceSeconds ?? 30,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat", "nbf", "application_id", "token_kind", "actor_type", "scope", "roles"],
    });
    const claims = payload as Platform93Claims;
    const tolerance = options.clockToleranceSeconds ?? 30;
    const now = Math.floor(Date.now() / 1000);
    if (!protectedHeader.kid || claims.application_id !== options.applicationId ||
      !(claims.token_kind === "access" && claims.actor_type === "user" || claims.token_kind === "machine" && claims.actor_type === "client") || typeof claims.sub !== "string" || claims.sub === "" ||
      typeof claims.iat !== "number" || claims.iat > now + tolerance) {
      throw new Error("Platform93 token context rejected");
    }
    if (claims.act && (claims.token_kind !== "access" || claims.act.type !== "control_user" || !claims.act.sub)) {
      throw new Error("Platform93 delegated token actor rejected");
    }
    if (!validScopeClaim(claims.scope, options.applicationId) || !validRolesClaim(claims.roles) ||
      claims.act && (claims.roles.application.length !== 0 || Object.keys(claims.roles.workspaces).length !== 0)) {
      throw new Error("Platform93 token authorization claims rejected");
    }
    return claims;
  };
}

export function hasPermission(claims: Platform93Claims, permission: string) {
  if (!validAbsolutePermission(permission)) return false;
  return claims.scope.split(" ").some((value) => validAbsolutePermission(value) &&
    (value === permission || value.endsWith("/*") && (permission === value.slice(0, -2) || permission.startsWith(value.slice(0, -1)))));
}

const permissionSegment = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const roleKey = /^[a-z][a-z0-9_-]{0,62}$/;
const workspaceKey = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const protocolScopes = new Set(["openid", "profile", "email", "offline_access"]);

function validScopeClaim(scope: unknown, applicationId: string) {
  if (typeof scope !== "string") return false;
  if (scope === "") return true;
  if (scope !== scope.trim() || /[\t\r\n]| {2}/.test(scope)) return false;
  const values = scope.split(" ");
  if (new Set(values).size !== values.length) return false;
  const prefix = `/applications/${applicationId}/`;
  return values.every((value) => protocolScopes.has(value) || value.startsWith(prefix) && validAbsolutePermission(value));
}

function validAbsolutePermission(value: string) {
  if (!value.startsWith("/") || /[ :\\%\t\r\n]/.test(value)) return false;
  const segments = value.slice(1).split("/");
  return segments.length >= 3 && segments.every((segment, index) =>
    segment === "*" ? index === segments.length - 1 : permissionSegment.test(segment));
}

function validRolesClaim(value: unknown): value is Platform93Claims["roles"] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const roles = value as Record<string, unknown>;
  if (Object.keys(roles).sort().join(",") !== "application,workspaces") return false;
  if (!Array.isArray(roles.application) || !roles.workspaces || typeof roles.workspaces !== "object" || Array.isArray(roles.workspaces)) return false;
  if (!uniqueRoleKeys(roles.application)) return false;
  return Object.entries(roles.workspaces as Record<string, unknown>).every(([workspaceId, values]) =>
    workspaceKey.test(workspaceId) && Array.isArray(values) && uniqueRoleKeys(values));
}

function uniqueRoleKeys(values: unknown[]) {
  return values.every((value) => typeof value === "string" && roleKey.test(value)) && new Set(values).size === values.length;
}

export type MachineClientOptions = {
  baseUrl: string;
  applicationId: string;
  clientId: string;
  clientSecret: string;
  scopes?: string[];
  fetch?: typeof globalThis.fetch;
};

export type MachineNotification = {
  template_key: string;
  user_id?: string;
  recipient?: string;
  locale?: string;
  variables?: Record<string, unknown>;
  attachments?: Array<{ filename: string; content_type: string; content_base64: string }>;
};

export class Platform93MachineClient {
  private readonly baseUrl: string;
  private readonly applicationId: string;
  private readonly clientId: string;
  private clientSecret: string;
  private readonly scopes: string[];
  private readonly fetcher: typeof globalThis.fetch;
  private accessToken: string | null = null;
  private expiresAt = 0;
  private tokenRequest: Promise<string> | null = null;
  private readonly api: Platform93Client;

  constructor(options: MachineClientOptions) {
    if (!options.baseUrl || !options.applicationId || !options.clientId || !options.clientSecret) {
      throw new Error("Platform93 machine client requires baseUrl, applicationId, clientId, and clientSecret");
    }
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.applicationId = options.applicationId;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.scopes = options.scopes ?? [];
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.api = new Platform93Client({
      baseUrl: this.baseUrl,
      applicationId: this.applicationId,
      fetch: this.fetcher,
      accessToken: () => this.token(),
    });
  }

  updateSecret(secret: string) {
    if (!secret) throw new Error("Platform93 machine client secret is required");
    this.clientSecret = secret;
    this.accessToken = null;
    this.expiresAt = 0;
  }

  async token() {
    if (this.accessToken && Date.now() < this.expiresAt - 30_000) return this.accessToken;
    if (this.tokenRequest) return this.tokenRequest;
    this.tokenRequest = this.exchangeToken().finally(() => { this.tokenRequest = null; });
    return this.tokenRequest;
  }

  sendNotification(input: MachineNotification, idempotencyKey: string) {
    return this.request<generated.QueuedNotification>("POST", "/notifications", input, idempotencyKey);
  }
  createInvitation(input: CreateInvitation) { return this.request<Invitation>("POST", "/invitations", input); }
  listInvitations() { return this.request<Page<Invitation>>("GET", "/invitations"); }
  getInvitation(id: string) { return this.request<Invitation>("GET", `/invitations/${encodeURIComponent(id)}`); }
  resendInvitation(id: string) { return this.request<generated.InvitationResent>("POST", `/invitations/${encodeURIComponent(id)}/resend`); }
  revokeInvitation(id: string) { return this.request<void>("DELETE", `/invitations/${encodeURIComponent(id)}`); }
  listUsers() { return this.request<Page<User>>("GET", "/users"); }
  getUser(id: string) { return this.request<User>("GET", `/users/${encodeURIComponent(id)}`); }
  listWorkspaces() { return this.request<generated.WorkspacePage>("GET", "/workspaces"); }
  getWorkspace(id: string) { return this.request<generated.Workspace>("GET", `/service/workspaces/${encodeURIComponent(id)}`); }
  getWorkspaceAccess(id: string) { return this.request<generated.WorkspaceAccessPage>("GET", `/service/workspaces/${encodeURIComponent(id)}/access`); }
  getEntitlements(subjectType: "user" | "workspace", subjectId: string) { return this.request<generated.EntitlementGrantPage>("GET", `/subjects/${subjectType}/${encodeURIComponent(subjectId)}/entitlements`); }
  getBilling(subjectType: "user" | "workspace", subjectId: string) { return this.request<generated.BillingSummary>("GET", `/subjects/${subjectType}/${encodeURIComponent(subjectId)}/billing`); }
  publishEvent<T extends Record<string, unknown>>(input: PublishCustomEvent<T>, idempotencyKey: string) { return this.request<PublishedEvent<T>>("POST", "/events", input, idempotencyKey); }

  private async exchangeToken() {
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    if (this.scopes.length) body.set("scope", this.scopes.join(" "));
    const response = await this.fetcher(`${this.baseUrl}/oidc/token`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa(`${this.clientId}:${this.clientSecret}`)}`,
      },
      body,
    });
    if (!response.ok) throw new Error(`Platform93 client credentials exchange failed with HTTP ${response.status}`);
    const payload = await response.json() as { access_token?: string; expires_in?: number };
    if (!payload.access_token) throw new Error("Platform93 token response did not contain an access token");
    this.accessToken = payload.access_token;
    this.expiresAt = Date.now() + Math.max(1, payload.expires_in ?? 300) * 1000;
    return payload.access_token;
  }

  private request<T>(method: string, path: string, body?: unknown, idempotencyKey?: string) {
    return this.api.request<T>(method, `/v1/applications/${encodeURIComponent(this.applicationId)}${path}`, body, { idempotencyKey });
  }
}

export { Platform93Error };
