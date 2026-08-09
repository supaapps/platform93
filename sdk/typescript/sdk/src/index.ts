export * as generated from "./generated/index.js";

export type Platform93ClientOptions = {
  baseUrl: string;
  applicationId?: string;
  accessToken?: () => string | null | Promise<string | null>;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
};

export type Problem = {
  type: string;
  title: string;
  status: number;
  detail?: string;
  code: string;
  request_id?: string;
  errors?: Record<string, unknown>;
};

export class Platform93Error extends Error {
  constructor(public readonly problem: Problem) {
    super(problem.detail ?? problem.title);
    this.name = "Platform93Error";
  }
}

export class Platform93Client {
  readonly baseUrl: string;
  readonly applicationId?: string;
  readonly timeoutMs: number;
  private readonly token?: Platform93ClientOptions["accessToken"];
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: Platform93ClientOptions) {
    if (!options.baseUrl) throw new Error("Platform93 baseUrl is required");
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.applicationId = options.applicationId;
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.token = options.accessToken;
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  application(id = this.applicationId): ApplicationClient {
    if (!id) throw new Error("Platform93 applicationId is required for this operation");
    return new ApplicationClient(this, id);
  }

  async request<T>(method: string, path: string, body?: unknown, options: { idempotencyKey?: string; signal?: AbortSignal; headers?: Record<string, string> } = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const abort = () => controller.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    try {
      const token = await this.token?.();
      const response = await this.fetcher(`${this.baseUrl}${path}`, {
        method,
        signal: controller.signal,
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(options.idempotencyKey ? { "Idempotency-Key": options.idempotencyKey } : {}),
          ...options.headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (!response.ok) {
        const fallback: Problem = { type: "about:blank", title: response.statusText, status: response.status, code: "http_error" };
        throw new Platform93Error(await response.json().catch(() => fallback));
      }
      if (response.status === 204) return undefined as T;
      return response.json() as Promise<T>;
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
    }
  }
}

export class ApplicationClient {
  constructor(private readonly client: Platform93Client, readonly id: string) {}
  private path(path: string) { return `/v1/applications/${encodeURIComponent(this.id)}${path}`; }
  publicConfig() { return this.client.request<RuntimeConfig>("GET", this.path("/public-config")); }
  listCatalog() { return this.client.request<Page<Product>>("GET", this.path("/catalog/products")); }
  signUp(input: PasswordSignUp) { return this.client.request<AuthenticationResult>("POST", this.path("/auth/password/sign-up"), input); }
  signIn(input: PasswordSignIn) { return this.client.request<AuthenticationResult>("POST", this.path("/auth/password/sign-in"), input); }
  refresh(refreshToken: string) { return this.client.request<TokenResponse>("POST", this.path("/auth/token/refresh"), { refresh_token: refreshToken }); }
  startEmail(input: EmailStart) { return this.client.request<{ challenge_id: string; expires_in: number }>("POST", this.path("/auth/email/start"), input); }
  verifyEmail(input: EmailVerify) { return this.client.request<AuthenticationResult>("POST", this.path("/auth/email/verify"), input); }
  verifyMFA(input: MFAVerify) { return this.client.request<TokenResponse>("POST", this.path("/auth/mfa/verify"), input); }
  authMethods(email?: string) { return this.client.request<AuthMethods>("POST", this.path("/auth/methods"), email ? { email } : {}); }
  me() { return this.client.request<User>("GET", this.path("/me")); }
  updateMe(input: Partial<Pick<User, "first_name" | "last_name" | "username" | "locale">>) { return this.client.request<void>("PATCH", this.path("/me"), input); }
  listSessions() { return this.client.request<Page<Record<string, unknown>>>("GET", this.path("/me/sessions")); }
  revokeSession(sessionId: string) { return this.client.request<void>("DELETE", this.path(`/me/sessions/${encodeURIComponent(sessionId)}`)); }
  logout() { return this.client.request<void>("POST", this.path("/auth/logout"), {}); }
  logoutAll() { return this.client.request<void>("POST", this.path("/me/logout-all"), {}); }
  listWorkspaces() { return this.client.request<Page<Record<string, unknown>>>("GET", this.path("/me/workspaces")); }
  createWorkspace(input: { key: string; name: string; metadata?: Record<string, unknown> }) { return this.client.request<Record<string, unknown>>("POST", this.path("/me/workspaces"), input); }
  getWorkspace(workspaceId: string) { return this.client.request<Record<string, unknown>>("GET", this.path(`/workspaces/${encodeURIComponent(workspaceId)}`)); }
  updateWorkspace(workspaceId: string, input: Record<string, unknown>) { return this.client.request<void>("PATCH", this.path(`/workspaces/${encodeURIComponent(workspaceId)}`), input); }
  archiveWorkspace(workspaceId: string) { return this.client.request<void>("DELETE", this.path(`/workspaces/${encodeURIComponent(workspaceId)}`)); }
  transferWorkspaceOwnership(workspaceId: string, input: { new_owner_user_id: string; previous_owner_disposition?: "member" | "remove" }) { return this.client.request<WorkspaceOwnershipTransferResult>("POST", this.path(`/workspaces/${encodeURIComponent(workspaceId)}/owner-transfer`), input); }
  leaveWorkspace(workspaceId: string) { return this.client.request<void>("DELETE", this.path(`/workspaces/${encodeURIComponent(workspaceId)}/membership`)); }
  getBillingProfile(workspaceId?: string) { return this.client.request<BillingProfile>("GET", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/billing-profile` : "/me/billing-profile")); }
  updateBillingProfile(input: Partial<BillingProfile> & { version: number }, workspaceId?: string) { return this.client.request<void>("PATCH", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/billing-profile` : "/me/billing-profile"), input); }
  listAddresses(workspaceId?: string) { return this.client.request<Page<BillingAddress>>("GET", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/addresses` : "/me/addresses")); }
  createAddress(input: Omit<BillingAddress, "id" | "version">, workspaceId?: string) { return this.client.request<{ id: string; active: boolean }>("POST", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/addresses` : "/me/addresses"), input); }
  listEntitlements(workspaceId?: string) { return this.client.request<EffectiveEntitlements>("GET", this.path(`/me/entitlements${workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : ""}`)); }
  listLocalRequests() { return this.client.request<Page<LocalEntitlementRequest>>("GET", this.path("/me/local-entitlement-requests")); }
  getLocalRequest(requestId: string) { return this.client.request<LocalEntitlementRequest>("GET", this.path(`/me/local-entitlement-requests/${encodeURIComponent(requestId)}`)); }
  cancelLocalRequest(requestId: string) { return this.client.request<void>("POST", this.path(`/me/local-entitlement-requests/${encodeURIComponent(requestId)}/cancel`), {}); }
  localCheckout(input: LocalCheckoutInput, idempotencyKey?: string) { return this.client.request<LocalEntitlementRequest>("POST", this.path("/local-entitlement-checkouts"), input, { idempotencyKey }); }
  checkout(input: CheckoutInput, idempotencyKey?: string) { return this.client.request<CheckoutSession>("POST", this.path("/billing/checkout-sessions"), input, { idempotencyKey }); }
  checkoutSession(sessionId: string) { return this.client.request<CheckoutSession>("GET", this.path(`/billing/checkout-sessions/${encodeURIComponent(sessionId)}`)); }
  portal(input: { provider_id: string; subject_type?: "user" | "workspace"; subject_id?: string; return_uri: string }, idempotencyKey?: string) { return this.client.request<{ portal_uri: string }>("POST", this.path("/billing/portal-sessions"), input, { idempotencyKey }); }
  billingSummary() { return this.client.request<Record<string, unknown>>("GET", this.path("/me/billing")); }
  listSubscriptions() { return this.client.request<Page<Record<string, unknown>>>("GET", this.path("/me/subscriptions")); }
  listInvoices() { return this.client.request<Page<Record<string, unknown>>>("GET", this.path("/me/invoices")); }
  listPayments() { return this.client.request<Page<Record<string, unknown>>>("GET", this.path("/me/payments")); }
  publishEvent<T extends Record<string, unknown>>(input: PublishCustomEvent<T>, idempotencyKey: string) { return this.client.request<PublishedEvent<T>>("POST", this.path("/events"), input, { idempotencyKey }); }
}

export type Page<T> = { items: T[]; next_cursor: string | null };
export type ApplicationFlowConfig = { oauth_client_id: string; sign_in_redirect_uri: string; invitation_redirect_uri: string };
export type RuntimeConfig = { schema_version: string; api_base: string; issuer: string; application_id: string; public_config: Record<string, unknown>; auth: { registration_mode: "public" | "invite_only"; registration_enabled: boolean; password_enabled: boolean; passwordless_enabled: boolean; flows?: ApplicationFlowConfig } };
export type User = { id: string; application_id: string; email: string; first_name: string; last_name: string; username: string | null; locale: string; email_verified: boolean; is_org_verified: boolean; status: string; custom_attributes: Record<string, unknown>; version: number };
export type FeatureValue = {
  feature_id: string;
  key: string;
  name: string;
  value_type: "boolean" | "quantity" | "free_form";
  free_form_format?: "text" | "csv" | "json";
  boolean_value?: boolean;
  quantity_value?: number;
  free_form_value?: unknown;
  value: unknown;
};
export type Product = { id: string; key: string; name: string; description: string; status: string; entitlement_config: Record<string, unknown>; features: FeatureValue[]; prices: Price[] };
export type Price = { id: string; key: string; mode: "recurring" | "one_time" | "local"; amount_minor: number; currency: string; currency_exponent: number; tax_behavior: string; checkout_config: Record<string, unknown>; entitlement_config: Record<string, unknown>; features: FeatureValue[] };
export type TokenResponse = { access_token: string; refresh_token: string; token_type: "Bearer"; expires_in: number };
export type MFAChallenge = { mfa_required: true; challenge_id: string; methods: string[]; expires_in: number };
export type AuthenticationResult = TokenResponse | MFAChallenge;
export type MFAVerify = { challenge_id: string; code?: string; recovery_code?: string };
export type AuthMethods = { methods: string[]; registration_enabled: boolean; registration_mode: "public" | "invite_only" };
export type PasswordSignIn = { email: string; password: string };
export type PasswordSignUp = PasswordSignIn & { first_name?: string; last_name?: string };
export type EmailStart = { email: string; intent: "sign_in" | "sign_up" | "automatic"; delivery: "code" | "link" | "both"; redirect_uri?: string };
export type EmailVerify = { challenge_id: string; code?: string; link_token?: string };
export type LocalCheckoutInput = { price_id: string; subject_type?: "user" | "workspace"; subject_id?: string; address_id?: string; local_reference?: string };
export type CheckoutInput = { price_id: string; provider_id: string; subject_type?: "user" | "workspace"; subject_id?: string; payment_methods?: Array<"card" | "twint">; success_uri: string; cancel_uri: string };
export type CheckoutSession = { id: string; status: string; checkout_uri: string; provider_session_id: string };
export type LocalEntitlementRequest = { id: string; status: string; product_snapshot: Record<string, unknown>; price_snapshot: Record<string, unknown>; feature_snapshot: Record<string, unknown>; address_snapshot: Record<string, unknown> | null; history?: Array<Record<string, unknown>> };
export type EffectiveEntitlements = { effective: Record<string, boolean | number | unknown>; provenance: Record<string, Array<Record<string, unknown>>>; sources: Array<Record<string, unknown>> };
export type BillingProfile = { id: string; subject_type: "user" | "workspace"; subject_id: string; name: string; email: string | null; tax_id: string | null; version: number };
export type WorkspaceOwnershipTransferResult = { workspace_id: string; owner_user_id: string; previous_owner_user_id: string; previous_owner_disposition: "member" | "remove" };
export type BillingAddress = { id: string; name: string; line1: string; line2: string; city: string; region: string; postal_code: string; country_code: string; tax_id?: string | null; active: boolean; version: number };
export type PublishCustomEvent<T extends Record<string, unknown> = Record<string, unknown>> = { type: string; subject: string; data: T; correlation_id?: string; causation_id?: string };
export type PublishedEvent<T extends Record<string, unknown> = Record<string, unknown>> = PublishCustomEvent<T> & { specversion: "1.0"; id: string; source: string; schema_version: string };
