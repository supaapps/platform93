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
  affected_users?: number;
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
  startExternalAuth(provider: ExternalAuthProvider, input: ExternalAuthStart) { return this.client.request<ExternalAuthAuthorization>("POST", this.path(`/auth/providers/${provider}/start`), input); }
  exchangeExternalAuth(provider: ExternalAuthProvider, exchange: string, codeVerifier?: string) { return this.client.request<AuthenticationResult>("POST", this.path(`/auth/providers/${provider}/exchange`), { exchange, ...(codeVerifier ? { code_verifier: codeVerifier } : {}) }); }
  startGoogleAuth(input: ExternalAuthStart) { return this.startExternalAuth("google", input); }
  exchangeGoogleAuth(exchange: string, codeVerifier?: string) { return this.exchangeExternalAuth("google", exchange, codeVerifier); }
  startAppleAuth(input: ExternalAuthStart) { return this.startExternalAuth("apple", input); }
  exchangeAppleAuth(exchange: string, codeVerifier?: string) { return this.exchangeExternalAuth("apple", exchange, codeVerifier); }
  startMicrosoftAuth(input: ExternalAuthStart) { return this.startExternalAuth("microsoft", input); }
  exchangeMicrosoftAuth(exchange: string, codeVerifier?: string) { return this.exchangeExternalAuth("microsoft", exchange, codeVerifier); }
  startFacebookAuth(input: ExternalAuthStart) { return this.startExternalAuth("facebook", input); }
  exchangeFacebookAuth(exchange: string, codeVerifier?: string) { return this.exchangeExternalAuth("facebook", exchange, codeVerifier); }
  startLinkedInAuth(input: ExternalAuthStart) { return this.startExternalAuth("linkedin", input); }
  exchangeLinkedInAuth(exchange: string, codeVerifier?: string) { return this.exchangeExternalAuth("linkedin", exchange, codeVerifier); }
  startExternalEmailEnrollment(input: ExternalEmailEnrollmentStart) { return this.client.request<ExternalEmailEnrollmentChallenge>("POST", this.path("/auth/external-email/start"), input); }
  verifyExternalEmailEnrollment(input: ExternalEmailEnrollmentVerify) { return this.client.request<AuthenticationResult>("POST", this.path("/auth/external-email/verify"), input); }
  startApplicationInvitationProvider(provider: ExternalAuthProvider, input: InvitationExchange) { return this.client.request<ExternalAuthAuthorization>("POST", this.path(`/auth/invitations/providers/${provider}/start`), input); }
  exchangeInvitation(input: InvitationExchange) { return this.client.request<InvitationAuthorizationCode>("POST", this.path("/auth/invitations/exchange"), input); }
  redeemInvitation(input: { authorization_code: string; code_verifier: string }) { return this.client.request<AuthenticationResult>("POST", this.path("/auth/invitations/token"), input); }
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
  listWorkspaceAccess(workspaceId: string) { return this.client.request<Page<WorkspaceAccessEntry>>("GET", this.path(`/workspaces/${encodeURIComponent(workspaceId)}/access`)); }
  createWorkspaceInvitation(workspaceId: string, input: Omit<CreateInvitation, "workspace_id" | "application_role_keys">) { return this.client.request<Invitation>("POST", this.path(`/workspaces/${encodeURIComponent(workspaceId)}/invitations`), input); }
  listWorkspaceInvitations(workspaceId: string) { return this.client.request<Page<Invitation>>("GET", this.path(`/workspaces/${encodeURIComponent(workspaceId)}/invitations`)); }
  resendWorkspaceInvitation(workspaceId: string, invitationId: string) { return this.client.request<Invitation>("POST", this.path(`/workspaces/${encodeURIComponent(workspaceId)}/invitations/${encodeURIComponent(invitationId)}/resend`)); }
  revokeWorkspaceInvitation(workspaceId: string, invitationId: string) { return this.client.request<void>("DELETE", this.path(`/workspaces/${encodeURIComponent(workspaceId)}/invitations/${encodeURIComponent(invitationId)}`)); }
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
  listStorageObjects(workspaceId?: string) { return this.client.request<Page<StorageObject>>("GET", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/storage/objects` : "/me/storage/objects")); }
  createStorageUpload(input: CreateStorageUpload, idempotencyKey: string, workspaceId?: string) { return this.client.request<StorageUploadAuthorization>("POST", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/storage/uploads` : "/me/storage/uploads"), input, { idempotencyKey }); }
  async putStorageUpload(authorization: StorageUploadAuthorization, body: BodyInit, signal?: AbortSignal) {
    const headers = new Headers(authorization.required_headers);
    headers.delete("authorization");
    headers.delete("content-length");
    const response = await fetch(authorization.upload_url, { method: "PUT", headers, body, signal });
    if (!response.ok) throw new Error(`Storage upload returned HTTP ${response.status}`);
  }
  completeStorageUpload(objectId: string, workspaceId?: string) { return this.client.request<StorageObject>("POST", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/storage/uploads/${encodeURIComponent(objectId)}/complete` : `/me/storage/uploads/${encodeURIComponent(objectId)}/complete`)); }
  storageDownload(objectId: string, workspaceId?: string) { return this.client.request<StorageDownload>("POST", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/storage/objects/${encodeURIComponent(objectId)}/download` : `/me/storage/objects/${encodeURIComponent(objectId)}/download`)); }
  deleteStorageObject(objectId: string, workspaceId?: string) { return this.client.request<void>("DELETE", this.path(workspaceId ? `/workspaces/${encodeURIComponent(workspaceId)}/storage/objects/${encodeURIComponent(objectId)}` : `/me/storage/objects/${encodeURIComponent(objectId)}`)); }
}

export type Page<T> = { items: T[]; next_cursor: string | null };
export type ApplicationFlowConfig = { oauth_client_id: string; sign_in_redirect_uri: string; invitation_redirect_uri: string };
export type RuntimeStorageConfig = { public_uploads_enabled: boolean; private_uploads_enabled: boolean; max_public_object_bytes?: number; max_private_object_bytes?: number; max_email_image_bytes?: number; public_provider_scope?: "installation" | "organization" | "application"; private_provider_scope?: "installation" | "organization" | "application" };
export type RuntimeConfig = { schema_version: string; api_base: string; issuer: string; application_id: string; public_config: Record<string, unknown>; auth: { registration_mode: "public" | "invite_only"; registration_enabled: boolean; password_enabled: boolean; passwordless_enabled: boolean; flows?: ApplicationFlowConfig }; storage: RuntimeStorageConfig };
export type CreateStorageUpload = { filename: string; content_type: string; size_bytes: number; visibility: "public" | "private"; purpose?: "email_image"; metadata?: Record<string, unknown> };
export type StorageObject = { id: string; application_id: string | null; provider_id: string; owner_type: "installation" | "application" | "user" | "workspace"; owner_id: string | null; visibility: "public" | "private"; filename: string; content_type: string; size_bytes: number; etag: string | null; metadata: Record<string, unknown>; status: "pending" | "ready" | "deleting" | "failed"; public_url: string | null; upload_expires_at: string | null; ready_at: string | null; last_error: string | null; version: number; created_at: string; updated_at: string };
export type StorageUploadAuthorization = { object: StorageObject; upload_url: string; upload_expires_at: string; required_headers: Record<string, string> };
export type StorageDownload = { url: string; expires_at: string | null; visibility: "public" | "private" };
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
export type ExternalAuthProvider = "google" | "apple" | "microsoft" | "facebook" | "linkedin";
export type ExternalAuthFlow = "sign_in" | "sign_up" | "automatic";
export type ExternalAuthStart = { redirect_uri: string; flow?: ExternalAuthFlow; login_hint?: string; code_challenge?: string };
export type ExternalAuthAuthorization = { provider: ExternalAuthProvider; authorize_url: string; expires_in: number };
export type ExternalEmailEnrollmentContinuation = { kind: "email_verification_required"; provider: "microsoft" | "facebook" | "linkedin"; enrollment: string };
export type ExternalEmailEnrollmentStart = { enrollment: string; email: string; code_verifier: string; delivery?: "code" | "link" | "both" };
export type ExternalEmailEnrollmentChallenge = { challenge_id: string; provider: "microsoft" | "facebook" | "linkedin"; expires_in: number };
export type ExternalEmailEnrollmentVerify = { enrollment: string; code?: string; link_token?: string };
export type LocalCheckoutInput = { price_id: string; subject_type?: "user" | "workspace"; subject_id?: string; address_id?: string; external_reference?: string };
export type CheckoutInput = { price_id: string; provider_id?: string; subject_type?: "user" | "workspace"; subject_id?: string; payment_methods?: Array<"card" | "twint">; success_uri: string; cancel_uri: string; external_reference?: string };
export type CheckoutSession = { id: string; status: string; checkout_uri: string; provider_session_id: string; external_reference?: string | null };
export type LocalEntitlementRequest = { id: string; status: string; external_reference?: string | null; product_snapshot: Record<string, unknown>; price_snapshot: Record<string, unknown>; feature_snapshot: Record<string, unknown>; address_snapshot: Record<string, unknown> | null; history?: Array<Record<string, unknown>> };
export type EffectiveEntitlements = { effective: Record<string, boolean | number | unknown>; provenance: Record<string, Array<Record<string, unknown>>>; sources: Array<Record<string, unknown>> };
export type BillingProfile = { id: string; subject_type: "user" | "workspace"; subject_id: string; name: string; email: string | null; tax_id: string | null; version: number };
export type WorkspaceOwnershipTransferResult = { workspace_id: string; owner_user_id: string; previous_owner_user_id: string; previous_owner_disposition: "member" | "remove" };
export type BillingAddress = { id: string; name: string; line1: string; line2: string; city: string; region: string; postal_code: string; country_code: string; tax_id?: string | null; active: boolean; version: number };
export type PublishCustomEvent<T extends Record<string, unknown> = Record<string, unknown>> = { type: string; subject: string; data: T; correlation_id?: string; causation_id?: string };
export type PublishedEvent<T extends Record<string, unknown> = Record<string, unknown>> = PublishCustomEvent<T> & { specversion: "1.0"; id: string; source: string; schema_version: string };
export type InvitationOnboardingMethod = "email" | ExternalAuthProvider;
export type CreateInvitation = { email: string; workspace_id?: string; application_role_keys?: string[]; workspace_role_keys?: string[]; onboarding_method?: InvitationOnboardingMethod; expires_in?: number };
export type Invitation = { id: string; application_id: string; email: string; workspace_id?: string | null; application_role_keys: string[]; workspace_role_keys: string[]; onboarding_method: InvitationOnboardingMethod; status: "pending" | "accepted" | "revoked" | "expired"; expires_at: string; last_sent_at: string; resend_available_at: string };
export type InvitationCredential = { email: string; code: string; invitation_id?: never; link_token?: never } | { invitation_id: string; link_token: string; email?: never; code?: never };
export type InvitationExchange = InvitationCredential & { code_challenge: string };
export type InvitationAuthorizationCode = { authorization_code: string; expires_in: number };
export type WorkspaceAccessEntry = { entry_type: "user"; status: "owner" | "active"; user_id: string; email: string; first_name: string; last_name: string; role_keys: string[] } | { entry_type: "invitation"; status: "pending" | "expired"; invitation_id: string; email: string; role_keys: string[]; expires_at: string; last_sent_at: string; resend_available_at: string };
