import {
  Platform93Client,
  Platform93Error,
  type AuthenticationResult,
  type ApplicationFlowConfig,
  type EmailStart,
  type EmailVerify,
  type ExternalAuthAuthorization,
  type ExternalEmailEnrollmentChallenge,
  type ExternalEmailEnrollmentContinuation,
  type ExternalAuthFlow,
  type ExternalAuthProvider,
  type InvitationCredential,
  type MFAChallenge,
  type MFAVerify,
  type PasswordSignIn,
  type PasswordSignUp,
  type TokenResponse,
} from "@supaapps/platform93-sdk";

export type AuthSnapshot = {
  status: "anonymous" | "authenticated" | "refreshing";
  accessToken: string | null;
};

export type PKCEAuthorizationRequest = {
  authorizationUrl: string;
  codeVerifier: string;
  state: string;
  clientId: string;
  redirectUri: string;
};

export type PKCEAuthorizationOptions = {
  scopes?: string[];
  state?: string;
  nonce?: string;
  clientId?: string;
  redirectUri?: string;
};

export type ExternalAuthStartOptions = {
  redirectUri: string;
  flow?: ExternalAuthFlow;
  loginHint?: string;
};

export type PendingExternalAuth = { provider: ExternalAuthProvider; requestId: string; expiresAt: number };
export type ExternalAuthRequest = ExternalAuthAuthorization & { requestId: string };
export class ExternalAuthRecoveryError extends Error {
  constructor(message: string, readonly recovery: "retry" | "restart" | "cancelled", cause?: unknown) {
    super(message, { cause });
    this.name = "ExternalAuthRecoveryError";
  }
}
type AuthorizationVerifier = { verifier: string; expiresAt: number; requestId: string };

function retryableExchangeError(error: unknown) {
  return error instanceof Platform93Error
    ? error.problem.status === 408 || error.problem.status === 429 || error.problem.status >= 500
    : error instanceof TypeError || error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
}

export type InvitationLink = { applicationId: string; invitationId: string; linkToken: string };

export interface TokenStore {
  loadRefreshToken(): Promise<string | null>;
  saveRefreshToken(value: string | null): Promise<void>;
}

export interface AuthorizationStateStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export class MemoryAuthorizationStateStore implements AuthorizationStateStore {
  private readonly values = new Map<string, string>();
  getItem(key: string) { return this.values.get(key) ?? null; }
  setItem(key: string, value: string) { this.values.set(key, value); }
  removeItem(key: string) { this.values.delete(key); }
}

/** Browser PKCE state is scoped to the current tab and is never used for tokens. */
export class BrowserSessionAuthorizationStateStore implements AuthorizationStateStore {
  private readonly fallback = new MemoryAuthorizationStateStore();
  constructor(private readonly storage: Storage) {}
  getItem(key: string) {
    try { return this.storage.getItem(key) ?? this.fallback.getItem(key); }
    catch { return this.fallback.getItem(key); }
  }
  setItem(key: string, value: string) {
    try { this.storage.setItem(key, value); this.fallback.removeItem(key); }
    catch { this.fallback.setItem(key, value); }
  }
  removeItem(key: string) {
    this.fallback.removeItem(key);
    try { this.storage.removeItem(key); } catch { /* The fallback is already cleared. */ }
  }
}

export class MemoryTokenStore implements TokenStore {
  private value: string | null = null;
  async loadRefreshToken() { return this.value; }
  async saveRefreshToken(value: string | null) { this.value = value; }
}

/** Persistent browser storage is available only through explicit construction. */
export class BrowserStorageTokenStore implements TokenStore {
  constructor(private readonly storage: Storage, private readonly key = "platform93.refresh_token") {}
  async loadRefreshToken() { return this.storage.getItem(this.key); }
  async saveRefreshToken(value: string | null) {
    if (value === null) this.storage.removeItem(this.key);
    else this.storage.setItem(this.key, value);
  }
}

export interface SessionAdapter {
  accept(tokens: TokenResponse): Promise<void>;
  refresh(client: Platform93Client, applicationId: string): Promise<TokenResponse | null>;
  clear(): Promise<void>;
}

export class TokenStoreSessionAdapter implements SessionAdapter {
  constructor(readonly store: TokenStore = new MemoryTokenStore()) {}
  async accept(tokens: TokenResponse) { await this.store.saveRefreshToken(tokens.refresh_token); }
  async refresh(client: Platform93Client, applicationId: string) {
    const refreshToken = await this.store.loadRefreshToken();
    return refreshToken ? client.application(applicationId).refresh(refreshToken) : null;
  }
  async clear() { await this.store.saveRefreshToken(null); }
}

export type BFFCookieAdapterOptions = {
  sessionPath?: string;
  refreshPath?: string;
  logoutPath?: string;
  fetch?: typeof globalThis.fetch;
};

/**
 * Exchanges rotating credentials with an application BFF. The BFF is responsible
 * for storing the refresh credential in a Secure HttpOnly cookie and returning a
 * short-lived access token from its refresh endpoint.
 */
export class BFFCookieSessionAdapter implements SessionAdapter {
  private readonly fetcher: typeof globalThis.fetch;
  private readonly sessionPath: string;
  private readonly refreshPath: string;
  private readonly logoutPath: string;
  constructor(options: BFFCookieAdapterOptions = {}) {
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.sessionPath = options.sessionPath ?? "/api/platform93/session";
    this.refreshPath = options.refreshPath ?? "/api/platform93/session/refresh";
    this.logoutPath = options.logoutPath ?? "/api/platform93/session";
  }
  async accept(tokens: TokenResponse) {
    const response = await this.fetcher(this.sessionPath, {
      method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(tokens),
    });
    if (!response.ok) throw new Error("Platform93 BFF session exchange failed");
  }
  async refresh() {
    const response = await this.fetcher(this.refreshPath, { method: "POST", credentials: "same-origin" });
    if (response.status === 401 || response.status === 404) return null;
    if (!response.ok) throw new Error("Platform93 BFF session refresh failed");
    return response.json() as Promise<TokenResponse>;
  }
  async clear() {
    await this.fetcher(this.logoutPath, { method: "DELETE", credentials: "same-origin" }).catch(() => undefined);
  }
}

export type Platform93AuthOptions = {
  baseUrl: string;
  applicationId: string;
  adapter?: SessionAdapter;
  authorizationStateStore?: AuthorizationStateStore;
  fetch?: typeof globalThis.fetch;
  channelName?: string | false;
};

export class Platform93Auth extends EventTarget {
  private accessToken: string | null = null;
  private accessTokenExpiresAt = 0;
  private status: AuthSnapshot["status"] = "anonymous";
  private refreshPromise: Promise<string | null> | null = null;
  private readonly adapter: SessionAdapter;
  private readonly authorizationStateStore: AuthorizationStateStore;
  private readonly channel: BroadcastChannel | null;
  private readonly source = globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36);
  readonly client: Platform93Client;
  readonly applicationId: string;

  constructor(options: Platform93AuthOptions);
  constructor(baseUrl: string, applicationId: string, store?: TokenStore);
  constructor(optionsOrURL: Platform93AuthOptions | string, applicationId?: string, store?: TokenStore) {
    super();
    const options: Platform93AuthOptions = typeof optionsOrURL === "string"
      ? { baseUrl: optionsOrURL, applicationId: applicationId ?? "", adapter: new TokenStoreSessionAdapter(store) }
      : optionsOrURL;
    if (!options.applicationId) throw new Error("Platform93 applicationId is required");
    this.applicationId = options.applicationId;
    this.adapter = options.adapter ?? new TokenStoreSessionAdapter();
    this.authorizationStateStore = options.authorizationStateStore ?? defaultAuthorizationStateStore();
    this.client = new Platform93Client({
      baseUrl: options.baseUrl,
      applicationId: options.applicationId,
      accessToken: () => this.accessToken,
      fetch: options.fetch,
    });
    const channelName = options.channelName === false ? null : options.channelName ?? `platform93-auth:${options.applicationId}`;
    this.channel = channelName && typeof BroadcastChannel !== "undefined" ? new BroadcastChannel(channelName) : null;
    if (this.channel) this.channel.onmessage = (event: MessageEvent<{ type?: string; source?: string }>) => {
      if (event.data.source === this.source) return;
      if (event.data.type === "logout") void this.clear(false);
      if (event.data.type === "session-changed") void this.refresh(false);
    };
  }

  snapshot(): AuthSnapshot { return { status: this.status, accessToken: this.accessToken }; }
  async getAccessToken(leewaySeconds = 10) {
    if (this.accessToken && Date.now() + leewaySeconds * 1000 < this.accessTokenExpiresAt) return this.accessToken;
    return this.refresh(false);
  }
  signIn(input: PasswordSignIn) { return this.resolve(this.client.application().signIn(input)); }
  signUp(input: PasswordSignUp) { return this.resolve(this.client.application().signUp(input)); }
  startEmail(input: EmailStart) { return this.client.application().startEmail(input); }
  verifyEmail(input: EmailVerify) { return this.resolve(this.client.application().verifyEmail(input)); }
  pendingExternalAuth(provider: ExternalAuthProvider): PendingExternalAuth | null {
    const record = this.loadAuthorizationRecord("provider", provider);
    return record ? { provider, requestId: record.requestId, expiresAt: record.expiresAt } : null;
  }
  /** Pass a request ID when cancelling from a delayed callback or component cleanup. */
  cancelExternalAuth(provider: ExternalAuthProvider, requestId?: string): boolean {
    const record = this.loadAuthorizationRecord("provider", provider);
    if (!record || requestId !== undefined && record.requestId !== requestId) return false;
    return this.removeAuthorizationVerifier("provider", provider, record.verifier);
  }
  restartExternalAuth(provider: ExternalAuthProvider, options: ExternalAuthStartOptions, requestId?: string) {
    this.cancelForRestart(provider, requestId);
    return this.startExternalAuth(provider, options);
  }
  restartApplicationInvitationProvider(provider: ExternalAuthProvider, input: InvitationCredential, requestId?: string) {
    this.cancelForRestart(provider, requestId);
    return this.startApplicationInvitationProvider(provider, input);
  }
  cancelExternalEmailEnrollment(continuation: ExternalEmailEnrollmentContinuation): boolean {
    const verifier = this.loadAuthorizationVerifier("enrollment", continuation.enrollment);
    return !!verifier && this.removeAuthorizationVerifier("enrollment", continuation.enrollment, verifier);
  }
  async startExternalAuth(provider: ExternalAuthProvider, options: ExternalAuthStartOptions): Promise<ExternalAuthRequest> {
    if (this.loadAuthorizationVerifier("provider", provider)) {
      throw new Error(`Platform93 ${provider} authentication already has a request in progress`);
    }
    const codeVerifier = randomBase64URL(32);
    const requestId = this.saveAuthorizationVerifier("provider", provider, codeVerifier, 600);
    try {
      const codeChallenge = await sha256Base64URL(codeVerifier);
      const authorization = await this.client.application().startExternalAuth(provider, {
        redirect_uri: options.redirectUri,
        flow: options.flow,
        ...(options.loginHint ? { login_hint: options.loginHint } : {}),
        code_challenge: codeChallenge,
      });
      this.assertAuthorizationCurrent("provider", provider, codeVerifier);
      this.saveAuthorizationVerifier("provider", provider, codeVerifier, authorization.expires_in, requestId);
      return { ...authorization, requestId };
    } catch (error) {
      if (!this.removeAuthorizationVerifier("provider", provider, codeVerifier)) {
        throw new ExternalAuthRecoveryError("Platform93 external authentication request was cancelled, expired or replaced", "cancelled", error);
      }
      throw error;
    }
  }
  startGoogleAuth(options: ExternalAuthStartOptions) { return this.startExternalAuth("google", options); }
  startAppleAuth(options: Omit<ExternalAuthStartOptions, "loginHint">) { return this.startExternalAuth("apple", options); }
  startMicrosoftAuth(options: ExternalAuthStartOptions) { return this.startExternalAuth("microsoft", options); }
  startFacebookAuth(options: ExternalAuthStartOptions) { return this.startExternalAuth("facebook", options); }
  startLinkedInAuth(options: ExternalAuthStartOptions) { return this.startExternalAuth("linkedin", options); }
  async exchangeExternalAuth(provider: ExternalAuthProvider, exchange: string, codeVerifier = this.loadAuthorizationVerifier("provider", provider)) {
    if (!codeVerifier) throw new ExternalAuthRecoveryError(`Platform93 ${provider} authentication is missing its PKCE verifier`, "restart");
    this.assertAuthorizationCurrent("provider", provider, codeVerifier);
    return this.resolveAuthorizationExchange("provider", provider, codeVerifier,
      this.client.application().exchangeExternalAuth(provider, exchange, codeVerifier));
  }
  exchangeGoogleAuth(exchange: string) { return this.exchangeExternalAuth("google", exchange); }
  exchangeAppleAuth(exchange: string) { return this.exchangeExternalAuth("apple", exchange); }
  async completeExternalAuthRedirect(provider: ExternalAuthProvider, input: string | URL, requestId?: string): Promise<AuthenticationResult | ExternalEmailEnrollmentContinuation> {
    const record = this.loadAuthorizationRecord("provider", provider);
    if (requestId !== undefined && record?.requestId !== requestId) throw new ExternalAuthRecoveryError("Platform93 external authentication request was cancelled or replaced", "cancelled");
    const clear = () => record && this.removeAuthorizationVerifier("provider", provider, record.verifier);
    let redirect: URL;
    try {
      redirect = input instanceof URL ? input : new URL(input);
    } catch {
      clear();
      throw new ExternalAuthRecoveryError(`Platform93 ${provider} redirect is not a valid URL`, "restart");
    }
    const providerError = redirect.searchParams.get("external_auth_error");
    if (providerError) {
      clear();
      throw new ExternalAuthRecoveryError(`Platform93 ${provider} authentication failed: ${providerError}`, "restart");
    }
    const enrollment = redirect.searchParams.get("external_auth_email_enrollment");
    if (enrollment) {
      if (provider === "google" || provider === "apple") {
        clear();
        throw new ExternalAuthRecoveryError(`Platform93 ${provider} returned an unsupported email enrollment continuation`, "restart");
      }
      const verifier = record?.verifier;
      clear();
      if (!verifier) throw new Error(`Platform93 ${provider} email enrollment is missing its PKCE verifier`);
      this.saveAuthorizationVerifier("enrollment", enrollment, verifier, 600);
      return { kind: "email_verification_required", provider, enrollment };
    }
    const exchange = redirect.searchParams.get("external_auth_exchange");
    if (!exchange) {
      clear();
      throw new ExternalAuthRecoveryError(`Platform93 ${provider} redirect is missing its one-time exchange credential`, "restart");
    }
    return this.exchangeExternalAuth(provider, exchange, record?.verifier);
  }
  startExternalEmailEnrollment(continuation: ExternalEmailEnrollmentContinuation, email: string, delivery: "code" | "link" | "both" = "both"): Promise<ExternalEmailEnrollmentChallenge> {
    const verifier = this.loadAuthorizationVerifier("enrollment", continuation.enrollment);
    if (!verifier) throw new Error("Platform93 external email enrollment is missing its PKCE verifier");
    return this.client.application().startExternalEmailEnrollment({ enrollment: continuation.enrollment, email, delivery, code_verifier: verifier });
  }
  async verifyExternalEmailEnrollment(continuation: ExternalEmailEnrollmentContinuation, credential: { code: string } | { linkToken: string }) {
    const verifier = this.loadAuthorizationVerifier("enrollment", continuation.enrollment);
    if (!verifier) throw new ExternalAuthRecoveryError("Platform93 external email enrollment is missing its PKCE verifier", "restart");
    return this.resolveAuthorizationExchange("enrollment", continuation.enrollment, verifier, this.client.application().verifyExternalEmailEnrollment({
      enrollment: continuation.enrollment,
      ...( "code" in credential ? { code: credential.code.trim().toUpperCase() } : { link_token: credential.linkToken }),
    }), ["invalid_external_email_verification"]);
  }
  verifyExternalEmailEnrollmentLink(continuation: ExternalEmailEnrollmentContinuation, input?: string | URL) {
    const source = input ?? globalThis.location?.href;
    if (!source) throw new Error("Platform93 external email verification requires an explicit link URL outside a browser");
    const link = source instanceof URL ? source : new URL(source, globalThis.location?.origin);
    const enrollment = link.searchParams.get("external_auth_email_enrollment");
    const linkToken = link.searchParams.get("external_auth_email_link");
    if (enrollment !== continuation.enrollment || !linkToken) throw new Error("Platform93 external email link is missing or has the wrong enrollment context");
    return this.verifyExternalEmailEnrollment(continuation, { linkToken });
  }
  async exchangeInvitation(input: InvitationCredential) {
    const codeVerifier = randomBase64URL(32);
    const codeChallenge = await sha256Base64URL(codeVerifier);
    const authorization = await this.client.application().exchangeInvitation({ ...input, code_challenge: codeChallenge });
    return this.resolve(this.client.application().redeemInvitation({ authorization_code: authorization.authorization_code, code_verifier: codeVerifier }));
  }
  async startApplicationInvitationProvider(provider: ExternalAuthProvider, input: InvitationCredential): Promise<ExternalAuthRequest> {
    if (this.loadAuthorizationVerifier("provider", provider)) {
      throw new Error(`Platform93 ${provider} authentication already has a request in progress`);
    }
    const codeVerifier = randomBase64URL(32);
    const requestId = this.saveAuthorizationVerifier("provider", provider, codeVerifier, 600);
    try {
      const codeChallenge = await sha256Base64URL(codeVerifier);
      const authorization = await this.client.application().startApplicationInvitationProvider(provider, { ...input, code_challenge: codeChallenge });
      this.assertAuthorizationCurrent("provider", provider, codeVerifier);
      this.saveAuthorizationVerifier("provider", provider, codeVerifier, authorization.expires_in, requestId);
      return { ...authorization, requestId };
    } catch (error) {
      if (!this.removeAuthorizationVerifier("provider", provider, codeVerifier)) {
        throw new ExternalAuthRecoveryError("Platform93 external authentication request was cancelled, expired or replaced", "cancelled", error);
      }
      throw error;
    }
  }
  verifyMFA(input: MFAVerify) { return this.resolve(this.client.application().verifyMFA(input)); }

  async createAuthorizationRequest(options: PKCEAuthorizationOptions = {}): Promise<PKCEAuthorizationRequest> {
    const runtime = await this.client.application().publicConfig();
    const flows = runtime.auth.flows as ApplicationFlowConfig | undefined;
    const hasOverride = options.clientId !== undefined || options.redirectUri !== undefined;
    if (hasOverride && (!options.clientId || !options.redirectUri)) {
      throw new Error("Platform93 authorization overrides require both clientId and redirectUri");
    }
    const clientId = options.clientId ?? flows?.oauth_client_id;
    const redirectUri = options.redirectUri ?? flows?.sign_in_redirect_uri;
    if (!clientId || !redirectUri) {
      throw new Error("Platform93 application sign-in flow is not configured");
    }
    const codeVerifier = randomBase64URL(32);
    const challenge = await sha256Base64URL(codeVerifier);
    const state = options.state ?? randomBase64URL(24);
    const authorization = new URL("/oidc/authorize", runtime.issuer);
    authorization.searchParams.set("client_id", clientId);
    authorization.searchParams.set("redirect_uri", redirectUri);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("scope", (options.scopes ?? ["openid", "profile", "email"]).join(" "));
    authorization.searchParams.set("state", state);
    authorization.searchParams.set("code_challenge", challenge);
    authorization.searchParams.set("code_challenge_method", "S256");
    if (options.nonce) authorization.searchParams.set("nonce", options.nonce);
    return { authorizationUrl: authorization.toString(), codeVerifier, state, clientId, redirectUri };
  }

  async verifyEmailLink(input: string | URL = globalThis.location.href) {
    const link = input instanceof URL ? input : new URL(input, globalThis.location?.origin);
    const challengeId = link.searchParams.get("challenge_id");
    const linkToken = link.searchParams.get("link_token") ?? link.searchParams.get("invitation_token");
    if (!challengeId || !linkToken) throw new Error("Platform93 email link is missing its one-time credential");
    return this.verifyEmail({ challenge_id: challengeId, link_token: linkToken });
  }

  parseInvitationLink(input: string | URL = globalThis.location.href): InvitationLink {
    const link = input instanceof URL ? input : new URL(input, globalThis.location?.origin);
    const applicationId = link.searchParams.get("application_id");
    const invitationId = link.searchParams.get("invitation_id");
    const linkToken = link.searchParams.get("link_token");
    if (!applicationId || !invitationId || !linkToken || applicationId !== this.applicationId) {
      throw new Error("Platform93 invitation link is missing or has the wrong application context");
    }
    return { applicationId, invitationId, linkToken };
  }

  exchangeInvitationLink(input: string | URL = globalThis.location.href) {
    const invitation = this.parseInvitationLink(input);
    return this.exchangeInvitation({ invitation_id: invitation.invitationId, link_token: invitation.linkToken });
  }

  exchangeInvitationCode(email: string, code: string) {
    return this.exchangeInvitation({ email, code: code.trim().toUpperCase() });
  }

  async refresh(broadcast = true) {
    if (this.refreshPromise) return this.refreshPromise;
    this.refreshPromise = this.withRefreshLock(async () => {
      this.setStatus("refreshing");
      try {
        const tokens = await this.adapter.refresh(this.client, this.applicationId);
        if (!tokens) {
          await this.clear(false);
          return null;
        }
        await this.accept(tokens, broadcast);
        return tokens.access_token;
      } catch (error) {
        await this.clear(false);
        throw error;
      }
    }).finally(() => { this.refreshPromise = null; });
    return this.refreshPromise;
  }

  async logout() {
    if (this.accessToken) await this.client.application().logout().catch(() => undefined);
    await this.clear(true);
  }

  destroy() { this.channel?.close(); }

  private async resolve(result: Promise<AuthenticationResult>): Promise<TokenResponse | MFAChallenge> {
    const value = await result;
    if ("access_token" in value) await this.accept(value, true);
    return value;
  }

  private async accept(tokens: TokenResponse, broadcast: boolean) {
    await this.adapter.accept(tokens);
    this.accessToken = tokens.access_token;
    this.accessTokenExpiresAt = Date.now() + tokens.expires_in * 1000;
    this.setStatus("authenticated");
    if (broadcast) this.channel?.postMessage({ type: "session-changed", source: this.source });
  }

  private async clear(broadcast: boolean) {
    this.accessToken = null;
    this.accessTokenExpiresAt = 0;
    await this.adapter.clear();
    this.setStatus("anonymous");
    if (broadcast) this.channel?.postMessage({ type: "logout", source: this.source });
  }

  private setStatus(status: AuthSnapshot["status"]) {
    this.status = status;
    this.dispatchEvent(new Event("change"));
  }

  private authorizationVerifierKey(kind: "provider" | "enrollment", identifier: string) {
    const storageIdentifier = kind === "enrollment" ? identifier.split(":", 1)[0] : identifier;
    return `platform93.${this.applicationId}.pkce.${kind}.${storageIdentifier}`;
  }

  private saveAuthorizationVerifier(kind: "provider" | "enrollment", identifier: string, verifier: string, expiresIn: number, requestId = randomBase64URL(24)) {
    const expiresAt = Date.now() + (Number.isFinite(expiresIn) ? Math.max(1, Math.min(600, expiresIn)) : 600) * 1000;
    this.authorizationStateStore.setItem(this.authorizationVerifierKey(kind, identifier), JSON.stringify({ verifier, expiresAt, requestId }));
    return requestId;
  }

  private loadAuthorizationVerifier(kind: "provider" | "enrollment", identifier: string) {
    return this.loadAuthorizationRecord(kind, identifier)?.verifier;
  }
  private loadAuthorizationRecord(kind: "provider" | "enrollment", identifier: string): AuthorizationVerifier | undefined {
    const key = this.authorizationVerifierKey(kind, identifier);
    const encoded = this.authorizationStateStore.getItem(key);
    if (!encoded) return undefined;
    try {
      const record = JSON.parse(encoded) as { verifier?: unknown; expiresAt?: unknown; requestId?: unknown };
      if (typeof record.verifier === "string" && /^[A-Za-z0-9_-]{43}$/.test(record.verifier) &&
        typeof record.expiresAt === "number" && Number.isFinite(record.expiresAt) && record.expiresAt > Date.now() && record.expiresAt <= Date.now() + 600_000) {
        const requestId = typeof record.requestId === "string" ? record.requestId : randomBase64URL(24);
        const valid = { verifier: record.verifier, expiresAt: record.expiresAt, requestId };
        if (record.requestId === undefined) this.authorizationStateStore.setItem(key, JSON.stringify(valid));
        return valid;
      }
    } catch { /* Invalid state is removed below. */ }
    this.authorizationStateStore.removeItem(key);
    return undefined;
  }

  private removeAuthorizationVerifier(kind: "provider" | "enrollment", identifier: string, expectedVerifier: string) {
    const key = this.authorizationVerifierKey(kind, identifier);
    if (this.loadAuthorizationVerifier(kind, identifier) !== expectedVerifier) return false;
    this.authorizationStateStore.removeItem(key);
    return true;
  }
  private cancelForRestart(provider: ExternalAuthProvider, requestId?: string) {
    const pending = this.pendingExternalAuth(provider);
    if (pending && requestId !== undefined && pending.requestId !== requestId) {
      throw new ExternalAuthRecoveryError("Platform93 external authentication request was replaced", "cancelled");
    }
    this.cancelExternalAuth(provider, requestId);
  }
  private assertAuthorizationCurrent(kind: "provider" | "enrollment", identifier: string, verifier: string) {
    if (this.loadAuthorizationVerifier(kind, identifier) !== verifier) {
      throw new ExternalAuthRecoveryError("Platform93 external authentication request was cancelled, expired or replaced", "cancelled");
    }
  }
  private async resolveAuthorizationExchange(kind: "provider" | "enrollment", identifier: string, verifier: string, response: Promise<AuthenticationResult>, correctableCodes: string[] = []) {
    let result: AuthenticationResult;
    try { result = await response; }
    catch (error) {
      this.assertAuthorizationCurrent(kind, identifier, verifier);
      const retry = retryableExchangeError(error) || error instanceof Platform93Error && correctableCodes.includes(error.problem.code);
      if (!retry) this.removeAuthorizationVerifier(kind, identifier, verifier);
      throw new ExternalAuthRecoveryError(error instanceof Error ? error.message : "Platform93 authentication exchange failed", retry ? "retry" : "restart", error);
    }
    this.assertAuthorizationCurrent(kind, identifier, verifier);
    this.removeAuthorizationVerifier(kind, identifier, verifier);
    try { return await this.resolve(Promise.resolve(result)); }
    catch (error) {
      // The provider credential was consumed even when the local/BFF session failed.
      throw new ExternalAuthRecoveryError("Platform93 session could not be saved; restart authentication", "restart", error);
    }
  }

  private async withRefreshLock<T>(operation: () => Promise<T>): Promise<T> {
    const manager = typeof navigator === "undefined" ? undefined : navigator.locks;
    if (!manager) return operation();
    return manager.request(`platform93-refresh:${this.applicationId}`, operation);
  }
}

function defaultAuthorizationStateStore(): AuthorizationStateStore {
  try {
    if (typeof globalThis.sessionStorage !== "undefined") {
      return new BrowserSessionAuthorizationStateStore(globalThis.sessionStorage);
    }
  } catch { /* Some browser privacy modes deny access to sessionStorage. */ }
  return new MemoryAuthorizationStateStore();
}

function randomBase64URL(byteLength: number) {
  if (!globalThis.crypto?.getRandomValues) throw new Error("Web Crypto is required for Platform93 PKCE");
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(byteLength));
  return base64URL(bytes);
}

async function sha256Base64URL(value: string) {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required for Platform93 PKCE");
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64URL(new Uint8Array(digest));
}

function base64URL(value: Uint8Array) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
