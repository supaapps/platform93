import {
  Platform93Client,
  type AuthenticationResult,
  type ApplicationFlowConfig,
  type EmailStart,
  type EmailVerify,
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
};

export interface TokenStore {
  loadRefreshToken(): Promise<string | null>;
  saveRefreshToken(value: string | null): Promise<void>;
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
  fetch?: typeof globalThis.fetch;
  channelName?: string | false;
};

export class Platform93Auth extends EventTarget {
  private accessToken: string | null = null;
  private status: AuthSnapshot["status"] = "anonymous";
  private refreshPromise: Promise<string | null> | null = null;
  private readonly adapter: SessionAdapter;
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
  signIn(input: PasswordSignIn) { return this.resolve(this.client.application().signIn(input)); }
  signUp(input: PasswordSignUp) { return this.resolve(this.client.application().signUp(input)); }
  startEmail(input: EmailStart) { return this.client.application().startEmail(input); }
  verifyEmail(input: EmailVerify) { return this.resolve(this.client.application().verifyEmail(input)); }
  verifyMFA(input: MFAVerify) { return this.resolve(this.client.application().verifyMFA(input)); }

  async createAuthorizationRequest(options: PKCEAuthorizationOptions = {}): Promise<PKCEAuthorizationRequest> {
    const runtime = await this.client.application().publicConfig();
    const flows = runtime.auth.flows as ApplicationFlowConfig | undefined;
    if (!flows?.oauth_client_id || !flows.sign_in_redirect_uri) {
      throw new Error("Platform93 application sign-in flow is not configured");
    }
    const codeVerifier = randomBase64URL(32);
    const challenge = await sha256Base64URL(codeVerifier);
    const state = options.state ?? randomBase64URL(24);
    const authorization = new URL("/oidc/authorize", runtime.issuer);
    authorization.searchParams.set("client_id", flows.oauth_client_id);
    authorization.searchParams.set("redirect_uri", flows.sign_in_redirect_uri);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("scope", (options.scopes ?? ["openid", "profile", "email"]).join(" "));
    authorization.searchParams.set("state", state);
    authorization.searchParams.set("code_challenge", challenge);
    authorization.searchParams.set("code_challenge_method", "S256");
    if (options.nonce) authorization.searchParams.set("nonce", options.nonce);
    return { authorizationUrl: authorization.toString(), codeVerifier, state, clientId: flows.oauth_client_id, redirectUri: flows.sign_in_redirect_uri };
  }

  async verifyEmailLink(input: string | URL = globalThis.location.href) {
    const link = input instanceof URL ? input : new URL(input, globalThis.location?.origin);
    const challengeId = link.searchParams.get("challenge_id");
    const linkToken = link.searchParams.get("link_token");
    if (!challengeId || !linkToken) throw new Error("Platform93 email link is missing its one-time credential");
    return this.verifyEmail({ challenge_id: challengeId, link_token: linkToken });
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
    this.setStatus("authenticated");
    if (broadcast) this.channel?.postMessage({ type: "session-changed", source: this.source });
  }

  private async clear(broadcast: boolean) {
    this.accessToken = null;
    await this.adapter.clear();
    this.setStatus("anonymous");
    if (broadcast) this.channel?.postMessage({ type: "logout", source: this.source });
  }

  private setStatus(status: AuthSnapshot["status"]) {
    this.status = status;
    this.dispatchEvent(new Event("change"));
  }

  private async withRefreshLock<T>(operation: () => Promise<T>): Promise<T> {
    const manager = typeof navigator === "undefined" ? undefined : navigator.locks;
    if (!manager) return operation();
    return manager.request(`platform93-refresh:${this.applicationId}`, operation);
  }
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
