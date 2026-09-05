import {
  Platform93Auth,
  TokenStoreSessionAdapter,
  type ExternalAuthStartOptions,
  type TokenStore,
} from "@supaapps/platform93-auth";
import type {
  AuthenticationResult,
  ExternalEmailEnrollmentContinuation,
  ExternalAuthFlow,
  ExternalAuthProvider,
  PasswordSignIn,
  PasswordSignUp,
} from "@supaapps/platform93-sdk";

export interface ExpoSecureStore {
  getItemAsync(key: string): Promise<string | null>;
  setItemAsync(key: string, value: string): Promise<void>;
  deleteItemAsync(key: string): Promise<void>;
}

export interface ExpoWebBrowser {
  openAuthSessionAsync(url: string, redirectUrl: string): Promise<{ type: string; url?: string | null }>;
}

export class ExpoSecureStoreTokenStore implements TokenStore {
  constructor(
    private readonly secureStore: ExpoSecureStore,
    private readonly key = "platform93.refresh_token",
  ) {}

  loadRefreshToken() { return this.secureStore.getItemAsync(this.key); }

  async saveRefreshToken(value: string | null) {
    if (value === null) await this.secureStore.deleteItemAsync(this.key);
    else await this.secureStore.setItemAsync(this.key, value);
  }
}

export type Platform93ExpoAuthOptions = {
  baseUrl: string;
  applicationId: string;
  redirectUri: string;
  secureStore: ExpoSecureStore;
  webBrowser: ExpoWebBrowser;
  storageKey?: string;
  fetch?: typeof globalThis.fetch;
};

export class Platform93NativeAuthSessionError extends Error {
  constructor(public readonly resultType: string) {
    super(`Platform93 native authentication did not complete (${resultType})`);
    this.name = "Platform93NativeAuthSessionError";
  }
}

export class Platform93ExpoAuth {
  readonly auth: Platform93Auth;
  readonly redirectUri: string;
  private readonly webBrowser: ExpoWebBrowser;

  constructor(options: Platform93ExpoAuthOptions) {
    if (!options.redirectUri) throw new Error("Platform93 native redirectUri is required");
    this.redirectUri = options.redirectUri;
    this.webBrowser = options.webBrowser;
    const key = options.storageKey ?? `platform93.${options.applicationId}.refresh_token`;
    this.auth = new Platform93Auth({
      baseUrl: options.baseUrl,
      applicationId: options.applicationId,
      adapter: new TokenStoreSessionAdapter(new ExpoSecureStoreTokenStore(options.secureStore, key)),
      fetch: options.fetch,
      channelName: false,
    });
  }

  initialize() { return this.auth.refresh(false); }
  snapshot() { return this.auth.snapshot(); }
  getAccessToken() { return this.auth.getAccessToken(); }
  signIn(input: PasswordSignIn) { return this.auth.signIn(input); }
  signUp(input: PasswordSignUp) { return this.auth.signUp(input); }
  logout() { return this.auth.logout(); }

  signInWithGoogle(options: Omit<ExternalAuthStartOptions, "redirectUri"> = {}) {
    return this.openProviderSession("google", options);
  }

  signInWithApple(options: { flow?: ExternalAuthFlow } = {}) {
    return this.openProviderSession("apple", options);
  }

  signInWithMicrosoft(options: Omit<ExternalAuthStartOptions, "redirectUri"> = {}) {
    return this.openProviderSession("microsoft", options);
  }

  signInWithFacebook(options: Omit<ExternalAuthStartOptions, "redirectUri"> = {}) {
    return this.openProviderSession("facebook", options);
  }

  signInWithLinkedIn(options: Omit<ExternalAuthStartOptions, "redirectUri"> = {}) {
    return this.openProviderSession("linkedin", options);
  }

  async openProviderSession(
    provider: "google" | "apple",
    options?: { flow?: ExternalAuthFlow; loginHint?: string },
  ): Promise<AuthenticationResult>;
  async openProviderSession(
    provider: ExternalEmailEnrollmentContinuation["provider"],
    options?: { flow?: ExternalAuthFlow; loginHint?: string },
  ): Promise<AuthenticationResult | ExternalEmailEnrollmentContinuation>;
  async openProviderSession(
    provider: ExternalAuthProvider,
    options: { flow?: ExternalAuthFlow; loginHint?: string } = {},
  ): Promise<AuthenticationResult | ExternalEmailEnrollmentContinuation> {
    const authorization = await this.auth.startExternalAuth(provider, {
      redirectUri: this.redirectUri,
      flow: options.flow,
      loginHint: options.loginHint,
    });
    const result = await this.webBrowser.openAuthSessionAsync(authorization.authorize_url, this.redirectUri);
    if (result.type !== "success" || !result.url) {
      throw new Platform93NativeAuthSessionError(result.type);
    }
    return await this.auth.completeExternalAuthRedirect(provider, result.url);
  }
}
