import type {
  AuthenticationResult,
  ExternalEmailEnrollmentContinuation,
} from "@supaapps/platform93-sdk";

import type { Platform93ExpoAuth } from "../src/index.js";

type Assert<T extends true> = T;
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends
  (<T>() => T extends B ? 1 : 2) ? true : false;

type TrustedResult = Promise<AuthenticationResult>;
type UntrustedEmailResult = Promise<AuthenticationResult | ExternalEmailEnrollmentContinuation>;

type GoogleResult = Assert<Equal<ReturnType<Platform93ExpoAuth["signInWithGoogle"]>, TrustedResult>>;
type AppleResult = Assert<Equal<ReturnType<Platform93ExpoAuth["signInWithApple"]>, TrustedResult>>;
type MicrosoftResult = Assert<Equal<ReturnType<Platform93ExpoAuth["signInWithMicrosoft"]>, UntrustedEmailResult>>;
type FacebookResult = Assert<Equal<ReturnType<Platform93ExpoAuth["signInWithFacebook"]>, UntrustedEmailResult>>;
type LinkedInResult = Assert<Equal<ReturnType<Platform93ExpoAuth["signInWithLinkedIn"]>, UntrustedEmailResult>>;

export type ProviderResultContracts = [
  GoogleResult,
  AppleResult,
  MicrosoftResult,
  FacebookResult,
  LinkedInResult,
];
