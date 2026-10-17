import type { ProvisionGoogleUserData } from "../src/generated/types.gen.js";
import type { ProvisionGoogleUser } from "../src/index.js";

type Assert<T extends true> = T;
type IsRequired<T, K extends keyof T> = object extends Pick<T, K> ? false : true;
export type GoogleSubjectRequired = Assert<IsRequired<ProvisionGoogleUserData["body"], "google_sub">>;

export const newUser: ProvisionGoogleUser = { google_sub: "opaque", reason: "Import", user: { email: "a@example.test" } };
export const existingUser: ProvisionGoogleUser = { google_sub: "opaque", reason: "Import", user_id: "user-id" };
// @ts-expect-error A user target is required.
export const noTarget: ProvisionGoogleUser = { google_sub: "opaque", reason: "Import" };
// @ts-expect-error New and existing user targets are mutually exclusive.
export const bothTargets: ProvisionGoogleUser = { google_sub: "opaque", reason: "Import", user_id: "user-id", user: { email: "a@example.test" } };
