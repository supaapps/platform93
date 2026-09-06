import type {
  ExternalAuthFlow,
  ExternalEmailEnrollmentVerify,
} from "../src/index.js";

export const linkFlow: ExternalAuthFlow = "link";

export const enrollmentCode = {
  enrollment: "enrollment",
  code: "12345678",
} satisfies ExternalEmailEnrollmentVerify;

export const enrollmentLink = {
  enrollment: "enrollment",
  link_token: "link-token",
} satisfies ExternalEmailEnrollmentVerify;

// @ts-expect-error Exactly one verification credential is required.
export const enrollmentWithoutCredential: ExternalEmailEnrollmentVerify = { enrollment: "enrollment" };

// @ts-expect-error Code and link credentials cannot be submitted together.
export const enrollmentWithBothCredentials: ExternalEmailEnrollmentVerify = {
  enrollment: "enrollment",
  code: "12345678",
  link_token: "link-token",
};
