import type { StartExternalEmailEnrollmentData } from "../src/generated/types.gen.js";

type Assert<T extends true> = T;
type IsRequired<T, K extends keyof T> = object extends Pick<T, K> ? false : true;
type EnrollmentBody = StartExternalEmailEnrollmentData["body"];

type EnrollmentIsRequired = Assert<IsRequired<EnrollmentBody, "enrollment">>;
type EmailIsRequired = Assert<IsRequired<EnrollmentBody, "email">>;
type CodeVerifierIsRequired = Assert<IsRequired<EnrollmentBody, "code_verifier">>;

export type ExternalEmailEnrollmentRequestContract = [
  EnrollmentIsRequired,
  EmailIsRequired,
  CodeVerifierIsRequired,
];
