import type { CreateEntitlementData } from "../src/generated/types.gen.js";

type Assert<T extends true> = T;
type IsRequired<T, K extends keyof T> = object extends Pick<T, K> ? false : true;

export type ManualGrantRequestContract = [
  Assert<IsRequired<CreateEntitlementData, "headers">>,
  Assert<IsRequired<CreateEntitlementData["headers"], "Idempotency-Key">>,
];
