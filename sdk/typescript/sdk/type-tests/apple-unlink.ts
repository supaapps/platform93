import type { Problem, UnlinkMyIdentityErrors } from "../src/generated/types.gen.js";

type Assert<T extends true> = T;
export type AppleUnlinkErrorContract = Assert<UnlinkMyIdentityErrors[403] extends Problem ? true : false>;
