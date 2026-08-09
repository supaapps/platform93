import { createRemoteJWKSet, customFetch, jwtVerify, type JWTPayload } from "jose";

export type Platform93Claims = JWTPayload & {
  application_id: string;
  token_kind: "access" | "machine";
  actor_type: "user" | "client";
  scope: string;
  locale?: string;
  email_verified?: boolean;
  is_org_verified?: boolean;
  act?: { sub: string; type: string };
};

export type VerifierOptions = {
  issuer: string;
  audience: string;
  applicationId: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  clockToleranceSeconds?: number;
};

export function createVerifier(options: VerifierOptions) {
  const issuer = options.issuer.replace(/\/$/, "");
  const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks.json`), {
    ...(options.fetch ? { [customFetch]: options.fetch } : {}),
    timeoutDuration: options.timeoutMs ?? 5_000,
    cacheMaxAge: 300_000,
    cooldownDuration: 30_000,
  });
  return async (token: string) => {
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer,
      audience: options.audience,
      algorithms: ["RS256"],
      typ: "JWT",
      clockTolerance: options.clockToleranceSeconds ?? 30,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat", "nbf", "application_id", "token_kind", "actor_type", "scope"],
    });
    const claims = payload as Platform93Claims;
    const tolerance = options.clockToleranceSeconds ?? 30;
    const now = Math.floor(Date.now() / 1000);
    if (!protectedHeader.kid || claims.application_id !== options.applicationId ||
      !(claims.token_kind === "access" && claims.actor_type === "user" || claims.token_kind === "machine" && claims.actor_type === "client") || typeof claims.sub !== "string" || claims.sub === "" ||
      typeof claims.iat !== "number" || claims.iat > now + tolerance) {
      throw new Error("Platform93 token context rejected");
    }
    if (claims.act && (claims.token_kind !== "access" || claims.act.type !== "operator" || !claims.act.sub)) {
      throw new Error("Platform93 delegated token actor rejected");
    }
    return claims;
  };
}

export function hasPermission(claims: Platform93Claims, permission: string) {
  return claims.scope.split(/\s+/).some((value) => value === permission || value === "*" || value.endsWith("/*") && (permission === value.slice(0, -2) || permission.startsWith(value.slice(0, -1))));
}
