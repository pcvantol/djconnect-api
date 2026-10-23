/** Server-only APNs authentication. This module performs no fetch or environment lookup. */
import { base64Url } from "../crypto";
import type { AppEnv } from "../types";
import { need, SurfaceError } from "./wire";

export type ProviderConfiguration = Pick<AppEnv, "APNS_TEAM_ID" | "APNS_KEY_ID" | "APNS_PRIVATE_KEY">;
export interface SurfaceProvider {
 authorizeProvider(): Promise<string>;
 /** Retires this instance, including pending authorization. Not remote key revocation. */
 close(): void;
}
const REFRESH_MS = 50 * 60 * 1000;

/** One immutable team/key identity per instance. Caller owns key provisioning and retirement. */
export function createSurfaceProvider(configuration: ProviderConfiguration, clock: () => number = Date.now): SurfaceProvider {
 const team = configuration.APNS_TEAM_ID, keyId = configuration.APNS_KEY_ID;
 let pem = configuration.APNS_PRIVATE_KEY;
 need(typeof team === "string" && /^[A-Z0-9]{10}$/.test(team) && typeof keyId === "string" && /^[A-Z0-9]{10}$/.test(keyId), "surface_provider_not_admitted", 503);
 need(typeof pem === "string" && pem.length <= 8192 && /^-----BEGIN PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]+\s+-----END PRIVATE KEY-----\s*$/.test(pem), "surface_provider_not_admitted", 503);
 let closed = false, highWater = 0, key: CryptoKey | null = null;
 let cached: { token: string; issuedAt: number } | null = null;
 let pending: Promise<string> | null = null;
 const now = () => {
  const value = clock();
  need(!closed && Number.isSafeInteger(value) && value >= highWater && value >= 0, "surface_provider_not_admitted", 503);
  highWater = value; return value;
 };
 const generate = async (): Promise<string> => {
  const issuedAt = Math.floor(now() / 1000) * 1000;
  if (!key) {
   const body = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
   const bytes = Uint8Array.from(atob(body), c => c.charCodeAt(0));
   try {
    const imported = await crypto.subtle.importKey("pkcs8", bytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    now(); key = imported;
   }
   finally { bytes.fill(0); }
  }
  const input = base64Url(JSON.stringify({ alg: "ES256", kid: keyId })) + "." + base64Url(JSON.stringify({ iss: team, iat: issuedAt / 1000 }));
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(input));
  // Web Crypto ECDSA returns IEEE P1363 (raw r||s), which is the JWT encoding.
  need(signature.byteLength === 64 && now() - issuedAt < REFRESH_MS, "surface_provider_not_admitted", 503);
  const token = input + "." + base64Url(signature);
  cached = { token, issuedAt }; return token;
 };
 return {
  async authorizeProvider() {
   try {
    const current = now();
    if (cached && current - cached.issuedAt < REFRESH_MS) return cached.token;
    if (!pending) pending = generate().finally(() => { pending = null; });
    return await pending;
   } catch {
    // Do not expose private key material, provider tokens or runtime exception details.
    throw new SurfaceError(503, "surface_provider_not_admitted");
   }
  },
  close() { closed = true; cached = null; key = null; pem = ""; },
 };
}
