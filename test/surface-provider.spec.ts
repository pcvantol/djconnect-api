import { beforeAll, describe, expect, it, vi } from "vitest";
import { createSurfaceProvider, type ProviderConfiguration } from "../src/surface-push/provider";

const NOW = Date.UTC(2026, 9, 22), REFRESH = 50 * 60000;
let configuration: ProviderConfiguration, publicKey: CryptoKey;
function decode(segment: string): Uint8Array {
 return Uint8Array.from(atob(segment.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
}
async function valid(token: string): Promise<boolean> {
 const [header, claims, signature] = token.split(".") as [string, string, string];
 return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, decode(signature), new TextEncoder().encode(header + "." + claims));
}
describe("server-owned surface APNs provider with local software keys only", () => {
 beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
  publicKey = pair.publicKey;
  const bytes = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  configuration = { APNS_TEAM_ID: "TEAM123456", APNS_KEY_ID: "KEY1234567", APNS_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\n" + btoa(String.fromCharCode(...bytes)) + "\n-----END PRIVATE KEY-----" };
 });
 it("produces an independently verified ES256 JWT with only exact Apple header/claims", async () => {
  const token = await createSurfaceProvider(configuration, () => NOW).authorizeProvider();
  const [header, claims, signature] = token.split(".") as [string, string, string];
  expect(JSON.parse(new TextDecoder().decode(decode(header)))).toEqual({ alg: "ES256", kid: configuration.APNS_KEY_ID });
  expect(JSON.parse(new TextDecoder().decode(decode(claims)))).toEqual({ iss: configuration.APNS_TEAM_ID, iat: NOW / 1000 });
  expect(decode(signature)).toHaveLength(64); expect(await valid(token)).toBe(true);
  expect(await valid(header + "." + claims + "A." + signature)).toBe(false);
 });
 it("coalesces concurrent first signing and reuses the same token until the fixed refresh deadline", async () => {
  let clock = NOW; const provider = createSurfaceProvider(configuration, () => clock), signing = vi.spyOn(crypto.subtle, "sign");
  try {
   const tokens = await Promise.all(Array.from({ length: 8 }, () => provider.authorizeProvider()));
   expect(new Set(tokens).size).toBe(1); expect(signing).toHaveBeenCalledTimes(1);
   clock = NOW + REFRESH - 1; expect(await provider.authorizeProvider()).toBe(tokens[0]); expect(signing).toHaveBeenCalledTimes(1);
   clock = NOW + REFRESH;
   const rotated = await Promise.all([provider.authorizeProvider(), provider.authorizeProvider()]);
   expect(rotated[0]).toBe(rotated[1]); expect(rotated[0]).not.toBe(tokens[0]); expect(await valid(rotated[0]!)).toBe(true); expect(signing).toHaveBeenCalledTimes(2);
  } finally { signing.mockRestore(); }
 });
 it("snapshots one team/key configuration rather than switching identity through caller mutation", async () => {
  const input = { ...configuration }, provider = createSurfaceProvider(input, () => NOW);
  input.APNS_TEAM_ID = "OTHERTEAM1"; input.APNS_KEY_ID = "OTHERKEY01"; input.APNS_PRIVATE_KEY = "invalid";
  const token = await provider.authorizeProvider(); expect(await valid(token)).toBe(true);
  expect(JSON.parse(new TextDecoder().decode(decode(token.split(".")[1]!))).iss).toBe(configuration.APNS_TEAM_ID);
 });
 it("does not reuse or issue on a backwards clock", async () => {
  let clock = NOW; const provider = createSurfaceProvider(configuration, () => clock); await provider.authorizeProvider();
  clock--; await expect(provider.authorizeProvider()).rejects.toMatchObject({ code: "surface_provider_not_admitted", status: 503 });
 });
 it.each([NaN, Infinity, -1, 1.5])("refuses unqualified clock %s", async clock => {
  await expect(createSurfaceProvider(configuration, () => clock).authorizeProvider()).rejects.toMatchObject({ code: "surface_provider_not_admitted", status: 503 });
 });
 it.each(["APNS_TEAM_ID", "APNS_KEY_ID", "APNS_PRIVATE_KEY"] as const)("refuses invalid configured %s before signing", field => {
  expect(() => createSurfaceProvider({ ...configuration, [field]: "bad" })).toThrow("surface_provider_not_admitted");
 });
 it("conceals malformed PKCS8 import details and has no fallback", async () => {
  const provider = createSurfaceProvider({ ...configuration, APNS_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----" }, () => NOW);
  await expect(provider.authorizeProvider()).rejects.toMatchObject({ message: "surface_provider_not_admitted", status: 503 });
 });
 it("refuses the wrong elliptic curve even inside a valid PKCS8 envelope", async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const bytes = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const provider = createSurfaceProvider({ ...configuration, APNS_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\n" + btoa(String.fromCharCode(...bytes)) + "\n-----END PRIVATE KEY-----" }, () => NOW);
  await expect(provider.authorizeProvider()).rejects.toMatchObject({ code: "surface_provider_not_admitted", status: 503 });
 });
 it("close permanently retires cached authorization and pending signing", async () => {
  const provider = createSurfaceProvider(configuration, () => NOW); await provider.authorizeProvider(); provider.close();
  await expect(provider.authorizeProvider()).rejects.toMatchObject({ code: "surface_provider_not_admitted" });
  const pending = createSurfaceProvider(configuration, () => NOW), token = pending.authorizeProvider(); pending.close();
  await expect(token).rejects.toMatchObject({ code: "surface_provider_not_admitted" });
  await expect(pending.authorizeProvider()).rejects.toMatchObject({ code: "surface_provider_not_admitted" });
 });
 it("a signing delay cannot publish or cache an already outdated JWT", async () => {
  let clock = NOW; const original = crypto.subtle.sign.bind(crypto.subtle);
  const signing = vi.spyOn(crypto.subtle, "sign").mockImplementation(async (...args) => { const result = await original(...args); clock = NOW + REFRESH; return result; });
  try { await expect(createSurfaceProvider(configuration, () => clock).authorizeProvider()).rejects.toMatchObject({ code: "surface_provider_not_admitted" }); }
  finally { signing.mockRestore(); }
 });
});
