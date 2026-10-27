import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import vectors from "../qualification/surface-push/native-proof-transcript-vectors-v1.json";
import { base64Encode } from "../src/crypto";
import { canonical, SurfaceError } from "../src/surface-push/wire";
import { decodeNativeProofTranscript, decodeNativeProofTranscriptBase64, digestNativeProofTranscript,
 matchesExpectedNativeProofData, NATIVE_PROOF_DOMAINS, type DecodedNativeProofTranscript } from "../src/surface-push/native-proof-transcript";

// Expired synthetic DATA. No attestation/assertion, live clock, SDK, DB, authority or provider.
const utf8 = (s: string) => new TextEncoder().encode(s);
const copy = (value: unknown): Record<string, any> => JSON.parse(JSON.stringify(value));
function decode(value: unknown) { return decodeNativeProofTranscript(utf8(canonical(value))); }
function rejects(work: () => unknown, code = "native_proof_transcript_invalid", status = 400) {
 let error: unknown; try { work(); } catch (e) { error = e; }
 expect(error).toBeInstanceOf(SurfaceError); expect(error).toMatchObject({ code, status });
}
afterEach(() => vi.restoreAllMocks());

describe("uncomposed native proof canonical DATA codec in actual Worker runtime", () => {
 it("executes with the actual Worker runtime and disposable D1 binding", async () => {
  expect(navigator.userAgent).toBe("Cloudflare-Workers");
  expect(await env.DB.prepare("SELECT 1 AS n").first<number>("n")).toBe(1);
 });
 for (const [i, v] of vectors.cases.entries()) {
  const label = `${v.proof_variant}/${i < 3 ? "widget" : "iOS-Activity"}`;
  it(`matches independent Python canonical bytes and both digests: ${label}`, async () => {
   const original = utf8(v.canonical_transcript_utf8), parsed = decodeNativeProofTranscript(original);
   expect(parsed.data).toEqual(v.transcript);
   expect(parsed.canonicalUtf8).toBe(v.canonical_transcript_utf8);
   expect(NATIVE_PROOF_DOMAINS[parsed.variant]).toBe(v.domain_prefix_utf8);
   expect(v.domain_prefix_utf8 + parsed.canonicalUtf8).toBe(v.client_data_preimage_utf8);
   expect(decodeNativeProofTranscriptBase64(base64Encode(original)).data).toEqual(v.transcript);
   original.fill(0); // The result and pending digest must not retain caller-owned mutable bytes.
   expect(await digestNativeProofTranscript(parsed)).toEqual({ preparedTranscriptSha256: v.canonical_transcript_sha256, clientDataHashSha256: v.client_data_hash_sha256 });
   expect(Object.isFrozen(parsed)).toBe(true); expect(Object.isFrozen(parsed.data)).toBe(true);
   expect(Object.getPrototypeOf(parsed.data)).toBeNull();
   if (parsed.data.prospective_activity_identity) expect(Object.isFrozen(parsed.data.prospective_activity_identity)).toBe(true);
   if (parsed.data.proof_variant === "target_registration_assertion") expect(Object.isFrozen(parsed.data.native_target)).toBe(true);
  });
  it(`rejects an equal duplicate root key that JSON.parse would discard: ${label}`, () => {
   const raw = v.canonical_transcript_utf8.replace("{", '{"contract_version":1,');
   expect(JSON.parse(raw)).toEqual(v.transcript);
   rejects(() => decodeNativeProofTranscript(utf8(raw)), "duplicate_json_key");
  });
  it(`rejects an escaped equal duplicate key: ${label}`, () => {
   const raw = v.canonical_transcript_utf8.replace("{", '{"contract_\\u0076ersion":1,');
   expect(JSON.parse(raw)).toEqual(v.transcript);
   rejects(() => decodeNativeProofTranscript(utf8(raw)), "duplicate_json_key");
  });
  for (const spelling of ["1.0", "1e0", "1E+0"]) it(`keeps integer token spelling: ${label}/${spelling}`, () => {
   const raw = v.canonical_transcript_utf8.replace('"contract_version":1', '"contract_version":' + spelling);
   expect(JSON.parse(raw)).toEqual(v.transcript); rejects(() => decodeNativeProofTranscript(utf8(raw)));
  });
  it(`rejects noncanonical whitespace and member order: ${label}`, () => {
   for (const raw of [" " + v.canonical_transcript_utf8, v.canonical_transcript_utf8 + "\n", JSON.stringify(Object.fromEntries(Object.entries(v.transcript).reverse()))]) {
    expect(JSON.parse(raw)).toEqual(v.transcript); rejects(() => decodeNativeProofTranscript(utf8(raw)));
   }
  });
  it(`checks canonical nonce and key padding bits: ${label}`, () => {
   const a = copy(v.transcript); a.apple_key_id_b64 = a.apple_key_id_b64.slice(0, -2) + "J=";
   expect(atob(a.apple_key_id_b64)).toBe(atob(v.transcript.apple_key_id_b64)); rejects(() => decode(a));
   const b = copy(v.transcript); const last = b.nonce_b64url.at(-1), alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
   b.nonce_b64url = b.nonce_b64url.slice(0, -1) + alphabet[alphabet.indexOf(last) + 1];
   expect(atob(b.nonce_b64url.replaceAll("-", "+").replaceAll("_", "/") + "=")).toBe(atob(v.transcript.nonce_b64url.replaceAll("-", "+").replaceAll("_", "/") + "="));
   rejects(() => decode(b));
  });
 }

 const widget = vectors.cases[0];
 for (const [name, change] of Object.entries({
  extra: (v: Record<string, any>) => { v.owner_is_admin = true; },
  missing: (v: Record<string, any>) => { delete v.nonce_b64url; },
  booleanVersion: (v: Record<string, any>) => { v.contract_version = true; },
  unsafeInteger: (v: Record<string, any>) => { v.bootstrap_deadline_unix_ms = Number.MAX_SAFE_INTEGER + 1; },
  zeroDeadline: (v: Record<string, any>) => { v.bootstrap_deadline_unix_ms = 0; },
  upperUUID: (v: Record<string, any>) => { v.proof_job_id = "ABCDEFAB-0000-4000-8000-000000000001"; },
  UUIDv7: (v: Record<string, any>) => { v.operation_id = "00000000-0000-7000-8000-000000000003"; },
  upperHash: (v: Record<string, any>) => { v.candidate_sha256 = "A".repeat(64); },
  foreignAudience: (v: Record<string, any>) => { v.proof_port_audience = "rendezvous"; },
  keyLength: (v: Record<string, any>) => { v.apple_key_id_b64 = base64Encode(new Uint8Array(31)); },
  emptyOrigin: (v: Record<string, any>) => { v.selected_ha_origin = ""; },
  wrongPlatform: (v: Record<string, any>) => { v.client_type = "ipados"; },
  remoteStart: (v: Record<string, any>) => { v.token_role = "live_activity_start"; },
  widgetActivityProfile: (v: Record<string, any>) => { v.profile_identity_sha256 = "0".repeat(64); },
  widgetPresentation: (v: Record<string, any>) => { v.prospective_activity_identity = {}; },
  variantFields: (v: Record<string, any>) => { v.verified_key_ref = "00000000-0000-4000-8000-000000000004"; },
 })) it(`rejects closed shape/type input ${name}`, () => { const v = copy(widget.transcript); change(v); rejects(() => decode(v)); });

 it("rejects malformed UTF8, BOM, lone surrogate keys/values, depth, and overflow", () => {
  rejects(() => decodeNativeProofTranscript(new Uint8Array([0xff, 0xff])));
  rejects(() => decodeNativeProofTranscript(utf8("\ufeff" + widget.canonical_transcript_utf8)));
  for (const ch of ["\ud800", "\udfff"]) {
   const v = copy(widget.transcript); v.selected_ha_origin = ch; rejects(() => decode(v));
   v.selected_ha_origin = "ok"; v[ch] = true; rejects(() => decode(v));
  }
  rejects(() => decodeNativeProofTranscript(utf8("[".repeat(18) + "0" + "]".repeat(18))), "invalid_json");
  rejects(() => decodeNativeProofTranscript(utf8(widget.canonical_transcript_utf8.replace('"contract_version":1', '"contract_version":1e999'))), "invalid_json");
 });
 it("rejects nested equal duplicates and escaped duplicates before their shape disappears", () => {
  const v = vectors.cases[5], raw = v.canonical_transcript_utf8;
  for (const member of ['"presentation_id"', '"presentation_\\u0069d"']) {
   const changed = raw.replace('"prospective_activity_identity":{', '"prospective_activity_identity":{' + member + ':"' + (v.transcript.prospective_activity_identity as any).presentation_id + '",');
   expect(JSON.parse(changed)).toEqual(v.transcript); rejects(() => decodeNativeProofTranscript(utf8(changed)), "duplicate_json_key");
  }
 });
 for (const v of vectors.cases.slice(3)) it(`only client_type changes for causal Mac-Activity refusal: ${v.proof_variant}`, () => {
  expect(decode(v.transcript).data.token_role).toBe("live_activity_update");
  const mac = copy(v.transcript); mac.client_type = "macos";
  expect(Object.keys(mac).filter(k => canonical(mac[k]) !== canonical((v.transcript as any)[k]))).toEqual(["client_type"]);
  rejects(() => decode(mac));
 });
 it("accepts Mac widget DATA without declaring Mac native capability", () => {
  const v = copy(widget.transcript); v.client_type = "macos"; expect(decode(v).data.client_type).toBe("macos");
 });
 it("separately refuses target/prospective presentation identity mismatch", () => {
  for (const field of ["presentation_id", "presentation_generation"]) {
   const v = copy(vectors.cases[5].transcript); v.native_target[field] = "00000000-0000-4000-8000-000000000099";
   rejects(() => decode(v), "native_proof_context_mismatch", 403);
  }
 });
 it("enforces exactly 4096 decoded bytes even when 4097 still has 5464 encoded characters", () => {
  function sized(n: number) {
   const v = copy(widget.transcript); v.selected_ha_origin = ""; const count = n - utf8(canonical(v)).length;
   // Bounded DATA string only, deliberately not a claimed admissible origin/clock/authority.
   v.selected_ha_origin = "é".repeat(Math.floor(count / 2)) + "a".repeat(count % 2);
   return utf8(canonical(v));
  }
  const exact = sized(4096), over = sized(4097);
  expect(exact.length).toBe(4096); expect(over.length).toBe(4097);
  expect(base64Encode(exact).length).toBe(5464); expect(base64Encode(over).length).toBe(5464);
  expect(decodeNativeProofTranscript(exact).canonicalUtf8).toBe(new TextDecoder().decode(exact));
  expect(decodeNativeProofTranscriptBase64(base64Encode(exact)).canonicalBase64).toBe(base64Encode(exact));
  rejects(() => decodeNativeProofTranscript(over)); rejects(() => decodeNativeProofTranscriptBase64(base64Encode(over)));
  rejects(() => decodeNativeProofTranscriptBase64("A".repeat(5465)));
 });
 it("keeps standard base64 transport exact instead of accepting whitespace/unpadding/URL alphabet", () => {
  const good = base64Encode(utf8(widget.canonical_transcript_utf8));
  for (const bad of [" " + good, good + "\n", good.replaceAll("=", ""), "-" + good.slice(1)]) rejects(() => decodeNativeProofTranscriptBase64(bad));
 });
 it("compares immutable expected DATA without granting original-owner or clock authority", () => {
  const original = decode(widget.transcript); expect(matchesExpectedNativeProofData(original, decode(widget.transcript))).toBe(true);
  for (const field of ["proof_job_id", "owner_approval_binding_sha256", "source_selection_sha256", "bootstrap_deadline_unix_ms", "original_grant_expires_at_unix_ms"]) {
   const changed = copy(widget.transcript);
   changed[field] = field.endsWith("_ms") ? changed[field] - 1 : field.endsWith("_sha256") ? "f".repeat(64) : "00000000-0000-4000-8000-000000000099";
   expect(matchesExpectedNativeProofData(decode(changed), original)).toBe(false);
  }
 });
 it("does not accept a forged codec result as validated data", async () => {
  const forged = { ...decode(widget.transcript) } as DecodedNativeProofTranscript;
  rejects(() => matchesExpectedNativeProofData(forged, decode(widget.transcript)));
  await expect(digestNativeProofTranscript(forged)).rejects.toMatchObject({ code: "native_proof_transcript_invalid" });
 });
 for (const failingCall of [1, 2]) it(`propagates the identical original hash failure at call ${failingCall}`, async () => {
  const original = new Error("synthetic fixed WebCrypto failure"), digest = crypto.subtle.digest.bind(crypto.subtle); let count = 0;
  vi.spyOn(crypto.subtle, "digest").mockImplementation((...args: Parameters<SubtleCrypto["digest"]>) => ++count === failingCall ? Promise.reject(original) : digest(...args));
  await expect(digestNativeProofTranscript(decode(widget.transcript))).rejects.toBe(original);
 });
});
