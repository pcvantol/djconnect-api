/** Pure candidate DATA codec. Uncomposed: no admission, clock, native verification or IO. */
import { base64Encode, sha256Hex } from "../crypto";
import { canonical, need, parseStrictJson } from "./wire";

export const NATIVE_TRANSCRIPT_MAX_BYTES = 4096;
export const NATIVE_TRANSCRIPT_MAX_BASE64 = 5464;
export const STATUS_PROFILE_IDENTITY = "090b8c9cd0d0b74622cd8ce00accaaecd816feb9d762f0554a9709bbf6342517";
export const NATIVE_PROOF_DOMAINS = Object.freeze({
 new_key_attestation: "DJC-PUSH-STATUS-KEY-ATTEST-V1\n",
 existing_key_assertion: "DJC-PUSH-STATUS-KEY-REUSE-V1\n",
 target_registration_assertion: "DJC-PUSH-STATUS-TARGET-REGISTER-V1\n",
});
export type NativeProofVariant = keyof typeof NATIVE_PROOF_DOMAINS;
interface Presentation { presentation_id: string; presentation_generation: string }
interface WidgetTarget { kind: "widget"; app_bundle_id: string; extension_bundle_id: string; widget_kind: string }
interface ActivityTarget extends Presentation {
 kind: "live_activity_update"; app_bundle_id: string; native_activity_id: string;
 native_attributes_type: "DJConnectRemotePlaybackStatusActivityAttributesV1";
 profile_id: "remote-playback-status-v1"; profile_identity_sha256: typeof STATUS_PROFILE_IDENTITY;
}
interface Common {
 contract_version: 1; proof_port_audience: "djc-push-status-native-proof/1";
 proof_job_id: string; bootstrap_id: string; operation_id: string; nonce_b64url: string;
 candidate_sha256: string; source_selection_sha256: string; owner_approval_binding_sha256: string;
 paired_subject_binding_sha256: string; selected_ha_origin: string; client_type: "ios" | "macos";
 identity_policy_sha256: string; deployment_policy_sha256: string; expected_target_generation: string | null;
 bootstrap_deadline_unix_ms: number; original_grant_expires_at_unix_ms: number; apple_key_id_b64: string;
}
interface WidgetRole { token_role: "widget"; profile_identity_sha256: null; prospective_activity_identity: null }
interface ActivityRole { token_role: "live_activity_update"; profile_identity_sha256: typeof STATUS_PROFILE_IDENTITY; prospective_activity_identity: Presentation }
type Roles = WidgetRole | ActivityRole;
export type NativeProofTranscript = Common & (
 (({ proof_variant: "new_key_attestation" } | { proof_variant: "existing_key_assertion"; verified_key_ref: string }) & Roles) |
 ({ proof_variant: "target_registration_assertion"; verified_key_ref: string; native_token_sha256: string } &
   ((WidgetRole & { native_target: WidgetTarget }) | (ActivityRole & { native_target: ActivityTarget })))
);
type Immutable<T> = T extends object ? { readonly [P in keyof T]: Immutable<T[P]> } : T;
/** Validated immutable data only; possessing or constructing it grants no authority. */
export interface DecodedNativeProofTranscript {
 readonly variant: NativeProofVariant;
 readonly canonicalUtf8: string;
 readonly canonicalBase64: string;
 readonly data: Immutable<NativeProofTranscript>;
}
const commonKeys = ["contract_version", "proof_variant", "proof_port_audience", "proof_job_id", "bootstrap_id", "operation_id", "nonce_b64url",
 "candidate_sha256", "source_selection_sha256", "owner_approval_binding_sha256", "paired_subject_binding_sha256", "selected_ha_origin",
 "client_type", "token_role", "identity_policy_sha256", "deployment_policy_sha256", "profile_identity_sha256", "expected_target_generation",
 "prospective_activity_identity", "bootstrap_deadline_unix_ms", "original_grant_expires_at_unix_ms", "apple_key_id_b64"];
const extraKeys: Record<NativeProofVariant, string[]> = {
 new_key_attestation: [], existing_key_assertion: ["verified_key_ref"],
 target_registration_assertion: ["verified_key_ref", "native_target", "native_token_sha256"],
};
const decodedData = new WeakMap<DecodedNativeProofTranscript, { text: string; variant: NativeProofVariant }>();
function invalid(ok: unknown): asserts ok { need(ok, "native_proof_transcript_invalid", 400); }
function object(value: unknown): asserts value is Record<string, unknown> {
 invalid(value !== null && typeof value === "object" && !Array.isArray(value));
}
function closed(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
 object(value); invalid(Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)));
}
function uuid(value: unknown) { invalid(typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)); }
function hash(value: unknown) { invalid(typeof value === "string" && /^[0-9a-f]{64}$/.test(value)); }
function text(value: unknown, max: number) { invalid(typeof value === "string" && [...value].length >= 1 && [...value].length <= max); }
function unicodeAndNumbers(value: unknown): void {
 if (typeof value === "string") for (const c of value) { const n = c.codePointAt(0)!; invalid(n < 0xd800 || n > 0xdfff); }
 if (typeof value === "number") invalid(Number.isSafeInteger(value));
 if (value !== null && typeof value === "object") for (const [key, child] of Object.entries(value)) { unicodeAndNumbers(key); unicodeAndNumbers(child); }
}
function freeze(value: unknown): void {
 if (value !== null && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
}
function standardBase64(value: unknown, max: number): Uint8Array {
 invalid(typeof value === "string" && value.length >= 4 && value.length <= max &&
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value));
 const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
 invalid(base64Encode(bytes) === value); return bytes;
}
function validate(value: unknown): asserts value is NativeProofTranscript {
 object(value); const variant = value.proof_variant;
 invalid(typeof variant === "string" && Object.hasOwn(extraKeys, variant));
 closed(value, [...commonKeys, ...extraKeys[variant as NativeProofVariant]]);
 invalid(value.contract_version === 1 && value.proof_port_audience === "djc-push-status-native-proof/1");
 for (const field of ["proof_job_id", "bootstrap_id", "operation_id"]) uuid(value[field]);
 for (const field of ["candidate_sha256", "source_selection_sha256", "owner_approval_binding_sha256", "paired_subject_binding_sha256", "identity_policy_sha256", "deployment_policy_sha256"]) hash(value[field]);
 invalid(value.expected_target_generation === null || typeof value.expected_target_generation === "string");
 if (value.expected_target_generation !== null) uuid(value.expected_target_generation);
 for (const field of ["bootstrap_deadline_unix_ms", "original_grant_expires_at_unix_ms"]) invalid(Number.isSafeInteger(value[field]) && (value[field] as number) >= 1);
 text(value.selected_ha_origin, 2048); // Actual selected-origin policy belongs to separately authenticated admission.
 invalid(value.client_type === "ios" || value.client_type === "macos");
 invalid(typeof value.nonce_b64url === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.nonce_b64url));
 const nonce = standardBase64((value.nonce_b64url as string).replaceAll("-", "+").replaceAll("_", "/") + "=", 44);
 invalid(nonce.length === 32 && standardBase64(value.apple_key_id_b64, 44).length === 32);
 invalid(value.token_role === "widget" || value.token_role === "live_activity_update");
 invalid(value.client_type !== "macos" || value.token_role === "widget");
 if (value.token_role === "widget") invalid(value.profile_identity_sha256 === null && value.prospective_activity_identity === null);
 else {
  invalid(value.profile_identity_sha256 === STATUS_PROFILE_IDENTITY);
  closed(value.prospective_activity_identity, ["presentation_id", "presentation_generation"]);
  uuid(value.prospective_activity_identity.presentation_id); uuid(value.prospective_activity_identity.presentation_generation);
 }
 if (variant !== "new_key_attestation") uuid(value.verified_key_ref);
 if (variant === "target_registration_assertion") {
  hash(value.native_token_sha256);
  const fields = value.token_role === "widget" ? ["kind", "app_bundle_id", "extension_bundle_id", "widget_kind"] :
   ["kind", "app_bundle_id", "native_activity_id", "native_attributes_type", "presentation_id", "presentation_generation", "profile_id", "profile_identity_sha256"];
  closed(value.native_target, fields); const target = value.native_target;
  invalid(target.kind === value.token_role); text(target.app_bundle_id, 200);
  if (value.token_role === "widget") { text(target.extension_bundle_id, 200); text(target.widget_kind, 200); }
  else {
   text(target.native_activity_id, 200); uuid(target.presentation_id); uuid(target.presentation_generation);
   invalid(target.native_attributes_type === "DJConnectRemotePlaybackStatusActivityAttributesV1" && target.profile_id === "remote-playback-status-v1" && target.profile_identity_sha256 === STATUS_PROFILE_IDENTITY);
   const prospective = value.prospective_activity_identity as Record<string, unknown>;
   need(target.presentation_id === prospective.presentation_id && target.presentation_generation === prospective.presentation_generation,
    "native_proof_context_mismatch", 403);
  }
 }
}
/** Requires original canonical bytes, not a parsed object that lost duplicate/numeric spelling. */
export function decodeNativeProofTranscript(raw: Uint8Array): DecodedNativeProofTranscript {
 invalid(raw instanceof Uint8Array && raw.byteLength >= 2 && raw.byteLength <= NATIVE_TRANSCRIPT_MAX_BYTES);
 const bytes = raw.slice(); let source: string;
 try { source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
 catch { need(false, "native_proof_transcript_invalid", 400); }
 invalid(source.charCodeAt(0) !== 0xfeff);
 const data: unknown = parseStrictJson(source); unicodeAndNumbers(data); validate(data);
 // Integral floats, exponents, -0, whitespace and alternate escapes cannot disappear into signing bytes.
 invalid(canonical(data) === source);
 freeze(data);
 const result: DecodedNativeProofTranscript = Object.freeze({ variant: data.proof_variant, canonicalUtf8: source, canonicalBase64: base64Encode(bytes), data });
 decodedData.set(result, { text: source, variant: data.proof_variant }); return result;
}
export function decodeNativeProofTranscriptBase64(encoded: string): DecodedNativeProofTranscript {
 return decodeNativeProofTranscript(standardBase64(encoded, NATIVE_TRANSCRIPT_MAX_BASE64));
}
function snapshot(value: DecodedNativeProofTranscript) {
 const saved = decodedData.get(value); invalid(saved); return saved;
}
/** Equality of two validated DATA values, never an authenticated admission decision. */
export function matchesExpectedNativeProofData(actual: DecodedNativeProofTranscript, expected: DecodedNativeProofTranscript): boolean {
 return snapshot(actual).text === snapshot(expected).text;
}
/** Pure digest derivation. Unexpected WebCrypto failures propagate unchanged, not as proof rejection. */
export async function digestNativeProofTranscript(value: DecodedNativeProofTranscript) {
 const saved = snapshot(value); const source = saved.text, domain = NATIVE_PROOF_DOMAINS[saved.variant];
 return Object.freeze({ preparedTranscriptSha256: await sha256Hex(source), clientDataHashSha256: await sha256Hex(domain + source) });
}
