import { base64Url, sha256Hex } from "../crypto";
import { canonical, need, operationCreated, parseStrictJson, SurfaceError, type JsonObject, type Role } from "./wire";

export const ISSUER_VERSION = "djc-surface-issuer/1";
export const ISSUER_PREFIX = "/v1/push/surface/issuer/";
export type PurposeAction = "challenge" | "issue" | "status" | "withdraw";
export interface Policy {
 token_role: Role; platform: string; apns_environment: "sandbox" | "production";
 target: { app_bundle_id: string; extension_bundle_id?: string; widget_kind?: string; attributes_type?: string };
 activity_profile: string | null; external_content_allowed: boolean;
 original_grant_expires_at_ms: number; max_operations: number; max_events: number; max_challenges: number;
}
export interface Enrolment {
 contract_version: 1; purpose: "surface_push"; action: "enrol"; operation_id: string;
 delegation_id: string; expected_revision: 0; approval_reference: string;
 install_id: string; device_binding: string; owner_binding: string; grant_binding: string; source_binding: string; binding_id: string;
 public_key: { kty: "EC"; crv: "P-256"; x: string; y: string }; policy: Policy;
}
export interface Statement {
 contract_version: 1; purpose: "surface_push"; action: PurposeAction; operation_id: string;
 delegation_id: string; delegation_revision: 1; key_thumbprint: string;
 challenge_id?: string; nonce?: string; scope_digest?: string;
}
export interface SignedStatement { payload: Statement; signature: string }
export function closed(value: unknown, fields: readonly string[]): asserts value is Record<string, unknown> {
 need(value !== null && typeof value === "object" && !Array.isArray(value));
 need(Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k)));
}
export function id(value: unknown): asserts value is string { need(typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value)); }
export function hex(value: unknown): asserts value is string { need(typeof value === "string" && /^[a-f0-9]{64}$/.test(value)); }
function integer(value: unknown, min: number, max: number) { need(Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max); }
export function operationDeadline(operation: string, now: number): number {
 const created = operationCreated(operation);
 need(created <= now + 30000, "operation_clock_unqualified", 409);
 need(now < created + 300000, "operation_expired", 409);
 return created + 300000;
}
export function bytes(value: string, length: number): Uint8Array {
 need(typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value));
 let result: Uint8Array<ArrayBuffer>;
 try { result = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0)); }
 catch { throw new SurfaceError(400,"invalid_request"); }
 need(result.length === length && base64Url(result.buffer) === value); return result;
}
export async function publicKey(value: Enrolment["public_key"]): Promise<CryptoKey> {
 closed(value, ["kty", "crv", "x", "y"]); need(value.kty === "EC" && value.crv === "P-256");
 bytes(value.x, 32); bytes(value.y, 32);
 try { return await crypto.subtle.importKey("jwk", value, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]); }
 catch { throw new SurfaceError(400, "surface_purpose_key_invalid"); }
}
export async function thumbprint(value: Enrolment["public_key"]): Promise<string> {
 return sha256Hex(canonical([ISSUER_VERSION, "public-key", value]));
}
export function signingBytes(path: string, statement: Statement): Uint8Array {
 return new TextEncoder().encode(canonical([ISSUER_VERSION, "POST", path, statement]));
}
export function enrolment(value: unknown, now: number, admittedProfiles: readonly string[]): Enrolment {
 closed(value, ["contract_version","purpose","action","operation_id","delegation_id","expected_revision","approval_reference","install_id","device_binding","owner_binding","grant_binding","source_binding","binding_id","public_key","policy"]);
 need(value.contract_version === 1 && value.purpose === "surface_push" && value.action === "enrol" && value.expected_revision === 0);
 for (const k of ["delegation_id","approval_reference","install_id"]) id(value[k]);
 for (const k of ["device_binding","owner_binding","grant_binding","source_binding","binding_id"]) hex(value[k]);
 need(typeof value.operation_id === "string"); operationDeadline(value.operation_id, now);
 const p = value.policy; closed(p, ["token_role","platform","apns_environment","target","activity_profile","external_content_allowed","original_grant_expires_at_ms","max_operations","max_events","max_challenges"]);
 need(typeof p.token_role === "string" && ["widget","live_activity_update","live_activity_start"].includes(p.token_role));
 need(typeof p.platform === "string" && ["ios","ipados","maccatalyst","macos","watchos","visionos"].includes(p.platform));
 need(p.token_role === "widget" || ["ios","ipados"].includes(p.platform));
 need(typeof p.apns_environment === "string" && ["sandbox","production"].includes(p.apns_environment));
 const fields = p.token_role === "widget" ? ["app_bundle_id","extension_bundle_id","widget_kind"] : ["app_bundle_id","attributes_type"];
 closed(p.target, fields);
 for (const field of fields) { const v = p.target[field]; if (field.endsWith("bundle_id")) need(typeof v === "string" && v.length <= 200 && /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(v)); else id(v); }
 if (p.token_role === "widget") need(String(p.target.extension_bundle_id).startsWith(String(p.target.app_bundle_id) + "."));
 need(typeof p.external_content_allowed === "boolean");
 need(p.activity_profile === null || (typeof p.activity_profile === "string" && admittedProfiles.includes(p.activity_profile)), "surface_payload_contract_pending", 403);
 need(!p.external_content_allowed || (p.token_role === "live_activity_update" && p.activity_profile !== null), "surface_content_not_admitted", 403);
 need(p.token_role === "live_activity_update" || (!p.external_content_allowed && p.activity_profile === null));
 integer(p.original_grant_expires_at_ms, now + 1, now + 8 * 3600000);
 integer(p.max_operations, 1, 10000); integer(p.max_events, 1, 1000); integer(p.max_challenges, 1, 100);
 return value as unknown as Enrolment;
}
export function statement(value: unknown, action: PurposeAction): SignedStatement {
 closed(value, ["payload", "signature"]); need(typeof value.signature === "string"); bytes(value.signature, 64);
 const p = value.payload;
 closed(p, ["contract_version","purpose","action","operation_id","delegation_id","delegation_revision","key_thumbprint", ...(action === "issue" ? ["challenge_id","nonce","scope_digest"] : [])]);
 need(p.contract_version === 1 && p.purpose === "surface_push" && p.action === action && p.delegation_revision === 1);
 id(p.delegation_id); hex(p.key_thumbprint); need(typeof p.operation_id === "string"); operationCreated(p.operation_id);
 if (action === "issue") { id(p.challenge_id); need(typeof p.nonce === "string"); bytes(p.nonce,32); hex(p.scope_digest); }
 return value as unknown as SignedStatement;
}
export async function readBody(request: Request): Promise<{ value: unknown; raw: ArrayBuffer }> {
 need((request.headers.get("content-type") ?? "").trim().toLowerCase() === "application/json", "unsupported_media_type", 415);
 need(!request.headers.has("content-encoding")); const reader = request.body?.getReader(); need(reader);
 const parts: Uint8Array[] = []; let size = 0;
 try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.length; need(size <= 16384, "payload_too_large", 413); parts.push(part.value); } }
 catch (error) { await reader.cancel().catch(() => {}); throw error; }
 const result = new Uint8Array(size); let at = 0; for (const part of parts) { result.set(part,at); at += part.length; }
 try { return { value: parseStrictJson(new TextDecoder("utf-8", { fatal:true,ignoreBOM:true }).decode(result)), raw: result.buffer }; }
 catch (error) { if (error instanceof SurfaceError) throw error; throw new SurfaceError(400,"invalid_json"); }
}
