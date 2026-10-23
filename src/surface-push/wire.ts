/** Candidate server-to-server wire. Not admitted by the public Worker root. */
export const VERSION = "djc-surface-push/1" as const;
export const ROLES = ["widget", "live_activity_update", "live_activity_start"] as const;
export type Role = typeof ROLES[number];
export type OperationKind = "register" | "revoke" | "event" | "status";
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };
export interface Coordinate { contract_version: 1; registration_id: string; generation: string; revision: number; operation_id: string; binding_id: string; device_binding: string; owner_binding: string }
export interface Target { instance_id: string; app_bundle_id: string; extension_bundle_id?: string; widget_kind?: string; activity_id?: string; attributes_type?: string }
export interface RegisterInput extends Coordinate { expires_at_ms: number; token_role: Role; platform: string; apns_environment: "sandbox" | "production"; target: Target; apns_token: string }
export interface EventInput extends Coordinate { event: "widget_reload" | "activity_update" | "activity_end" | "activity_start"; profile_id?: string; payload?: JsonObject }
export type Input = Coordinate | RegisterInput | EventInput;
export class SurfaceError extends Error {
 constructor(public readonly status: number, public readonly code: string) { super(code); }
}
export function need(ok: unknown, code = "invalid_request", status = 400): asserts ok { if (!ok) throw new SurfaceError(status, code); }
function object(value: unknown): asserts value is Record<string, unknown> { need(value !== null && typeof value === "object" && !Array.isArray(value)); }
function keys(value: Record<string, unknown>, required: string[], optional: string[] = []) {
 need(required.every(k => Object.hasOwn(value, k)) && Object.keys(value).every(k => [...required, ...optional].includes(k)));
}
function id(value: unknown): asserts value is string { need(typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value)); }
function integer(value: unknown, minimum: number): asserts value is number { need(Number.isSafeInteger(value) && (value as number) >= minimum); }
/** Parse with duplicate-key rejection, including escaped duplicate keys; no JSON reviver ambiguity. */
export function parseStrictJson(text: string): unknown {
 let at = 0;
 const ws = () => { while (/[\x20\x09\x0a\x0d]/.test(text[at] ?? "x")) at++; };
 const string = (): string => {
  need(text[at] === '"'); const start = at++;
  while (at < text.length) { const ch = text[at++]; if (ch === "\\") { at++; continue; } if (ch === '"') { try { return JSON.parse(text.slice(start, at)) as string; } catch { throw new SurfaceError(400, "invalid_json"); } } }
  throw new SurfaceError(400, "invalid_json");
 };
 const value = (depth: number): unknown => {
  need(depth <= 16, "invalid_json"); ws(); const ch = text[at];
  if (ch === '"') return string();
  if (ch === "{") {
   at++; ws(); const result: Record<string, unknown> = Object.create(null);
   if (text[at] === "}") { at++; return result; }
   while (true) { ws(); const key = string(); need(!Object.hasOwn(result, key), "duplicate_json_key"); ws(); need(text[at++] === ":", "invalid_json"); result[key] = value(depth + 1); ws(); const end = text[at++]; if (end === "}") return result; need(end === ",", "invalid_json"); }
  }
  if (ch === "[") {
   at++; ws(); const result: unknown[] = []; if (text[at] === "]") { at++; return result; }
   while (true) { result.push(value(depth + 1)); ws(); const end = text[at++]; if (end === "]") return result; need(end === ",", "invalid_json"); }
  }
  const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
  need(match, "invalid_json"); at += match[0].length; const parsed: unknown = JSON.parse(match[0]); need(typeof parsed !== "number" || Number.isFinite(parsed), "invalid_json"); return parsed;
 };
 const result = value(0); ws(); need(at === text.length, "invalid_json"); return result;
}
export function canonical(value: unknown): string {
 if (value === null || typeof value !== "object") return JSON.stringify(value);
 if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
 return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + canonical((value as Record<string, unknown>)[k])).join(",") + "}";
}
export function operationCreated(identifier: string): number {
 need(/^[a-f0-9]{8}-[a-f0-9]{4}-7[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(identifier), "invalid_operation_id");
 return Number.parseInt(identifier.replaceAll("-", "").slice(0, 12), 16);
}
export function decode(kind: OperationKind, value: unknown, now: number): Input {
 object(value);
 const base = ["contract_version", "registration_id", "generation", "revision", "operation_id", "binding_id", "device_binding", "owner_binding"];
 keys(value, [...base, ...(kind === "register" ? ["expires_at_ms", "token_role", "platform", "apns_environment", "target", "apns_token"] : []), ...(kind === "event" ? ["event"] : [])], kind === "event" ? ["profile_id", "payload"] : []);
 need(value.contract_version === 1); id(value.registration_id); id(value.generation); integer(value.revision, 1); need((value.revision as number) < Number.MAX_SAFE_INTEGER); need(typeof value.operation_id === "string");
 const created = operationCreated(value.operation_id);
 if (kind !== "status") { need(created <= now + 30000, "operation_clock_unqualified", 409); need(now < created + 300000, "operation_expired", 409); }
 for (const name of ["binding_id", "device_binding", "owner_binding"]) need(typeof value[name] === "string" && /^[a-f0-9]{64}$/.test(value[name] as string));
 if (kind === "register") {
  integer(value.expires_at_ms, 1); need((value.expires_at_ms as number) > now && (value.expires_at_ms as number) <= now + 8 * 3600000, "invalid_expiry");
  need(ROLES.includes(value.token_role as Role)); need(["ios", "ipados", "maccatalyst", "macos", "watchos", "visionos"].includes(value.platform as string));
  need(["sandbox", "production"].includes(value.apns_environment as string));
  need(typeof value.apns_token === "string" && /^(?:[a-f0-9]{2}){16,2048}$/.test(value.apns_token));
  object(value.target); const fields = ["instance_id", "app_bundle_id", ...(value.token_role === "widget" ? ["extension_bundle_id", "widget_kind"] : value.token_role === "live_activity_update" ? ["activity_id", "attributes_type"] : ["attributes_type"])]; keys(value.target, fields);
  for (const name of fields) { const v = value.target[name]; if (name.endsWith("bundle_id")) need(typeof v === "string" && v.length <= 200 && /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(v)); else id(v); }
 }
 if (kind === "event") {
  need(["widget_reload", "activity_update", "activity_end", "activity_start"].includes(value.event as string));
  if (value.event === "widget_reload") need(!Object.hasOwn(value, "profile_id") && !Object.hasOwn(value, "payload"));
  else { need(typeof value.profile_id === "string" && /^[A-Za-z0-9_-]{1,96}\/[1-9][0-9]{0,2}$/.test(value.profile_id)); object(value.payload); }
 }
 return value as unknown as Input;
}
export async function readInput(request: Request, kind: OperationKind, now: number): Promise<Input> {
 need((request.headers.get("content-type") ?? "").trim().toLowerCase() === "application/json", "unsupported_media_type", 415);
 need(!request.headers.has("content-encoding"));
 const reader = request.body?.getReader(); need(reader); const chunks: Uint8Array[] = []; let size = 0;
 try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; need(size <= 16384, "payload_too_large", 413); chunks.push(part.value); } } catch (e) { await reader.cancel().catch(() => {}); throw e; }
 const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
 try { return decode(kind, parseStrictJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)), now); }
 catch (e) { if (e instanceof SurfaceError) throw e; throw new SurfaceError(400, "invalid_json"); }
}
