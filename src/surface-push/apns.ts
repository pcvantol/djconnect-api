import { need, type EventInput, type JsonObject } from "./wire";
import type { Principal, TargetRow } from "./store";
export interface ActivityContent { content_state: JsonObject; observed_at_ms: number; expires_at_ms: number }
/** A compiled, independently reviewed Apple/Core schema; never loaded from request JSON or env. */
export interface ActivityProfile { id: string; parseContent(payload: JsonObject): ActivityContent }
export interface PushPayload { body: JsonObject; expiresAt: number }
export function payload(p: Principal, row: TargetRow, input: EventInput, now: number, profiles: readonly ActivityProfile[] = []): PushPayload {
 if (p.role === "widget") { need(input.event === "widget_reload"); return { body: { aps: { "content-changed": true } }, expiresAt: row.expires_at }; }
 need(p.role === "live_activity_update" && ["activity_update", "activity_end"].includes(input.event), "surface_start_not_admitted", 403);
 need(p.external_content_allowed === 1 && input.profile_id === p.activity_profile, "surface_content_not_admitted", 403);
 const profile = profiles.find(x => x.id === p.activity_profile); need(profile && input.payload, "surface_payload_contract_pending", 403);
 const content = profile.parseContent(input.payload);
 need(Number.isSafeInteger(content.observed_at_ms) && Number.isSafeInteger(content.expires_at_ms) && content.observed_at_ms <= now && now < content.expires_at_ms && content.expires_at_ms <= row.expires_at && content.expires_at_ms <= content.observed_at_ms + 120000, "surface_content_expired", 409);
 const aps: JsonObject = { timestamp: Math.floor(content.observed_at_ms / 1000), event: input.event === "activity_end" ? "end" : "update", "content-state": content.content_state, "stale-date": Math.floor(content.expires_at_ms / 1000) };
 if (input.event === "activity_end") aps["dismissal-date"] = Math.floor(now / 1000) - 1;
 const result = { aps }; need(new TextEncoder().encode(JSON.stringify(result)).length <= 4096, "surface_content_too_large", 413); return { body: result, expiresAt: content.expires_at_ms };
}
export function request(p: Principal, row: TargetRow, token: string, payload: PushPayload, authorization: string, now: number): { url: string; init: RequestInit } {
 need(/^(?:[a-f0-9]{2}){16,2048}$/.test(token), "surface_token_invalid", 503);
 need(p.role !== "live_activity_start", "surface_start_not_admitted", 403);
 need(Number.isSafeInteger(payload.expiresAt) && now < payload.expiresAt && payload.expiresAt <= row.expires_at, "surface_content_expired", 409);
 const type = p.role === "widget" ? "widgets" : "liveactivity";
 return { url: (p.environment === "sandbox" ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com") + "/3/device/" + token,
  init: { method: "POST", headers: { authorization: "bearer " + authorization, "apns-push-type": type, "apns-topic": p.parent_bundle + ".push-type." + type, "apns-expiration": String(Math.floor(payload.expiresAt / 1000)), "apns-priority": "5", "content-type": "application/json" }, body: JSON.stringify(payload.body), signal: AbortSignal.timeout(Math.max(1, Math.min(10000, payload.expiresAt - now))) } };
}
