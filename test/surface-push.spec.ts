import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import migration from "../migrations/0009_surface_push.sql?raw";
import ordinarySchema from "../migrations/0001_initial.sql?raw";
import { sha256Hex } from "../src/crypto";
import { createSurfaceProvider } from "../src/surface-push/provider";
import { createSurfacePushHandler, type SurfaceOptions } from "../src/surface-push/handler";
import { parseStrictJson, type JsonObject } from "../src/surface-push/wire";
import type { ActivityProfile } from "../src/surface-push/apns";

const NOW = Date.UTC(2026, 9, 22, 0, 0, 0), EXPIRES = NOW + 3600000;
const CAP = "djcs_" + "a".repeat(43), KEY = btoa("0123456789abcdef0123456789abcdef");
let sequence = 0;
function operation(time = NOW): string { return time.toString(16).padStart(12, "0").replace(/^(.{8})(.{4})$/, "$1-$2") + "-7000-8000-" + (++sequence).toString(16).padStart(12, "0"); }
function coordinate() { return { contract_version: 1, registration_id: "surface-example", generation: "example-generation", revision: 1, operation_id: operation(), binding_id: "b".repeat(64), device_binding: "d".repeat(64), owner_binding: "e".repeat(64) }; }
function registration() { return { ...coordinate(), expires_at_ms: EXPIRES, token_role: "widget", platform: "macos", apns_environment: "sandbox", target: { instance_id: "SessionWidget", app_bundle_id: "dev.djconnect.mac", extension_bundle_id: "dev.djconnect.mac.track-insight-widget", widget_kind: "DJConnectSessionWidget" }, apns_token: "01".repeat(32) }; }
type Body = Record<string, unknown>;
function options(overrides: Partial<SurfaceOptions> = {}): SurfaceOptions { return { db: env.DB, encryptionKey: KEY, now: () => NOW, authorizeProvider: async () => "example.provider.jwt", ...overrides }; }
function client(overrides: Partial<SurfaceOptions> = {}) {
 const handler = createSurfacePushHandler(options(overrides));
 return (kind: string, body: Body | string, headers: Record<string, string> = {}) => handler(new Request("https://local.test/v1/push/surface/" + kind, { method: "POST", headers: { authorization: "Bearer " + CAP, "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) }));
}
function terminal(body: Pick<ReturnType<typeof registration>, "contract_version" | "registration_id" | "generation" | "revision" | "binding_id" | "device_binding" | "owner_binding">) { const { contract_version, registration_id, generation, revision, binding_id, device_binding, owner_binding } = body; return { contract_version, registration_id, generation, revision, binding_id, device_binding, owner_binding, operation_id: operation() }; }
async function capability(role = "widget", platform = "macos", external = 0) {
 const parent = platform === "ios" ? "dev.djconnect.ios" : "dev.djconnect.mac";
 await env.DB.prepare(`INSERT INTO surface_push_capabilities
 (id,token_hash,install_id,device_binding,owner_binding,parent_bundle,extension_bundle,widget_kind,attributes_type,activity_profile,external_content_allowed,platform,environment,role,expires_at,revoked_at,max_operations,max_events)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?)`).bind("example-cap", await sha256Hex(CAP), "example-install", "d".repeat(64), "e".repeat(64), parent, parent + ".track-insight-widget", "DJConnectSessionWidget", "ExampleAttributes", "example-closed/1", external, platform, "sandbox", role, NOW + 8 * 3600000, 100, 10).run();
}
async function row() { return env.DB.prepare("SELECT * FROM surface_push_targets").first<Record<string, unknown>>(); }
const profile: ActivityProfile = { id: "example-closed/1", parseContent(payload) {
 if (Object.keys(payload).sort().join() !== "expires_at_ms,observed_at_ms,state" || payload.state !== "playing") throw new Error("closed_fixture_schema");
 return { content_state: { state: "playing" }, observed_at_ms: payload.observed_at_ms as number, expires_at_ms: payload.expires_at_ms as number };
} };

describe("source-only typed surface relay with actual D1", () => {
 beforeAll(async () => { for (const sql of (ordinarySchema + "\n" + migration).split(";").filter(s => s.replace(/--[^\n]*/g, "").trim())) await env.DB.prepare(sql).run(); });
 beforeEach(async () => { sequence = 0; await env.DB.batch([env.DB.prepare("DELETE FROM surface_push_operations"), env.DB.prepare("DELETE FROM surface_push_targets"), env.DB.prepare("DELETE FROM surface_push_capabilities")]); await capability(); });
 it("registers exactly Core's opaque generation/revision/expiry and stores only authenticated ciphertext", async () => {
  const input = registration(), response = await client()("register", input); expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ contract_version: 1, success: true, registration_id: input.registration_id, generation: input.generation, revision: 1, expires_at_ms: EXPIRES });
  const stored = await row(); expect(stored?.ciphertext).toBeTypeOf("string"); expect(stored?.ciphertext).not.toContain(input.apns_token); expect(JSON.stringify(stored)).not.toContain(input.apns_token);
 });
 it("persists a revoke tombstone before an unseen late register and across handler restart", async () => {
  const input = registration(), revoke = terminal(input);
  expect(await (await client()("revoke", revoke)).json()).toMatchObject({ success: true, state: "revoked", revision: 1 });
  expect(await (await client()("register", input)).json()).toMatchObject({ success: false, state: "revoked" });
  expect(await (await client()("register", { ...input, revision: 2, operation_id: operation() })).json()).toMatchObject({ success: false, state: "revoked" });
  expect((await row())?.ciphertext).toBeNull();
 });
 it("a historical register acknowledgment cannot claim current success after durable revoke", async () => {
  const input = registration(), call = client(); await call("register", input); await call("revoke", terminal(input));
  expect(await (await client()("register", input)).json()).toMatchObject({ success: false, replayed: true, state: "revoked", operation_state: "registered" });
 });
 it("atomically rotates while stale revoke and stale revision cannot affect the replacement", async () => {
  const input = registration(), call = client(); await call("register", input);
  const next = { ...input, revision: 2, operation_id: operation(), apns_token: "02".repeat(32) }; expect((await call("register", next)).status).toBe(200);
  expect((await call("revoke", terminal(input))).status).toBe(409); expect((await row())?.revision).toBe(2); expect((await row())?.state).toBe("active");
  expect((await call("register", { ...next, operation_id: operation() })).status).toBe(409);
 });
 it("status binds the historical operation to its recorded revision after rotation", async () => {
  const input = registration(), call = client(); await call("register", input);
  await call("register", { ...input, revision: 2, operation_id: operation() });
  const status = { ...terminal(input), operation_id: input.operation_id };
  const before = await row();
  expect((await call("status", { ...status, revision: 2 })).status).toBe(409);
  expect(await (await call("status", status)).json()).toMatchObject({ success: false, revision: 1, current_revision: 2, operation_id: input.operation_id, operation_state: "registered" });
  expect(await row()).toEqual(before);
 });
 it("concurrent register CAS has one winner and no mixed token state", async () => {
  const input = registration(), call = client(); await call("register", input);
  const responses = await Promise.all([call("register", { ...input, revision: 2, operation_id: operation(), apns_token: "02".repeat(32) }), call("register", { ...input, revision: 2, operation_id: operation(), apns_token: "03".repeat(32) })]);
  expect(responses.map(x => x.status).sort()).toEqual([200, 409]); expect((await row())?.revision).toBe(2);
 });
 it("idempotent register returns original expiry without rewriting encryption", async () => {
  const input = registration(), call = client(); await call("register", input); const first = await row();
  expect(await (await client()("register", input)).json()).toMatchObject({ success: true, replayed: true, expires_at_ms: EXPIRES }); expect(await row()).toEqual(first);
  expect((await call("register", { ...input, expires_at_ms: EXPIRES + 1 })).status).toBe(409);
  expect((await call("register", { ...input, revision: 2, operation_id: operation(), expires_at_ms: EXPIRES + 1 })).status).toBe(409);
 });
 it.each(["device_binding", "owner_binding"])("does not accept another %s from an authenticated caller", async field => {
  expect((await client()("register", { ...registration(), [field]: "f".repeat(64) })).status).toBe(403); expect(await row()).toBeNull();
 });
 it.each(["platform", "apns_environment", "token_role"])("does not let a caller change configured %s", async field => {
  const bad = { platform: "ios", apns_environment: "production", token_role: "live_activity_start" }[field];
  expect((await client()("register", { ...registration(), [field]: bad })).status).toBeGreaterThanOrEqual(400); expect(await row()).toBeNull();
 });
 it("rejects caller topics, wrong bundle/extension and arbitrary target keys", async () => {
  const input = registration(), call = client();
  expect((await call("register", { ...input, topic: "evil" })).status).toBe(400);
  expect((await call("register", { ...input, target: { ...input.target, app_bundle_id: "evil.invalid" } })).status).toBe(403);
  expect((await call("register", { ...input, target: { ...input.target, extension_bundle_id: "dev.djconnect.mac.other" } })).status).toBe(403);
 });
 it("rejects malformed UTF8, escaped duplicate keys, huge bodies and content encoding", async () => {
  const call = client(); expect(() => parseStrictJson('{"x":1,"\\u0078":2}')).toThrow();
  expect((await call("register", JSON.stringify(registration()).replace('"revision":1', '"revision":1,"revision":2'))).status).toBe(400);
  expect((await call("register", " ".repeat(16385))).status).toBe(413);
  expect((await call("register", registration(), { "content-encoding": "gzip" })).status).toBe(400);
  const handler = createSurfacePushHandler(options()); expect((await handler(new Request("https://local.test/v1/push/surface/register", { method: "POST", headers: { authorization: "Bearer " + CAP, "content-type": "application/json" }, body: new Uint8Array([0xff]) }))).status).toBe(400);
 });
 it("keeps ordinary app credentials, browser/cookie traffic and unknown routes outside this contract", async () => {
  const call = client(); expect((await call("register", registration(), { authorization: "Bearer djci_example" })).status).toBe(401);
  expect((await call("register", registration(), { origin: "https://example.invalid" })).status).toBe(403);
  expect((await call("register", registration(), { cookie: "synthetic" })).status).toBe(403); expect((await call("register?override=true", registration())).status).toBe(404);
 });
 it("requires UUIDv7 original operation freshness and never renews on retry", async () => {
  expect((await client()("register", { ...registration(), operation_id: operation(NOW - 300000) })).status).toBe(409);
  expect((await client()("register", { ...registration(), operation_id: operation(NOW + 30001) })).status).toBe(409);
  expect((await client()("register", { ...registration(), expires_at_ms: NOW + 8 * 3600000 + 1 })).status).toBe(400);
 });
 it("a delayed body cannot admit a register after its original operation deadline", async () => {
  let clock = NOW; const input = registration();
  const stream = new ReadableStream<Uint8Array>({ pull(controller) { clock = NOW + 300000; controller.enqueue(new TextEncoder().encode(JSON.stringify(input))); controller.close(); } }, { highWaterMark: 0 });
  const handler = createSurfacePushHandler(options({ now: () => clock }));
  const response = await handler(new Request("https://local.test/v1/push/surface/register", { method: "POST", headers: { authorization: "Bearer " + CAP, "content-type": "application/json" }, body: stream }));
  expect(response.status).toBe(409); expect(await row()).toBeNull();
  expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM surface_push_operations").first("n")).toBe(0);
 });
 it("a widget operation expiring during provider authorization is never dispatched", async () => {
  let clock = NOW; const input = registration(), transport = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 }));
  const call = client({ now: () => clock, fetcher: transport, authorizeProvider: async () => { clock = NOW + 300000; return "example.provider.jwt"; } });
  await call("register", input); const event = { ...terminal(input), event: "widget_reload" };
  expect(await (await call("event", event)).json()).toMatchObject({ success: false, operation_state: "not_sent" });
  expect(transport).not.toHaveBeenCalled();
 });
 it("unknown original operation status is read-only, scoped and secret-free", async () => {
  const input = terminal(registration()), response = await client()("status", input);
  expect(response.status).toBe(200); expect(await response.json()).toMatchObject({ success: false, state: "unknown", operation_state: "unknown" }); expect(await row()).toBeNull();
  expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM surface_push_operations").first("n")).toBe(0);
 });
 it("has a finite capability operation budget without evicting or replaying operations", async () => {
  await env.DB.prepare("UPDATE surface_push_capabilities SET max_operations=1").run(); const input = registration(), call = client();
  expect((await call("register", input)).status).toBe(200); expect((await call("register", input)).status).toBe(200); expect((await call("register", { ...input, revision: 2, operation_id: operation() })).status).toBe(429);
  expect((await call("revoke", terminal(input))).status).toBe(200);
 });
 it("dispatches one widget invalidation with fixed real APNs headers and no music data", async () => {
  const transport = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 })), call = client({ fetcher: transport }); const input = registration(); await call("register", input);
  const event = { ...terminal(input), event: "widget_reload" }; const responses = await Promise.all([call("event", event), call("event", event)]);
  expect(transport).toHaveBeenCalledTimes(1); const [url, init] = transport.mock.calls[0]!; expect(url).toBe("https://api.sandbox.push.apple.com/3/device/" + input.apns_token);
  expect(init?.headers).toMatchObject({ "apns-topic": "dev.djconnect.mac.push-type.widgets", "apns-push-type": "widgets" }); expect(JSON.parse(String(init?.body))).toEqual({ aps: { "content-changed": true } });
  const restart = client({ fetcher: transport }); expect((await restart("event", event)).status).toBe(200); expect(transport).toHaveBeenCalledTimes(1); expect(responses.some(r => r.status === 200)).toBe(true);
 });
 it("does not retry an unknown APNs outcome even after handler restart", async () => {
  const transport = vi.fn<typeof fetch>().mockRejectedValue(new Error("synthetic_unknown_outcome")), call = client({ fetcher: transport }); const input = registration(); await call("register", input);
  const event = { ...terminal(input), event: "widget_reload" }; expect((await call("event", event)).status).toBe(202);
  expect(await (await client({ fetcher: transport })("event", event)).json()).toMatchObject({ success: false, replayed: true, operation_state: "unknown" }); expect(transport).toHaveBeenCalledTimes(1);
 });
 it("revoke between reservation and dispatch prevents the provider call", async () => {
  const transport = vi.fn<typeof fetch>(), input = registration(), base = client(); await base("register", input);
  const call = client({ fetcher: transport, authorizeProvider: async () => { await base("revoke", terminal(input)); return "example.provider.jwt"; } });
  expect(await (await call("event", { ...terminal(input), event: "widget_reload" })).json()).toMatchObject({ success: false, operation_state: "not_sent", state: "revoked" }); expect(transport).not.toHaveBeenCalled();
 });
 it("a late410 for an earlier rotation cannot revoke the newer token", async () => {
  const input = registration(), base = client(); await base("register", input);
  const transport = vi.fn<typeof fetch>().mockImplementation(async () => { await base("register", { ...input, revision: 2, operation_id: operation(), apns_token: "02".repeat(32) }); return new Response(null, { status: 410 }); });
  await client({ fetcher: transport })("event", { ...terminal(input), event: "widget_reload" }); expect((await row())?.revision).toBe(2); expect((await row())?.state).toBe("active");
 });
 it("tampered token metadata/ciphertext fails before a provider call", async () => {
  const input = registration(), call = client(), transport = vi.fn<typeof fetch>(); await call("register", input); await env.DB.prepare("UPDATE surface_push_targets SET target_json='{}'").run();
  await client({ fetcher: transport })("event", { ...terminal(input), event: "widget_reload" }); expect(transport).not.toHaveBeenCalled();
 });
 it("provider absence and unauthorized live content have no dispatch effect", async () => {
  const input = registration(), call = client({ authorizeProvider: undefined }); await call("register", input); expect((await call("event", { ...terminal(input), event: "widget_reload" })).status).toBe(503);
  expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM surface_push_operations WHERE kind='event'").first("n")).toBe(0);
 });
 it.each(["live_activity_update", "live_activity_start"])("registers %s independently without starting or sending anything", async role => {
  await env.DB.prepare("DELETE FROM surface_push_capabilities").run(); await capability(role, "ios"); const transport = vi.fn<typeof fetch>(), call = client({ fetcher: transport });
  const input = { ...registration(), token_role: role, platform: "ios", target: role === "live_activity_update" ? { instance_id: "instance", app_bundle_id: "dev.djconnect.ios", activity_id: "activity", attributes_type: "ExampleAttributes" } : { instance_id: "instance", app_bundle_id: "dev.djconnect.ios", attributes_type: "ExampleAttributes" } };
  expect((await call("register", input)).status).toBe(200); expect(transport).not.toHaveBeenCalled();
  expect((await call("event", { ...terminal(registration()), event: role === "live_activity_start" ? "activity_start" : "activity_update", profile_id: "example-closed/1", payload: {} })).status).toBe(403); expect(transport).not.toHaveBeenCalled();
 });
 it("a compiled synthetic closed activity profile produces actual update/end envelopes only with separate rights", async () => {
  await env.DB.prepare("DELETE FROM surface_push_capabilities").run(); await capability("live_activity_update", "ios", 1);
  const input = { ...registration(), token_role: "live_activity_update", platform: "ios", target: { instance_id: "instance", app_bundle_id: "dev.djconnect.ios", activity_id: "activity", attributes_type: "ExampleAttributes" } };
  const transport = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 })), call = client({ fetcher: transport, activityProfiles: [profile] }); await call("register", input);
  for (const event of ["activity_update", "activity_end"]) expect((await call("event", { ...terminal(registration()), event, profile_id: profile.id, payload: { state: "playing", observed_at_ms: NOW, expires_at_ms: NOW + 60000 } })).status).toBe(200);
  expect(transport).toHaveBeenCalledTimes(2); for (const [, init] of transport.mock.calls) expect(init?.headers).toMatchObject({ "apns-topic": "dev.djconnect.ios.push-type.liveactivity", "apns-push-type": "liveactivity", "apns-expiration": String((NOW + 60000) / 1000) });
  const ended = JSON.parse(String(transport.mock.calls[1]![1]?.body)); expect(ended.aps).toMatchObject({ event: "end", timestamp: NOW / 1000, "content-state": { state: "playing" }, "dismissal-date": NOW / 1000 - 1 });
 });
 it("expired activity content during provider authorization is durably not sent or retried", async () => {
  await env.DB.prepare("DELETE FROM surface_push_capabilities").run(); await capability("live_activity_update", "ios", 1);
  const input = { ...registration(), token_role: "live_activity_update", platform: "ios", target: { instance_id: "instance", app_bundle_id: "dev.djconnect.ios", activity_id: "activity", attributes_type: "ExampleAttributes" } };
  let clock = NOW;
  const transport = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 }));
  const call = client({ fetcher: transport, activityProfiles: [profile], now: () => clock, authorizeProvider: async () => { clock = NOW + 1000; return "example.provider.jwt"; } });
  await call("register", input);
  const event = { ...terminal(input), event: "activity_update", profile_id: profile.id, payload: { state: "playing", observed_at_ms: NOW, expires_at_ms: NOW + 1000 } };
  expect(await (await call("event", event)).json()).toMatchObject({ success: false, operation_state: "not_sent" });
  expect(await (await client({ fetcher: transport, now: () => clock })("event", event)).json()).toMatchObject({ success: false, replayed: true, operation_state: "not_sent" });
  expect(transport).not.toHaveBeenCalled();
 });
 it("bounds the remaining provider timeout by the original activity deadline after authorization", async () => {
  await env.DB.prepare("DELETE FROM surface_push_capabilities").run(); await capability("live_activity_update", "ios", 1);
  const input = { ...registration(), token_role: "live_activity_update", platform: "ios", target: { instance_id: "instance", app_bundle_id: "dev.djconnect.ios", activity_id: "activity", attributes_type: "ExampleAttributes" } };
  let clock = NOW;
  const timeout = vi.spyOn(AbortSignal, "timeout"), transport = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 }));
  try {
   const call = client({ fetcher: transport, activityProfiles: [profile], now: () => clock, authorizeProvider: async () => { clock = NOW + 750; return "example.provider.jwt"; } });
   await call("register", input);
   expect((await call("event", { ...terminal(input), event: "activity_update", profile_id: profile.id, payload: { state: "playing", observed_at_ms: NOW, expires_at_ms: NOW + 1000 } })).status).toBe(200);
   expect(timeout).toHaveBeenLastCalledWith(250);
   expect(transport.mock.calls[0]![1]?.headers).toMatchObject({ "apns-expiration": String((NOW + 1000) / 1000) });
  } finally { timeout.mockRestore(); }
 });
 it.each(["widget_reload", "activity_update", "activity_end"])("composes real local provider JWT with D1 and %s without an APNs call", async event => {
  const activity = event !== "widget_reload";
  if (activity) { await env.DB.prepare("DELETE FROM surface_push_capabilities").run(); await capability("live_activity_update", "ios", 1); }
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const bytes = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const provider = createSurfaceProvider({ APNS_TEAM_ID: "TEAM123456", APNS_KEY_ID: "KEY1234567", APNS_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\n" + btoa(String.fromCharCode(...bytes)) + "\n-----END PRIVATE KEY-----" }, () => NOW);
  const input = activity ? { ...registration(), token_role: "live_activity_update", platform: "ios", target: { instance_id: "instance", app_bundle_id: "dev.djconnect.ios", activity_id: "activity", attributes_type: "ExampleAttributes" } } : registration();
  const transport = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => {
   const authorization = new Headers(init?.headers).get("authorization")!;
   const [header, claims, signature] = authorization.slice("bearer ".length).split(".") as [string, string, string];
   const binary = Uint8Array.from(atob(signature.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
   expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, binary, new TextEncoder().encode(header + "." + claims))).toBe(true);
   expect(new Headers(init?.headers).get("apns-topic")).toBe(activity ? "dev.djconnect.ios.push-type.liveactivity" : "dev.djconnect.mac.push-type.widgets");
   return new Response(null, { status: 200 });
  });
  const call = client({ fetcher: transport, authorizeProvider: provider.authorizeProvider, activityProfiles: [profile] });
  expect((await call("register", input)).status).toBe(200);
  const body = { ...terminal(input), event, ...(activity ? { profile_id: profile.id, payload: { state: "playing", observed_at_ms: NOW, expires_at_ms: NOW + 60000 } } : {}) };
  expect(await (await call("event", body)).json()).toMatchObject({ success: true, operation_state: "provider_accepted" });
  expect(transport).toHaveBeenCalledTimes(1); provider.close();
 });
 it("does not overwrite ordinary app-token registration during surface register/rotate/revoke", async () => {
  await env.DB.prepare("INSERT INTO registrations(id,ha_install_id,device_id,client_type,apns_token_hash,apns_token,apns_environment,topic) VALUES('ordinary-sentinel','example-install','device','macos','example-hash','example-app-token','sandbox','dev.djconnect.mac')").run();
  const before = await env.DB.prepare("SELECT * FROM registrations WHERE id='ordinary-sentinel'").first();
  const input = registration(), call = client(); await call("register", input); await call("register", { ...input, revision: 2, operation_id: operation(), apns_token: "02".repeat(32) }); await call("revoke", { ...terminal(input), revision: 2 });
  expect(await env.DB.prepare("SELECT * FROM registrations WHERE id='ordinary-sentinel'").first()).toEqual(before);
 });
 it("preserves the original operation's CAS conflict instead of retrying it after state changes", async () => {
  const input = registration(), call = client(); await call("register", input); const skipped = { ...input, revision: 3, operation_id: operation() };
  expect((await call("register", skipped)).status).toBe(409); await call("register", { ...input, revision: 2, operation_id: operation() });
  expect((await call("register", skipped)).status).toBe(409); expect((await row())?.revision).toBe(2);
 });
 it("a new grant generation is separate from an older generation's tombstone", async () => {
  const input = registration(), call = client(); await call("revoke", terminal(input));
  expect((await call("register", { ...input, generation: "fresh-explicit-generation", operation_id: operation() })).status).toBe(200);
  expect(await (await call("register", input)).json()).toMatchObject({ success: false, state: "revoked" });
 });
 it("refuses dispatch if the capability expires or is revoked while preparing authorization", async () => {
  const input = registration(), transport = vi.fn<typeof fetch>(), base = client(); await base("register", input);
  const call = client({ fetcher: transport, authorizeProvider: async () => { await env.DB.prepare("UPDATE surface_push_capabilities SET revoked_at=?").bind(NOW).run(); return "example.provider.jwt"; } });
  expect(await (await call("event", { ...terminal(input), event: "widget_reload" })).json()).toMatchObject({ success: false, operation_state: "not_sent", state: "withdrawn" }); expect(transport).not.toHaveBeenCalled();
 });
 it("does not send an expired registration or extend it on a backwards local clock", async () => {
  let clock = NOW; const input = { ...registration(), expires_at_ms: NOW + 1000 }, transport = vi.fn<typeof fetch>(), call = client({ fetcher: transport, now: () => clock }); await call("register", input);
  clock = NOW + 1000; expect((await call("event", { ...terminal(input), event: "widget_reload" })).status).toBe(409);
  clock = NOW; expect((await call("event", { ...terminal(input), event: "widget_reload" })).status).toBe(409); expect(transport).not.toHaveBeenCalled();
 });
 it("a finite event budget cannot be bypassed by distinct operation IDs", async () => {
  await env.DB.prepare("UPDATE surface_push_capabilities SET max_events=1").run(); const transport = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 })), call = client({ fetcher: transport }), input = registration(); await call("register", input);
  expect((await call("event", { ...terminal(input), event: "widget_reload" })).status).toBe(200); expect((await call("event", { ...terminal(input), event: "widget_reload" })).status).toBe(409); expect(transport).toHaveBeenCalledTimes(1);
 });
 it("a reviewed content decoder still cannot restamp stale or overlong content", async () => {
  await env.DB.prepare("DELETE FROM surface_push_capabilities").run(); await capability("live_activity_update", "ios", 1);
  const input = { ...registration(), token_role: "live_activity_update", platform: "ios", target: { instance_id: "instance", app_bundle_id: "dev.djconnect.ios", activity_id: "activity", attributes_type: "ExampleAttributes" } }, transport = vi.fn<typeof fetch>(), call = client({ fetcher: transport, activityProfiles: [profile] }); await call("register", input);
  for (const expiry of [NOW, NOW + 120001]) expect((await call("event", { ...terminal(registration()), event: "activity_update", profile_id: profile.id, payload: { state: "playing", observed_at_ms: NOW, expires_at_ms: expiry } })).status).toBe(409);
  expect(transport).not.toHaveBeenCalled();
 });

});
