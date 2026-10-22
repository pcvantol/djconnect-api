/** Internal source candidate. No import, route, capability mint or provider adapter at the public root. */
import { sha256Hex } from "../crypto";
import { seal, unseal } from "./crypto";
import { SurfaceStore, type Principal, type TargetRow, type OperationRow } from "./store";
import { payload, request as apnsRequest, type ActivityProfile } from "./apns";
import { canonical, need, readInput, SurfaceError, type Coordinate, type RegisterInput, type EventInput, type OperationKind } from "./wire";
export interface SurfaceOptions {
 db: D1Database;
 encryptionKey: string;
 /** Server-owned adapter; absent by default. No provider credential is read or provisioned here. */
 authorizeProvider?: () => Promise<string>;
 fetcher?: typeof fetch;
 activityProfiles?: readonly ActivityProfile[];
 now?: () => number;
}
const routes = new Map<string, OperationKind>(["register", "revoke", "event", "status"].map(kind => ["/v1/push/surface/" + kind, kind as OperationKind]));
function json(body: unknown, status = 200): Response {
 return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" } });
}
function aad(p: Principal, row: Pick<TargetRow, "id" | "generation" | "revision" | "expires_at" | "target_json">): string {
 return canonical(["surface-token/1", p.id, row.id, row.generation, row.revision, row.expires_at, row.target_json, p.parent_bundle, p.role, p.environment]);
}
function validateRegistration(p: Principal, input: RegisterInput, now: number): void {
 need(input.token_role === p.role && input.platform === p.platform && input.apns_environment === p.environment && input.target.app_bundle_id === p.parent_bundle, "surface_scope_mismatch", 403);
 need(input.expires_at_ms <= p.expires_at && input.expires_at_ms > now, "surface_scope_mismatch", 403);
 if (p.role === "widget") need(input.target.extension_bundle_id === p.extension_bundle && input.target.widget_kind === p.widget_kind, "surface_scope_mismatch", 403);
 else need(input.target.attributes_type === p.attributes_type, "surface_scope_mismatch", 403);
}
async function invalidToken(response: Response): Promise<boolean> {
 if (response.status === 410) return true;
 if (response.status !== 400) return false;
 const reader = response.body?.getReader(); if (!reader) return false; const decoder = new TextDecoder(); let text = "", size = 0;
 try { while (true) { const next = await reader.read(); if (next.done) break; size += next.value.byteLength; if (size > 1024) { await reader.cancel(); return false; } text += decoder.decode(next.value, { stream: true }); } text += decoder.decode(); const value: unknown = JSON.parse(text); return !!value && typeof value === "object" && "reason" in value && ["BadDeviceToken", "Unregistered"].includes(String(value.reason)); }
 catch { return false; }
}
export function createSurfacePushHandler(options: SurfaceOptions): (request: Request) => Promise<Response> {
 const store = new SurfaceStore(options.db); let highWater = 0;
 const now = () => { const value = (options.now ?? Date.now)(); need(Number.isSafeInteger(value) && value >= 0, "surface_clock_unqualified", 503); return highWater = Math.max(highWater, value); };
 async function receipt(p: Principal, input: Coordinate, id: string, op: OperationRow | null, replayed: boolean, readOnly = false): Promise<Response> {
  const row = await store.target(id), clock = now();
  const liveCapability = await options.db.prepare("SELECT 1 AS live FROM surface_push_capabilities WHERE id=? AND revoked_at IS NULL AND expires_at>?").bind(p.id, clock).first();
  const current = !row ? "unknown" : row.state === "revoked" ? "revoked" : row.expires_at <= clock ? "expired" : !liveCapability ? "withdrawn" : "registered";
  const outcome = op?.outcome ?? "unknown";
  const exactOperation = op?.target_id === id && op.registration_id === input.registration_id && op.generation === input.generation && op.revision === input.revision;
  const exact = exactOperation && row?.revision === input.revision && row.generation === input.generation;
  const success = (outcome === "registered" && current === "registered" && exact) || (op?.kind === "revoke" && outcome === "revoked" && current === "revoked" && exact) || (outcome === "provider_accepted" && current === "registered" && exact);
  const ambiguous = ["pending", "event_reserved", "dispatch_started", "outcome_unknown", "unknown"].includes(outcome);
  return json({ contract_version: 1, success, registration_id: input.registration_id, generation: input.generation, revision: input.revision,
   operation_id: input.operation_id, state: current, operation_state: ambiguous ? "unknown" : outcome, replayed,
   expires_at_ms: op?.kind === "register" ? op.expires_at : row?.expires_at ?? 0,
   current_revision: row?.revision ?? null, provider_status: op?.provider_status ?? null },
   readOnly || success ? 200 : ambiguous ? 202 : outcome === "provider_rejected" ? 502 : 409);
 }
 return async (request: Request): Promise<Response> => {
  try {
   const url = new URL(request.url), kind = routes.get(url.pathname);
   need(request.method === "POST" && kind && !url.search && !url.hash, "surface_route_not_found", 404);
   need(!request.headers.has("origin") && !request.headers.has("cookie"), "surface_server_transport_required", 403);
   const clock = now(), p = await store.authenticate(request.headers.get("authorization"), clock);
   const input = await readInput(request, kind, clock), id = await store.identity(p, input);
   const existing = await store.operation(p, input.operation_id);
   if (kind === "status") { need(!existing || (existing.target_id === id && existing.registration_id === input.registration_id && existing.generation === input.generation && existing.revision === input.revision), "surface_operation_conflict", 409); return receipt(p, input, id, existing, true, true); }
   const hash = await sha256Hex(canonical([kind, input]));
   if (existing) { need(existing.request_hash === hash && existing.target_id === id && existing.kind === kind, "surface_operation_conflict", 409); return receipt(p, input, id, existing, true); }
   const claim = crypto.randomUUID();
   if (kind === "register") {
    const registration = input as RegisterInput; validateRegistration(p, registration, clock);
    const sealed = await seal(registration.apns_token, options.encryptionKey, aad(p, { id, generation: input.generation, revision: input.revision, expires_at: registration.expires_at_ms, target_json: canonical(registration.target) }));
    validateRegistration(p, registration, now());
    await store.register(p, registration, id, hash, claim, now(), sealed);
   } else if (kind === "revoke") await store.revoke(p, input, id, hash, claim, now());
   else {
    const event = input as EventInput, row = await store.target(id);
    need(row && row.state === "active" && row.revision === input.revision && row.expires_at > clock, "surface_registration_not_current", 409);
    const body = payload(p, row, event, clock, options.activityProfiles);
    need(options.authorizeProvider, "surface_provider_not_admitted", 503);
    await store.reserveEvent(p, input, id, hash, claim, clock);
    const reserved = await store.operation(p, input.operation_id);
    need(reserved, "surface_capacity_exhausted", 429);
    if (reserved.claim_id === claim && reserved.outcome === "event_reserved") {
     let token: string, authorization: string;
     try {
      need(row.ciphertext && row.nonce, "surface_token_unavailable", 503);
      token = await unseal(row.ciphertext, row.nonce, options.encryptionKey, aad(p, row));
      authorization = await options.authorizeProvider();
      need(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization), "surface_provider_not_admitted", 503);
     } catch { await store.finish(p, input, claim, "not_sent"); return receipt(p, input, id, await store.operation(p, input.operation_id), false); }
     if (now() < body.expiresAt && await store.dispatch(p, input, id, claim, now())) {
      try {
       // Durable dispatch marker precedes the one outbound attempt. No automatic retry.
       const built = apnsRequest(p, row, token, body, authorization, now());
       const response = await (options.fetcher ?? fetch)(built.url, built.init);
       if (await invalidToken(response)) await store.invalidateSentGeneration(id, input.revision);
       await store.finish(p, input, claim, response.status === 200 ? "provider_accepted" : "provider_rejected", response.status);
      } catch { await store.finish(p, input, claim, "outcome_unknown"); }
     } else await store.finish(p, input, claim, "not_sent");
    }
   }
   const op = await store.operation(p, input.operation_id); need(op, "surface_capacity_exhausted", 429);
   need(op.request_hash === hash && op.target_id === id, "surface_operation_conflict", 409);
   return receipt(p, input, id, op, false);
  } catch (error) {
   if (error instanceof SurfaceError) return json({ contract_version: 1, success: false, error: error.code }, error.status);
   return json({ contract_version: 1, success: false, error: "surface_internal_error" }, 503);
  }
 };
}
