import { sha256Hex } from "../crypto";
import { canonical, need, type Coordinate, type Input, type OperationKind, type RegisterInput, type Role } from "./wire";
export interface Principal {
 id: string; token_hash: string; install_id: string; device_binding: string; owner_binding: string;
 parent_bundle: string; extension_bundle: string; widget_kind: string; attributes_type: string;
 platform: string; environment: "sandbox" | "production"; role: Role;
 activity_profile: string; external_content_allowed: number;
 expires_at: number; revoked_at: number | null; max_operations: number; max_events: number;
}
export interface TargetRow {
 id: string; capability_id: string; registration_id: string; generation: string; revision: number;
 binding_id: string; device_binding: string; owner_binding: string; expires_at: number;
 target_json: string | null; state: "active" | "revoked"; ciphertext: string | null; nonce: string | null; last_claim: string;
}
export interface OperationRow {
 capability_id: string; operation_id: string; request_hash: string; kind: string; target_id: string; claim_id: string;
 outcome: string; accepted_at: number; registration_id: string; generation: string; revision: number; expires_at: number; provider_status: number | null;
}
export class SurfaceStore {
 constructor(readonly db: D1Database) {}
 async authenticate(authorization: string | null, now: number): Promise<Principal> {
  need(authorization && /^Bearer djcs_[A-Za-z0-9_-]{43}$/.test(authorization), "surface_auth_required", 401);
  const principal = await this.db.prepare("SELECT * FROM surface_push_capabilities WHERE token_hash=? AND revoked_at IS NULL AND expires_at>?").bind(await sha256Hex(authorization.slice(7)), now).first<Principal>();
  need(principal, "surface_auth_required", 401);
  need(Number.isSafeInteger(principal.expires_at) && /^[a-f0-9]{64}$/.test(principal.device_binding) && /^[a-f0-9]{64}$/.test(principal.owner_binding), "surface_configuration_invalid", 503);
  need(/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(principal.parent_bundle) && ["sandbox", "production"].includes(principal.environment), "surface_configuration_invalid", 503);
  need(["ios", "ipados", "maccatalyst", "macos", "watchos", "visionos"].includes(principal.platform), "surface_configuration_invalid", 503);
  need(["widget", "live_activity_update", "live_activity_start"].includes(principal.role), "surface_configuration_invalid", 503);
  need(principal.role === "widget" || ["ios", "ipados"].includes(principal.platform), "surface_configuration_invalid", 503);
  need(principal.role !== "widget" || (principal.extension_bundle.startsWith(principal.parent_bundle + ".") && /^[A-Za-z0-9_-]{1,128}$/.test(principal.widget_kind)), "surface_configuration_invalid", 503);
  return principal;
 }
 async identity(p: Principal, input: Coordinate): Promise<string> {
  need(input.device_binding === p.device_binding && input.owner_binding === p.owner_binding, "surface_scope_mismatch", 403);
  return sha256Hex(canonical(["surface-target/1", p.id, input.registration_id, input.generation, input.binding_id, input.device_binding, input.owner_binding]));
 }
 async target(id: string): Promise<TargetRow | null> { return this.db.prepare("SELECT * FROM surface_push_targets WHERE id=?").bind(id).first<TargetRow>(); }
 async operation(p: Principal, id: string): Promise<OperationRow | null> { return this.db.prepare("SELECT * FROM surface_push_operations WHERE capability_id=? AND operation_id=?").bind(p.id, id).first<OperationRow>(); }
 private claim(p: Principal, input: Coordinate, kind: Exclude<OperationKind, "status">, id: string, hash: string, claim: string, now: number, expiry: number): D1PreparedStatement {
  return this.db.prepare(`INSERT OR IGNORE INTO surface_push_operations
   (capability_id,operation_id,request_hash,kind,target_id,claim_id,outcome,accepted_at,registration_id,generation,revision,expires_at)
   SELECT ?,?,?,?,?,?,'pending',?,?,?,?,? WHERE
   EXISTS(SELECT 1 FROM surface_push_capabilities WHERE id=? AND revoked_at IS NULL AND expires_at>?) AND
   (SELECT COUNT(*) FROM surface_push_operations WHERE capability_id=? AND ((?='revoke' AND kind='revoke') OR (?!='revoke' AND kind!='revoke')))<?`)
   .bind(p.id, input.operation_id, hash, kind, id, claim, now, input.registration_id, input.generation, input.revision, expiry, p.id, now, p.id, kind, kind, p.max_operations);
 }
 private owns(p: Principal, input: Coordinate, claim: string): unknown[] { return [p.id, input.operation_id, claim]; }
 private readonly owned = "EXISTS(SELECT 1 FROM surface_push_operations WHERE capability_id=? AND operation_id=? AND claim_id=? AND outcome='pending')";
 async register(p: Principal, input: RegisterInput, id: string, hash: string, claim: string, now: number, sealed: { ciphertext: string; nonce: string }): Promise<void> {
  const target = canonical(input.target), owned = this.owns(p, input, claim);
  await this.db.batch([
   this.claim(p, input, "register", id, hash, claim, now, input.expires_at_ms),
   this.db.prepare(`INSERT OR IGNORE INTO surface_push_targets
    (id,capability_id,registration_id,generation,revision,binding_id,device_binding,owner_binding,expires_at,target_json,state,ciphertext,nonce,last_claim)
    SELECT ?,?,?,?,?,?,?,?,?,?,'active',?,?,? WHERE ?=1 AND ${this.owned}`)
    .bind(id, p.id, input.registration_id, input.generation, input.revision, input.binding_id, input.device_binding, input.owner_binding, input.expires_at_ms, target, sealed.ciphertext, sealed.nonce, claim, input.revision, ...owned),
   this.db.prepare(`UPDATE surface_push_targets SET revision=?,ciphertext=?,nonce=?,last_claim=?
    WHERE id=? AND state='active' AND revision=? AND expires_at=? AND target_json=? AND ${this.owned}`)
    .bind(input.revision, sealed.ciphertext, sealed.nonce, claim, id, input.revision - 1, input.expires_at_ms, target, ...owned),
   this.db.prepare(`UPDATE surface_push_operations SET outcome=CASE
    WHEN EXISTS(SELECT 1 FROM surface_push_targets WHERE id=? AND last_claim=? AND state='active') THEN 'registered'
    WHEN EXISTS(SELECT 1 FROM surface_push_targets WHERE id=? AND state='revoked') THEN 'revoked' ELSE 'conflict' END
    WHERE capability_id=? AND operation_id=? AND claim_id=?`).bind(id, claim, id, ...owned),
  ]);
 }
 async revoke(p: Principal, input: Coordinate, id: string, hash: string, claim: string, now: number): Promise<void> {
  const owned = this.owns(p, input, claim);
  await this.db.batch([
   this.claim(p, input, "revoke", id, hash, claim, now, 0),
   this.db.prepare(`INSERT OR IGNORE INTO surface_push_targets
    (id,capability_id,registration_id,generation,revision,binding_id,device_binding,owner_binding,expires_at,target_json,state,ciphertext,nonce,last_claim)
    SELECT ?,?,?,?,?,?,?,?,0,NULL,'revoked',NULL,NULL,? WHERE ${this.owned}`)
    .bind(id, p.id, input.registration_id, input.generation, input.revision, input.binding_id, input.device_binding, input.owner_binding, claim, ...owned),
   this.db.prepare(`UPDATE surface_push_targets SET state='revoked',ciphertext=NULL,nonce=NULL,last_claim=?
    WHERE id=? AND revision=? AND ${this.owned}`).bind(claim, id, input.revision, ...owned),
   this.db.prepare(`UPDATE surface_push_operations SET outcome=CASE
    WHEN EXISTS(SELECT 1 FROM surface_push_targets WHERE id=? AND revision=? AND state='revoked') THEN 'revoked' ELSE 'conflict' END
    WHERE capability_id=? AND operation_id=? AND claim_id=?`).bind(id, input.revision, ...owned),
  ]);
 }
 async reserveEvent(p: Principal, input: Coordinate, id: string, hash: string, claim: string, now: number): Promise<void> {
  await this.db.batch([
   this.claim(p, input, "event", id, hash, claim, now, 0),
   this.db.prepare(`UPDATE surface_push_operations SET outcome='event_reserved',expires_at=(SELECT expires_at FROM surface_push_targets WHERE id=?)
    WHERE capability_id=? AND operation_id=? AND claim_id=? AND outcome='pending' AND
    EXISTS(SELECT 1 FROM surface_push_targets WHERE id=? AND state='active' AND revision=? AND expires_at>?) AND
    (SELECT COUNT(*) FROM surface_push_operations WHERE capability_id=? AND kind='event' AND outcome IN('event_reserved','dispatch_started','provider_accepted','provider_rejected','outcome_unknown'))<?`)
    .bind(id, p.id, input.operation_id, claim, id, input.revision, now, p.id, p.max_events),
   this.db.prepare("UPDATE surface_push_operations SET outcome='conflict' WHERE capability_id=? AND operation_id=? AND claim_id=? AND outcome='pending'").bind(p.id, input.operation_id, claim),
  ]);
 }
 async dispatch(p: Principal, input: Coordinate, id: string, claim: string, now: number): Promise<boolean> {
  const result = await this.db.prepare(`UPDATE surface_push_operations SET outcome='dispatch_started'
   WHERE capability_id=? AND operation_id=? AND claim_id=? AND outcome='event_reserved' AND
   EXISTS(SELECT 1 FROM surface_push_targets WHERE id=? AND revision=? AND state='active' AND expires_at>?) AND
   EXISTS(SELECT 1 FROM surface_push_capabilities WHERE id=? AND revoked_at IS NULL AND expires_at>?)`)
   .bind(p.id, input.operation_id, claim, id, input.revision, now, p.id, now).run();
  return result.meta.changes === 1;
 }
 async finish(p: Principal, input: Coordinate, claim: string, outcome: string, status: number | null = null): Promise<void> {
  await this.db.prepare("UPDATE surface_push_operations SET outcome=?,provider_status=? WHERE capability_id=? AND operation_id=? AND claim_id=? AND outcome IN('event_reserved','dispatch_started')").bind(outcome, status, p.id, input.operation_id, claim).run();
 }
 async invalidateSentGeneration(id: string, revision: number): Promise<void> {
  await this.db.prepare("UPDATE surface_push_targets SET state='revoked',ciphertext=NULL,nonce=NULL WHERE id=? AND revision=?").bind(id, revision).run();
 }
}
