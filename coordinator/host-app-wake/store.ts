import {sha256Hex} from '../../src/crypto';
import {canonical, need, original, type OriginalPurpose, type Input} from './wire';
export interface Row {purpose_id:string;scope_json:string;credential_hash:string;issued_at:number;expires_at:number;max_operations:number;max_wakes:number;host_bundle:string;install_id:string;environment:string;withdrawn:number;generation:string|null;revision:number;ciphertext:string|null;nonce:string|null;claim_id:string}
export interface Operation {purpose_id:string;operation_id:string;request_hash:string;kind:string;claim_id:string;generation:string;revision:number;accepted_at:number;expires_at:number;outcome:string;provider_status:number|null}
export class WakeStore {
 constructor(readonly db:D1Database){}
 async issue(p:OriginalPurpose,hash:string,claim:string,capacity:number,at:number):Promise<boolean>{
  const r=await this.db.prepare(`INSERT OR IGNORE INTO host_app_wake_purposes
   (purpose_id,scope_json,credential_hash,issued_at,expires_at,max_operations,max_wakes,host_bundle,install_id,environment,claim_id)
   SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM host_app_wake_purposes)<? AND ?<=? AND ?<?`)
   .bind(p.purpose_id,canonical(p),hash,p.issued_at_ms,p.expires_at_ms,p.max_operations,p.max_wakes,p.target.host_bundle_id,p.target.installation_id,p.apns_environment,claim,capacity,p.issued_at_ms,at,at,p.expires_at_ms).run();
  return r.meta.changes===1;
 }
 async authenticate(auth:string|null,purpose:string):Promise<Row>{
  need(auth&&/^Bearer djchw_[A-Za-z0-9_-]{43}$/.test(auth),'host_wake_auth',401);
  const row=await this.db.prepare('SELECT * FROM host_app_wake_purposes WHERE purpose_id=? AND credential_hash=?').bind(purpose,await sha256Hex(auth.slice(7))).first<Row>();
  need(row,'host_wake_auth',401);return row;
 }
 async row(purpose:string):Promise<Row>{const r=await this.db.prepare('SELECT * FROM host_app_wake_purposes WHERE purpose_id=?').bind(purpose).first<Row>();need(r,'host_wake_missing',409);return r;}
 scope(r:Row):OriginalPurpose {
  const p=original(JSON.parse(r.scope_json));
  need(p.purpose_id===r.purpose_id&&p.issued_at_ms===r.issued_at&&p.expires_at_ms===r.expires_at&&p.max_operations===r.max_operations&&p.max_wakes===r.max_wakes&&p.target.host_bundle_id===r.host_bundle&&p.target.installation_id===r.install_id&&p.apns_environment===r.environment,'host_wake_configuration',503);
  return p;
 }
 async operation(purpose:string,operation:string):Promise<Operation|null>{return this.db.prepare('SELECT * FROM host_app_wake_operations WHERE purpose_id=? AND operation_id=?').bind(purpose,operation).first<Operation>();}
 /** Called only after authentication and original-currentness verification.
  * A slow first read/auth cannot disappear and acquire a new lease on replay.
  * Retain the original deadline within the existing bounded history, without
  * reserving a send or replacing an already stored smaller boundary. */
 async expireWake(p:OriginalPurpose,i:Input,hash:string,claim:string,capturedAt:number,expiresAt:number,at:number):Promise<void>{
  await this.db.prepare(`INSERT OR IGNORE INTO host_app_wake_operations
   (purpose_id,operation_id,request_hash,kind,claim_id,generation,revision,accepted_at,expires_at,outcome)
   SELECT ?,?,?,'wake',?,?,?,?,?,'expired'
   WHERE EXISTS(SELECT 1 FROM host_app_wake_purposes WHERE purpose_id=? AND withdrawn=0 AND expires_at>?)
   AND (SELECT COUNT(*) FROM host_app_wake_operations WHERE purpose_id=?)<?`)
   .bind(p.purpose_id,i.operation_id,hash,claim,i.generation!,i.revision!,capturedAt,expiresAt,p.purpose_id,at,p.purpose_id,p.max_operations).run();
 }
 async reserve(kind:'register'|'wake',p:OriginalPurpose,i:Input,hash:string,claim:string,at:number,expiresAt:number,sealed?:{ciphertext:string;nonce:string}):Promise<void>{
  // The entire claim/rotation transition is one SQLite transaction. Failed
  // generation/CAS claims consume bounded operation space, never provider calls.
  const claimSql=this.db.prepare(`INSERT OR IGNORE INTO host_app_wake_operations
   (purpose_id,operation_id,request_hash,kind,claim_id,generation,revision,accepted_at,expires_at,outcome)
   SELECT ?,?,?,?,?,?,?,?,?,'conflict' WHERE EXISTS(SELECT 1 FROM host_app_wake_purposes WHERE purpose_id=? AND withdrawn=0 AND expires_at>?)
   AND (SELECT COUNT(*) FROM host_app_wake_operations WHERE purpose_id=?)<?`)
   .bind(p.purpose_id,i.operation_id,hash,kind,claim,i.generation!,i.revision!,at,expiresAt,p.purpose_id,at,p.purpose_id,p.max_operations);
  const owns="EXISTS(SELECT 1 FROM host_app_wake_operations WHERE purpose_id=? AND operation_id=? AND claim_id=?)";
  if(kind==='register'){
   need(sealed);
   await this.db.batch([claimSql,
    this.db.prepare(`UPDATE host_app_wake_purposes SET generation=?,revision=?,ciphertext=?,nonce=?,claim_id=?
     WHERE purpose_id=? AND withdrawn=0 AND expires_at>? AND revision=? AND (revision=0 OR generation=?) AND ${owns}`)
     .bind(i.generation!,i.revision!,sealed.ciphertext,sealed.nonce,claim,p.purpose_id,at,i.revision!-1,i.generation!,p.purpose_id,i.operation_id,claim),
    this.db.prepare(`UPDATE host_app_wake_operations SET outcome='registered' WHERE purpose_id=? AND operation_id=? AND claim_id=?
     AND EXISTS(SELECT 1 FROM host_app_wake_purposes WHERE purpose_id=? AND claim_id=? AND withdrawn=0)`)
     .bind(p.purpose_id,i.operation_id,claim,p.purpose_id,claim)]);
  }else{
   await this.db.batch([claimSql,
    this.db.prepare(`UPDATE host_app_wake_operations SET outcome='reserved' WHERE purpose_id=? AND operation_id=? AND claim_id=?
     AND EXISTS(SELECT 1 FROM host_app_wake_purposes WHERE purpose_id=? AND withdrawn=0 AND expires_at>? AND generation=? AND revision=? AND ciphertext IS NOT NULL)
     AND (SELECT COUNT(*) FROM host_app_wake_operations WHERE purpose_id=? AND kind='wake' AND outcome IN('reserved','dispatch_started','provider_accepted','provider_rejected','unknown','not_sent'))<?
     AND (SELECT COUNT(*) FROM host_app_wake_operations o JOIN host_app_wake_purposes p ON p.purpose_id=o.purpose_id
      WHERE o.kind='wake' AND o.outcome IN('reserved','dispatch_started','provider_accepted','provider_rejected','unknown','not_sent') AND o.accepted_at>? AND p.host_bundle=? AND p.install_id=? AND p.environment=?)=0`)
     .bind(p.purpose_id,i.operation_id,claim,p.purpose_id,at,i.generation!,i.revision!,p.purpose_id,p.max_wakes,at-30000,p.target.host_bundle_id,p.target.installation_id,p.apns_environment),
    this.db.prepare(`UPDATE host_app_wake_operations SET outcome='coalesced' WHERE purpose_id=? AND operation_id=? AND claim_id=? AND outcome='conflict'
     AND EXISTS(SELECT 1 FROM host_app_wake_operations o JOIN host_app_wake_purposes p ON p.purpose_id=o.purpose_id
      WHERE o.kind='wake' AND o.outcome IN('reserved','dispatch_started','provider_accepted','provider_rejected','unknown','not_sent') AND o.accepted_at>? AND p.host_bundle=? AND p.install_id=? AND p.environment=?)`)
     .bind(p.purpose_id,i.operation_id,claim,at-30000,p.target.host_bundle_id,p.target.installation_id,p.apns_environment)]);
  }
 }
 async mark(p:OriginalPurpose,i:Input,claim:string,at:number):Promise<boolean>{
  const r=await this.db.prepare(`UPDATE host_app_wake_operations SET outcome='dispatch_started'
   WHERE purpose_id=? AND operation_id=? AND claim_id=? AND outcome='reserved' AND expires_at>?
   AND EXISTS(SELECT 1 FROM host_app_wake_purposes WHERE purpose_id=? AND withdrawn=0 AND expires_at>? AND generation=? AND revision=? AND ciphertext IS NOT NULL)`)
   .bind(p.purpose_id,i.operation_id,claim,at,p.purpose_id,at,i.generation!,i.revision!).run();return r.meta.changes===1;
 }
 async finish(purpose:string,operation:string,claim:string,outcome:string,status:number|null):Promise<void>{
  await this.db.prepare("UPDATE host_app_wake_operations SET outcome=?,provider_status=? WHERE purpose_id=? AND operation_id=? AND claim_id=? AND outcome IN('reserved','dispatch_started')").bind(outcome,status,purpose,operation,claim).run();
 }
 /** Purpose-wide terminal withdrawal has a preallocated row and no operation
  * insertion, provider key, encryption key or remaining budget prerequisite. */
 async withdraw(purpose:string):Promise<void>{await this.db.prepare('UPDATE host_app_wake_purposes SET withdrawn=1,ciphertext=NULL,nonce=NULL WHERE purpose_id=?').bind(purpose).run();}
 async invalidate(purpose:string,generation:string,revision:number):Promise<void>{await this.db.prepare('UPDATE host_app_wake_purposes SET ciphertext=NULL,nonce=NULL WHERE purpose_id=? AND generation=? AND revision=?').bind(purpose,generation,revision).run();}
}
