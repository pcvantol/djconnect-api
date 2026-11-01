import type {NativeProofKind} from './server-wire';
import {canonical} from '../../src/surface-push/wire';
import {need,integer} from '../host-app-wake/wire';
import {decodeOperatorAuthorization,decodeNativeOriginal,decodeNativeChallenge,type OperatorAuthorizationData,type NativeOriginalData,type NativeChallengeData} from './wire';
export interface AuthorizationRow {authorization_id:string;operation_id:string;request_hash:string;core_install_token_record_id:string;ha_install_id:string;authorization_json:string;issued_at:number;expires_at:number;outcome:'authorized'|'expired'|'withdrawn';accepted_at:number;original_request_expires_at:number}
export interface IssuerRow {authorization_id:string;core_purpose_id:string;issuer_operation_id:string;native_proof_kind:NativeProofKind;claim_id:string;request_hash:string;original_json:string;private_purpose_id:string;issued_at:number;expires_at:number;accepted_at:number;original_request_expires_at:number;outcome:'reserved'|'issued'|'expired'|'unknown'|'withdrawn'}
export interface NativeJobRow {challenge_id:string;private_job_id:string;authorization_id:string;core_purpose_id:string;operation_id:string;generation:string;revision:number;request_hash:string;original_json:string;challenge_json:string;proof_kind:NativeProofKind;verification_claim:string|null;captured_at:number;expires_at:number;outcome:'reserved'|'verifying'|'verified'|'rejected'|'expired'|'unknown'|'withdrawn'}
export interface IntentRow {authorization_id:string;core_purpose_id:string;issuer_operation_id:string;route:string;claim_id:string;request_hash:string|null;captured_at:number;expires_at:number;outcome:'reserved'|'completed'|'expired'|'unknown'|'withdrawn'}
const LIVE=`SELECT 1 FROM host_wake_operator_authorizations a JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id WHERE a.authorization_id=? AND a.outcome='authorized' AND a.issued_at<=? AND a.expires_at>? AND i.disabled=0`;
/** Actual D1 once-history. No status read returns a credential or issues a grant.
 * SQL checks actual local install-token state, not remote Core RAM state. */
export class ReceivingStore {
 constructor(readonly db:D1Database,readonly capacity:number){integer(capacity,1,10000);}
 async authorization(id:string){return this.db.prepare('SELECT * FROM host_wake_operator_authorizations WHERE authorization_id=?').bind(id).first<AuthorizationRow>();}
 async issuer(id:string,corePurpose:string){return this.db.prepare('SELECT * FROM host_wake_issuer_once WHERE authorization_id=? AND core_purpose_id=?').bind(id,corePurpose).first<IssuerRow>();}
 async nativeJob(challenge:string){return this.db.prepare('SELECT * FROM host_wake_native_jobs WHERE challenge_id=?').bind(challenge).first<NativeJobRow>();}
 async intent(id:string,purpose:string,operation:string,route:string){return this.db.prepare('SELECT * FROM host_wake_receiving_intents WHERE authorization_id=? AND core_purpose_id=? AND issuer_operation_id=? AND route=?').bind(id,purpose,operation,route).first<IntentRow>();}
 /** Only actual authenticated private header scope may allocate this prebody
  * latch. No unauthenticated body identity or guessed RAM child is trusted. */
 async reserveIntent(id:string,principal:string,purpose:string,operation:string,route:string,claim:string,captured:number,at:number){
  integer(captured);integer(at,captured);
  await this.db.prepare(`INSERT OR IGNORE INTO host_wake_receiving_intents
   (authorization_id,core_purpose_id,issuer_operation_id,route,claim_id,captured_at,expires_at,outcome)
   SELECT ?,?,?,?,?,?,MIN(?,a.expires_at),CASE WHEN ?>=? OR CAST(unixepoch('subsec')*1000 AS INTEGER)>=MIN(?,a.expires_at) THEN 'expired' ELSE 'reserved' END
   FROM host_wake_operator_authorizations a JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
   WHERE a.authorization_id=? AND a.outcome='authorized' AND i.id=? AND i.disabled=0 AND a.issued_at<=? AND a.expires_at>?
   AND NOT EXISTS(SELECT 1 FROM host_wake_child_withdrawals WHERE authorization_id=a.authorization_id AND core_purpose_id=?)
   AND (SELECT COUNT(*) FROM host_wake_receiving_intents WHERE authorization_id=?)<json_extract(a.authorization_json,'$.max_operations')
   AND (SELECT COUNT(*) FROM host_wake_receiving_intents)<?`)
   .bind(id,purpose,operation,route,claim,captured,captured+30000,at,captured+30000,captured+30000,id,principal,at,at,purpose,id,this.capacity).run();
  const row=await this.intent(id,purpose,operation,route);need(row,'host_wake_intent_capacity_or_authority',409);return row;
 }
 async bindIntent(row:IntentRow,hash:string,at:number):Promise<boolean>{
  const r=await this.db.prepare(`UPDATE host_wake_receiving_intents SET request_hash=?
   WHERE authorization_id=? AND core_purpose_id=? AND issuer_operation_id=? AND route=? AND claim_id=?
   AND outcome='reserved' AND request_hash IS NULL AND expires_at>? AND expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
   AND EXISTS(${LIVE})`).bind(hash,row.authorization_id,row.core_purpose_id,row.issuer_operation_id,row.route,row.claim_id,at,row.authorization_id,at,at).run();return r.meta.changes===1;
 }
 async finishIntent(row:IntentRow,outcome:'completed'|'unknown'|'expired'){
  need(outcome==='completed'||outcome==='unknown'||outcome==='expired');
  await this.db.prepare(`UPDATE host_wake_receiving_intents SET outcome=CASE WHEN expires_at<=CAST(unixepoch('subsec')*1000 AS INTEGER) THEN 'expired' ELSE ? END
   WHERE authorization_id=? AND core_purpose_id=? AND issuer_operation_id=? AND route=? AND claim_id=? AND outcome='reserved'`)
   .bind(outcome,row.authorization_id,row.core_purpose_id,row.issuer_operation_id,row.route,row.claim_id).run();
 }
 /** Call only AFTER authenticating the actual selected custodian HMAC. The
  * original captured deadline remains in the row even after late auth. */
 async authorize(value:OperatorAuthorizationData,requestHash:string,captured:number,at:number){
  const v=decodeOperatorAuthorization(value);integer(captured);integer(at,captured);integer(captured+30000);
  // No unrelated token/HA pair can receive a grant, even under concurrency.
  await this.db.prepare(`INSERT OR IGNORE INTO host_wake_operator_authorizations
   (authorization_id,operation_id,request_hash,core_install_token_record_id,ha_install_id,authorization_json,issued_at,expires_at,outcome,accepted_at,original_request_expires_at)
   SELECT ?,?,?,?,?,?,?,?,CASE WHEN ?>=? OR ?>=? THEN 'expired' ELSE 'authorized' END,?,?
   WHERE EXISTS(SELECT 1 FROM install_tokens WHERE id=? AND ha_install_id=? AND disabled=0)
   AND (SELECT COUNT(*) FROM host_wake_operator_authorizations)<?`)
   .bind(v.authorization_id,v.operation_id,requestHash,v.core_install_token_record_id,v.ha_install_id,canonical(v),v.original_authorization_issued_at_ms,v.original_authorization_expires_at_ms,at,captured+30000,at,v.original_authorization_expires_at_ms,captured,captured+30000,v.core_install_token_record_id,v.ha_install_id,this.capacity).run();
  const row=await this.authorization(v.authorization_id);need(row&&row.request_hash===requestHash&&row.operation_id===v.operation_id,'host_wake_authorization_consumed_or_capacity',409);return row;
 }
 /** Preallocated terminal update; works at full capacity without encryption,
  * provider credentials or an additional operation/budget allocation. */
 async withdrawAuthorization(id:string){
  await this.db.batch([
   this.db.prepare("UPDATE host_wake_operator_authorizations SET outcome='withdrawn' WHERE authorization_id=?").bind(id),
   this.db.prepare("UPDATE host_wake_issuer_once SET outcome='withdrawn' WHERE authorization_id=?").bind(id),
   this.db.prepare("UPDATE host_wake_native_jobs SET outcome='withdrawn' WHERE authorization_id=?").bind(id),
   this.db.prepare("UPDATE host_wake_receiving_intents SET outcome='withdrawn' WHERE authorization_id=?").bind(id),
   this.db.prepare(`UPDATE host_app_wake_purposes SET withdrawn=1,ciphertext=NULL,nonce=NULL WHERE purpose_id IN (SELECT private_purpose_id FROM host_wake_issuer_once WHERE authorization_id=?)`).bind(id)
  ]);
 }
 /** Scoped negative closure: one original Core push child only, never its
  * display parent or another surface/child under the same operator grant. */
 async withdrawIssuer(id:string,purpose:string,principal:string){
  const owns=`EXISTS(SELECT 1 FROM host_wake_operator_authorizations a WHERE a.authorization_id=? AND a.core_install_token_record_id=?)`;
  await this.db.batch([
   this.db.prepare(`INSERT OR IGNORE INTO host_wake_child_withdrawals(authorization_id,core_purpose_id)
    SELECT ?,? WHERE ${owns} AND (SELECT COUNT(*) FROM host_wake_child_withdrawals)<?`)
    .bind(id,purpose,id,principal,this.capacity),
   this.db.prepare(`UPDATE host_wake_issuer_once SET outcome='withdrawn' WHERE authorization_id=? AND core_purpose_id=? AND ${owns}`).bind(id,purpose,id,principal),
   this.db.prepare(`UPDATE host_wake_native_jobs SET outcome='withdrawn' WHERE authorization_id=? AND core_purpose_id=? AND ${owns}`).bind(id,purpose,id,principal),
   this.db.prepare(`UPDATE host_wake_receiving_intents SET outcome='withdrawn' WHERE authorization_id=? AND core_purpose_id=? AND ${owns}`).bind(id,purpose,id,principal),
   this.db.prepare(`UPDATE host_app_wake_purposes SET withdrawn=1,ciphertext=NULL,nonce=NULL WHERE purpose_id IN(SELECT private_purpose_id FROM host_wake_issuer_once WHERE authorization_id=? AND core_purpose_id=?) AND ${owns}`).bind(id,purpose,id,principal)
  ]);
  // Existing issuer rows close without allocating a fence; a new unknown child
  // at full fence capacity never receives a false terminal acknowledgement.
  const [issuer,fence]=await Promise.all([this.issuer(id,purpose),this.db.prepare('SELECT 1 FROM host_wake_child_withdrawals WHERE authorization_id=? AND core_purpose_id=?').bind(id,purpose).first()]);
  return issuer?.outcome==='withdrawn'||!!fence;
 }
 async isLive(id:string,principal:string,at:number){integer(at);return !!await this.db.prepare(LIVE+' AND i.id=?').bind(id,at,at,principal).first();}
 /** The original semantic purpose identity, not a transport operation UUID,
  * is the primary once-key. A new HTTP retry cannot replace its deadline. */
 async reserveIssuer(id:string,principal:string,operation:string,requestHash:string,original:NativeOriginalData,privatePurpose:string,claim:string,captured:number,at:number,expectedKind:NativeProofKind){
  need(expectedKind==='app_attest_attestation'||expectedKind==='app_attest_assertion');const v=decodeNativeOriginal(original);integer(captured);integer(at,captured);
  // The original API observation is the ceiling. A later callback cannot
  // legalize future issuance or renew the retained Core tuple/deadlines.
  need(v.original_wake_issued_at_ms<=captured,'host_wake_original_scope',403);const auth=await this.authorization(id);need(auth,'host_wake_authorization_missing',403);const a=decodeOperatorAuthorization(JSON.parse(auth.authorization_json));
  for(const k of ['owner_binding','device_binding','source_binding','paired_subject_binding_sha256','selected_ha_origin_sha256','identity_policy_sha256','deployment_policy_sha256','platform','apns_environment'] as const)need(v[k]===a[k],'host_wake_authorization_scope',403);
  need(canonical(v.target)===canonical(a.target),'host_wake_authorization_scope',403);
  need(v.original_wake_issued_at_ms>=a.original_authorization_issued_at_ms&&v.original_wake_expires_at_ms<=a.original_authorization_expires_at_ms&&v.original_wake_expires_at_ms-v.original_wake_issued_at_ms<=a.max_original_purpose_ms,'host_wake_authorization_window',403);
  // Bind to exactly the selected existing record; rotation has no inferred lineage.
  need(principal===a.core_install_token_record_id,'host_wake_principal',403);
  await this.db.prepare(`INSERT OR IGNORE INTO host_wake_issuer_once
   (authorization_id,core_purpose_id,issuer_operation_id,native_proof_kind,claim_id,request_hash,original_json,private_purpose_id,issued_at,expires_at,accepted_at,original_request_expires_at,outcome)
   SELECT ?,?,?,?,?,?,?,?,?,?,?,?,CASE WHEN ?>=? OR ?>=? THEN 'expired' ELSE 'reserved' END
   WHERE EXISTS(${LIVE} AND i.id=?) AND NOT EXISTS(SELECT 1 FROM host_wake_child_withdrawals WHERE authorization_id=? AND core_purpose_id=?) AND (SELECT COUNT(*) FROM host_wake_issuer_once)<?`)
   .bind(id,v.core_purpose_id,operation,expectedKind,claim,requestHash,canonical(v),privatePurpose,v.original_wake_issued_at_ms,v.original_wake_expires_at_ms,captured,captured+30000,at,captured+30000,at,v.original_wake_expires_at_ms,id,at,at,principal,id,v.core_purpose_id,this.capacity).run();
  const row=await this.issuer(id,v.core_purpose_id);need(row&&row.request_hash===requestHash&&row.issuer_operation_id===operation&&row.native_proof_kind===expectedKind,'host_wake_issuer_consumed_or_capacity',409);return row;
 }
 /** Caller receives an existing challenge, never a new nonce on duplicate,
  * lost-reply, UNKNOWN, rejected or expired semantic register attempts. */
 async reserveNativeJob(id:string,principal:string,original:NativeOriginalData,challenge:NativeChallengeData,requestHash:string,expectedKind:NativeProofKind,at:number){
  const v=decodeNativeOriginal(original),c=decodeNativeChallenge(challenge,v);integer(at,c.captured_at_ms);need(expectedKind==='app_attest_attestation'||expectedKind==='app_attest_assertion');
  await this.db.prepare(`INSERT OR IGNORE INTO host_wake_native_jobs
   (challenge_id,private_job_id,authorization_id,core_purpose_id,operation_id,generation,revision,request_hash,original_json,challenge_json,proof_kind,captured_at,expires_at,outcome)
   SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,CASE WHEN ?>=? THEN 'expired' ELSE 'reserved' END
   WHERE EXISTS(${LIVE} AND i.id=?)
   AND EXISTS(SELECT 1 FROM host_wake_issuer_once WHERE authorization_id=? AND core_purpose_id=? AND outcome='issued' AND original_json=? AND expires_at>? AND native_proof_kind=?)
   AND (SELECT COUNT(*) FROM host_wake_native_jobs WHERE authorization_id=? AND core_purpose_id=?)<
    (SELECT json_extract(authorization_json,'$.max_operations') FROM host_wake_operator_authorizations WHERE authorization_id=?)`)
   .bind(c.challenge_id,crypto.randomUUID(),id,v.core_purpose_id,v.operation_id,v.generation,v.revision,requestHash,canonical(v),canonical(c),expectedKind,c.captured_at_ms,c.expires_at_ms,at,c.expires_at_ms,id,at,at,principal,id,v.core_purpose_id,canonical(v),at,expectedKind,id,v.core_purpose_id,id).run();
  const row=await this.nativeJob(c.challenge_id);need(row&&row.authorization_id===id&&row.core_purpose_id===v.core_purpose_id&&row.request_hash===requestHash&&row.proof_kind===expectedKind,'host_wake_native_job_consumed_or_capacity',409);return row;
 }
 /** Durable once marker BEFORE native crypto awaits. UNKNOWN is deliberately
  * terminal after a negative finish; only the same in-flight real verifier may
  * atomically publish a valid proof/counter receipt from VERIFYING, never UNKNOWN.
  * This store has no positive
  * enrollment/verification writer or generic boolean proof-admission method. */
 async claimNativeProof(id:string,principal:string,challenge:string,kind:NativeProofKind,claim:string,at:number):Promise<boolean>{
  integer(at);const r=await this.db.prepare(`UPDATE host_wake_native_jobs SET outcome='verifying',verification_claim=?
   WHERE challenge_id=? AND authorization_id=? AND proof_kind=? AND outcome='reserved' AND captured_at<=? AND expires_at>?
   AND EXISTS(${LIVE} AND i.id=?)
   AND EXISTS(SELECT 1 FROM host_wake_issuer_once s WHERE s.authorization_id=host_wake_native_jobs.authorization_id AND s.core_purpose_id=host_wake_native_jobs.core_purpose_id AND s.outcome='issued' AND s.expires_at>?)`)
   .bind(claim,challenge,id,kind,at,at,id,at,at,principal,at).run();return r.meta.changes===1;
 }
 /** Negative closure never needs a live/positive grant or a new budget row.
  * Once an original proof becomes UNKNOWN it cannot be reclaimed or verified. */
 async failNativeProof(id:string,challenge:string,claim:string,outcome:'unknown'|'rejected'|'expired'){
  need(outcome==='unknown'||outcome==='rejected'||outcome==='expired');
  await this.db.prepare(`UPDATE host_wake_native_jobs SET outcome=? WHERE authorization_id=? AND challenge_id=? AND verification_claim=? AND outcome='verifying'`).bind(outcome,id,challenge,claim).run();
 }
 /** Reserve-to-issued is performed only once. Persisted UNKNOWN/expiry cannot
  * be promoted by retry. No recovery of Source181's one-time credential. */
 async finishIssuer(id:string,purpose:string,outcome:'issued'|'unknown'|'expired',at:number,originalClaim:string,requestHash:string,principal:string){
  integer(at);need(outcome==='issued'||outcome==='unknown'||outcome==='expired');
  const authority=outcome==='issued'?`EXISTS(${LIVE} AND i.id=?)`:
   `EXISTS(SELECT 1 FROM host_wake_operator_authorizations a WHERE a.authorization_id=? AND a.core_install_token_record_id=?)`;
  const bindings=outcome==='issued'?[id,at,at,principal]:[id,principal];
  await this.db.prepare(`UPDATE host_wake_issuer_once SET outcome=CASE
   WHEN original_request_expires_at<=? OR expires_at<=? OR original_request_expires_at<=CAST(unixepoch('subsec')*1000 AS INTEGER) OR expires_at<=CAST(unixepoch('subsec')*1000 AS INTEGER)
   THEN 'expired' ELSE ? END
   WHERE authorization_id=? AND core_purpose_id=? AND outcome='reserved' AND claim_id=? AND request_hash=? AND ${authority}`)
   .bind(at,at,outcome,id,purpose,originalClaim,requestHash,...bindings).run();
 }
}
