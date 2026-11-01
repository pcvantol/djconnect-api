/** Actual D1 custody-policy history. Call mutation methods only after the
 * selected HMAC-only operator authentication; no DATA tuple mints authority. */
import {canonical} from '../../src/surface-push/wire';
import {integer,need} from '../host-app-wake/wire';
import {decodeOperatorAuthorization,type NativeOriginalData} from './wire';
import {decodeNativePolicy,matchNativePolicy,type NativePolicy} from './native-policy';
import {ReceivingStore} from './receiving-store';
import {RequestWindow} from './request-window';
export interface NativePolicyRow {native_key_ref:string;native_key_id_b64:string;authorization_id:string;operation_id:string;request_hash:string;policy_json:string;issued_at:number;expires_at:number;outcome:'pending'|'enrolled'|'withdrawn'|'expired';original_request_expires_at:number;enrollment_claim:string|null;attestation_job_id:string|null}
export async function nativePolicyRow(db:D1Database,key:string){return db.prepare('SELECT * FROM host_wake_native_pending_policies WHERE native_key_ref=?').bind(key).first<NativePolicyRow>();}
export async function authorizeNativePolicy(db:D1Database,value:NativePolicy,hash:string,captured:number,at:number,capacity:number){
 const p=decodeNativePolicy(value);integer(captured);integer(at,captured);integer(capacity,1,4096);need(/^[a-f0-9]{64}$/.test(hash));
 const auth=await new ReceivingStore(db,capacity).authorization(p.authorization_id);need(auth,'host_wake_native_authority',403);const a=decodeOperatorAuthorization(JSON.parse(auth.authorization_json));matchNativePolicy(p,a);
 await db.prepare(`INSERT OR IGNORE INTO host_wake_native_pending_policies
  (native_key_ref,native_key_id_b64,authorization_id,operation_id,request_hash,policy_json,issued_at,expires_at,outcome,original_request_expires_at)
  SELECT ?,?,?,?,?,?,?,?,CASE WHEN ?>=? OR ?>=? OR CAST(unixepoch('subsec')*1000 AS INTEGER)>=? OR CAST(unixepoch('subsec')*1000 AS INTEGER)>=? THEN 'expired' ELSE 'pending' END,?
  FROM host_wake_operator_authorizations a JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
  WHERE a.authorization_id=? AND a.authorization_json=? AND a.outcome='authorized' AND i.disabled=0 AND a.issued_at<=? AND a.expires_at>?
  AND NOT EXISTS(SELECT 1 FROM host_wake_native_enrollments WHERE native_key_id_b64=? OR native_key_ref=?)
  AND (SELECT COUNT(*) FROM host_wake_native_pending_policies)<?`)
  .bind(p.native_key_ref,p.native_key_id_b64,p.authorization_id,p.operation_id,hash,canonical(p),p.original_policy_issued_at_ms,p.original_policy_expires_at_ms,at,captured+30000,at,p.original_policy_expires_at_ms,captured+30000,p.original_policy_expires_at_ms,captured+30000,p.authorization_id,auth.authorization_json,at,at,p.native_key_id_b64,p.native_key_ref,capacity).run();
 const row=await nativePolicyRow(db,p.native_key_ref);need(row&&row.operation_id===p.operation_id&&row.request_hash===hash&&row.policy_json===canonical(p),'host_wake_native_policy_consumed_or_capacity',409);return row;
}
export async function currentNativePolicy(db:D1Database,authorization:string,key:string,window:RequestWindow,original?:Readonly<NativeOriginalData>){
 const row=await window.run(()=>nativePolicyRow(db,key));need(row&&(row.outcome==='pending'||row.outcome==='enrolled')&&row.authorization_id===authorization&&row.issued_at<=window.check()&&row.expires_at>window.check(),'host_wake_native_policy_unavailable',503);
 const p=decodeNativePolicy(JSON.parse(row.policy_json));need(canonical(p)===row.policy_json&&p.native_key_id_b64===row.native_key_id_b64&&p.native_key_ref===row.native_key_ref,'host_wake_native_policy_unavailable',503);
 const auth=await window.run(()=>new ReceivingStore(db,4096).authorization(authorization));need(auth,'host_wake_native_authority',403);const a=decodeOperatorAuthorization(JSON.parse(auth.authorization_json));matchNativePolicy(p,a);if(original){matchNativePolicy(p,original);if(row.outcome==='pending'&&row.attestation_job_id){const saved=await window.run(()=>db.prepare('SELECT original_json FROM host_wake_native_jobs WHERE private_job_id=? AND authorization_id=?').bind(row.attestation_job_id,authorization).first<{original_json:string}>());need(saved?.original_json===canonical(original),'host_wake_native_authority',403);}}return {row,policy:p};
}
export async function withdrawNativePolicy(db:D1Database,key:string,capacity:number){
 const row=await nativePolicyRow(db,key);need(row,'host_wake_history_unknown',404);
 await db.batch([db.prepare("UPDATE host_wake_native_pending_policies SET outcome='withdrawn' WHERE native_key_ref=?").bind(key),db.prepare('UPDATE host_wake_native_enrollments SET disabled=1 WHERE native_key_ref=?').bind(key)]);
 // Disable the key before closing its owning operator/push children. Partial
 // negative failure cannot make it current again or renew a policy/nonce.
 await new ReceivingStore(db,capacity).withdrawAuthorization(row.authorization_id);return true;
}
