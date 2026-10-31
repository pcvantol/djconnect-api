/** Pure existing-role lookup: no authorization, key, token, purpose, nonce or
 * capability creation; no body-ID semantic latch on this readonly operation. */
import type {AppEnv} from '../../src/types';
import {canonical} from '../../src/surface-push/wire';
import {sha256Hex} from '../../src/crypto';
import {exact,target,need} from '../host-app-wake/wire';
import {decodeOperatorAuthorization,RECEIVING_VERSION} from './wire';
import {authenticateCore} from './principal';
import {RequestWindow} from './request-window';
import {readBoundedPrivateBody} from './private-intake';
import {decodeSavedAssertionPolicy} from './native-assertion';
export const RESOLVE_PATH='/v1/push/host-app-wake/authorization/resolve';
const hashes=['paired_subject_binding_sha256','owner_binding','device_binding','source_binding'] as const;
export interface RoleScope {paired_subject_binding_sha256:string;owner_binding:string;device_binding:string;source_binding:string;target:{host_bundle_id:string;installation_id:string};platform:'ios'|'ipados';apns_environment:'sandbox'|'production';native_key_id_b64:string}
export function decodeResolve(value:unknown):Readonly<{version:typeof RECEIVING_VERSION;scope:Readonly<RoleScope>} >{
 exact(value,['version','scope']);need(value.version===RECEIVING_VERSION);exact(value.scope,[...hashes,'target','platform','apns_environment','native_key_id_b64']);const s=value.scope;
 for(const f of hashes)need(typeof s[f]==='string'&&/^[a-f0-9]{64}$/.test(s[f]));target(s.target);need((s.platform==='ios'||s.platform==='ipados')&&(s.apns_environment==='sandbox'||s.apns_environment==='production'));
 need(typeof s.native_key_id_b64==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(s.native_key_id_b64)&&atob(s.native_key_id_b64).length===32&&btoa(atob(s.native_key_id_b64))===s.native_key_id_b64);
 return Object.freeze({version:RECEIVING_VERSION,scope:Object.freeze({...s,target:Object.freeze({...s.target})})}) as unknown as Readonly<{version:typeof RECEIVING_VERSION;scope:Readonly<RoleScope>}>;
}
export interface ResolvedAuthorization {version:typeof RECEIVING_VERSION;resolution:'existing';authorization_id:string;request_sha256:string;scope_sha256:string;original_authorization_issued_at_ms:number;original_authorization_expires_at_ms:number;max_original_purpose_ms:number;max_operations:number;max_reserved_sends:number;native_proof_kind:'app_attest_assertion';registration_mode:'single_original_no_rotation';selected_ha_origin_sha256:string;identity_policy_sha256:string;deployment_policy_sha256:string}
export async function resolveAuthorization(request:Request,env:AppEnv,now:()=>number):Promise<Readonly<ResolvedAuthorization>>{
 const db=env.DB,window=new RequestWindow(now,request.signal);
 try{
  const u=new URL(request.url);need(request.method==='POST'&&u.protocol==='https:'&&u.pathname===RESOLVE_PATH&&!request.url.includes('?')&&!request.url.includes('#'),'host_wake_receiving_route',404);
  for(const h of ['origin','cookie','x-djconnect-device-id','x-djconnect-client-type'])need(!request.headers.has(h),'host_wake_server_transport',403);
  const principal=await authenticateCore(request,db,window),body=decodeResolve((await readBoundedPrivateBody(request,window)).value),s=body.scope;
  const predicates=hashes.map(k=>`json_extract(a.authorization_json,'$.${k}')=?`).join(' AND '),at=window.check();
  const result=await window.run(()=>db.prepare(`SELECT a.authorization_id,a.authorization_json,n.public_key_spki_b64,n.native_key_id_b64,n.assertion_policy_json,n.host_bundle,n.enrollment_receipt_sha256,n.signed_environment_receipt_sha256
   FROM host_wake_operator_authorizations a JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
   JOIN host_wake_native_enrollments n ON n.native_key_ref=json_extract(a.authorization_json,'$.native_key_ref')
   WHERE i.id=? AND i.ha_install_id=? AND i.disabled=0 AND a.outcome='authorized' AND a.issued_at<=? AND a.expires_at>?
   AND a.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND n.disabled=0 AND n.issued_at<=? AND n.expires_at>?
   AND ${predicates} AND n.native_key_id_b64=? AND n.host_bundle=? AND n.install_id=? AND n.platform=? AND n.environment=?
   AND n.identity_policy_sha256=json_extract(a.authorization_json,'$.identity_policy_sha256') AND n.deployment_policy_sha256=json_extract(a.authorization_json,'$.deployment_policy_sha256')
   AND json_extract(a.authorization_json,'$.target.host_bundle_id')=? AND json_extract(a.authorization_json,'$.target.installation_id')=?
   AND json_extract(a.authorization_json,'$.platform')=? AND json_extract(a.authorization_json,'$.apns_environment')=? LIMIT 2`)
   .bind(principal.id,principal.ha_install_id,at,at,at,at,...hashes.map(k=>s[k]),s.native_key_id_b64,s.target.host_bundle_id,s.target.installation_id,s.platform,s.apns_environment,s.target.host_bundle_id,s.target.installation_id,s.platform,s.apns_environment).all<Record<string,unknown>>());
  // Never choose the latest of two grants or infer a rotation/authority lineage.
  need(result.results.length===1,'host_wake_authorization_unavailable',503);const r=result.results[0],a=decodeOperatorAuthorization(JSON.parse(String(r.authorization_json)));
  need(typeof r.enrollment_receipt_sha256==='string'&&/^[a-f0-9]{64}$/.test(r.enrollment_receipt_sha256)&&typeof r.signed_environment_receipt_sha256==='string'&&/^[a-f0-9]{64}$/.test(r.signed_environment_receipt_sha256),'host_wake_authorization_unavailable',503);
  const p=decodeSavedAssertionPolicy({host_bundle:s.target.host_bundle_id,assertion_policy_json:typeof r.assertion_policy_json==='string'?r.assertion_policy_json:null});
  need(p.app_identifier===env.APNS_TEAM_ID+'.'+s.target.host_bundle_id&&env.APNS_TOPIC_IOS===s.target.host_bundle_id&&env.APNS_ENVIRONMENT===s.apns_environment,'host_wake_native_deployment_mismatch',503);
  need(typeof r.public_key_spki_b64==='string','host_wake_authorization_unavailable',503);const raw=Uint8Array.from(atob(r.public_key_spki_b64),c=>c.charCodeAt(0));
  const key=await window.run(()=>crypto.subtle.importKey('spki',raw,{name:'ECDSA',namedCurve:'P-256'},true,['verify']));const point=await window.run(()=>crypto.subtle.exportKey('raw',key));need(point instanceof ArrayBuffer,'host_wake_authorization_unavailable',503);
  const id=new Uint8Array(await window.run(()=>crypto.subtle.digest('SHA-256',point)));need(btoa(String.fromCharCode(...id))===s.native_key_id_b64,'host_wake_authorization_unavailable',503);
  const requestHash=await window.run(()=>sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST',RESOLVE_PATH,body]))),scopeHash=await window.run(()=>sha256Hex(canonical(s)));window.check();
  return decodeResolvedAuthorization(requestHash,scopeHash,{version:RECEIVING_VERSION,resolution:'existing',authorization_id:a.authorization_id,request_sha256:requestHash,scope_sha256:scopeHash,original_authorization_issued_at_ms:a.original_authorization_issued_at_ms,original_authorization_expires_at_ms:a.original_authorization_expires_at_ms,max_original_purpose_ms:a.max_original_purpose_ms,max_operations:a.max_operations,max_reserved_sends:a.max_reserved_sends,native_proof_kind:'app_attest_assertion',registration_mode:'single_original_no_rotation',selected_ha_origin_sha256:a.selected_ha_origin_sha256,identity_policy_sha256:a.identity_policy_sha256,deployment_policy_sha256:a.deployment_policy_sha256});
 }finally{window.close();}
}

/** Role metadata cannot initialize an original Core parent or a capability. */
export function decodeResolvedAuthorization(requestHash:string,scopeHash:string,value:unknown):Readonly<ResolvedAuthorization>{
 exact(value,['version','resolution','authorization_id','request_sha256','scope_sha256','original_authorization_issued_at_ms','original_authorization_expires_at_ms','max_original_purpose_ms','max_operations','max_reserved_sends','native_proof_kind','registration_mode','selected_ha_origin_sha256','identity_policy_sha256','deployment_policy_sha256']);
 need(value.version===RECEIVING_VERSION&&value.resolution==='existing'&&typeof value.authorization_id==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(value.authorization_id));
 need(value.request_sha256===requestHash&&value.scope_sha256===scopeHash&&/^[a-f0-9]{64}$/.test(requestHash)&&/^[a-f0-9]{64}$/.test(scopeHash));
 const number=(v:unknown,min:number,max=Number.MAX_SAFE_INTEGER)=>need(typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=min&&v<=max);
 number(value.original_authorization_issued_at_ms,0);number(value.original_authorization_expires_at_ms,(value.original_authorization_issued_at_ms as number)+1);number(value.max_original_purpose_ms,1,28800000);number(value.max_operations,1,256);number(value.max_reserved_sends,1,64);
 for(const k of ['selected_ha_origin_sha256','identity_policy_sha256','deployment_policy_sha256'])need(typeof value[k]==='string'&&/^[a-f0-9]{64}$/.test(value[k] as string));
 need(value.native_proof_kind==='app_attest_assertion'&&value.registration_mode==='single_original_no_rotation');return Object.freeze({...value}) as unknown as Readonly<ResolvedAuthorization>;
}
