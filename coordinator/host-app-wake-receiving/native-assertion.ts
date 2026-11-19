/** Actual saved-job assertion crypto + atomic counter receipt. SOURCE ONLY.
 * No native enrollment writer, caller-provided key, boolean verifier, fixed-QA
 * relabelling, or default native policy is admitted by this module. */
import cbor from 'cbor';
import * as asn1js from 'asn1js';
import * as pki from 'pkijs';
import {canonical} from '../../src/surface-push/wire';
import {currentNativePolicy} from './native-policy-store';
import {decodeLaunchCategory} from './native-policy';
import {exact,need} from '../host-app-wake/wire';
import {decodeNativeOriginal,decodeNativeChallenge,nativeSigningData} from './wire';
import {proof,type NativeProofData} from './server-wire';
import {ReceivingStore,type NativeJobRow} from './receiving-store';
import {RequestWindow} from './request-window';
interface Enrollment {
 native_key_ref:string;native_key_id_b64:string;public_key_spki_b64:string;assertion_policy_json:string|null;native_policy_json:string|null;
 host_bundle:string;install_id:string;platform:string;environment:string;identity_policy_sha256:string;deployment_policy_sha256:string;
 enrollment_receipt_sha256:string;signed_environment_receipt_sha256:string;issued_at:number;expires_at:number;counter:number;disabled:number;
}
interface Saved {db:D1Database;job:NativeJobRow;key:Enrollment;principal:string;claim:string;counter:number;original:string}
export interface VerifiedAssertion {readonly kind:'host_wake_assertion_crypto_only'}
const verified=new WeakMap<VerifiedAssertion,Saved>();
const bytes=(s:string)=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const equal=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const digest=async(b:Uint8Array)=>new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(b)));
const concat=(a:Uint8Array,b:Uint8Array)=>{const r=new Uint8Array(a.length+b.length);r.set(a);r.set(b,a.length);return r;};
class InvalidProof extends Error {}
function valid(x:unknown):asserts x {if(!x)throw new InvalidProof();}
function closedMap(v:unknown,keys:(string|number)[]):Map<unknown,unknown>{valid(v instanceof Map&&v.size===keys.length&&keys.every(k=>v.has(k)));return v;}
function decode(b:Uint8Array){return cbor.decodeFirstSync(Buffer.from(b),{preventDuplicateKeys:true,preferMap:true,max_depth:8});}
function signature(raw:unknown):Uint8Array{
 valid(raw instanceof Uint8Array&&raw.length>=8&&raw.length<=72&&raw[0]===0x30&&raw[1]===raw.length-2);
 const d=asn1js.fromBER(Uint8Array.from(raw).buffer);valid(d.offset===raw.length&&!d.result.error&&equal(new Uint8Array(d.result.toBER(false)),raw));
 const seq=d.result;valid(seq instanceof asn1js.Sequence&&seq.valueBlock.value.length===2);
 for(const n of seq.valueBlock.value){valid(n instanceof asn1js.Integer&&!n.idBlock.isConstructed&&n.idBlock.blockLength===1&&n.lenBlock.blockLength===1&&!n.lenBlock.isIndefiniteForm);const b=n.valueBlock.valueHexView;valid(b.length>0&&b.length<=33&&!(b[0]&128)&&b.some(x=>x!==0)&&!(b.length>1&&b[0]===0&&b[1]<128)&&(b.length<33||b[0]===0));}
 const out=new Uint8Array(pki.createECDSASignatureFromCMS(seq,32));valid(out.length===64);return out;
}
export function decodeSavedAssertionPolicy(key:Pick<Enrollment,'host_bundle'|'assertion_policy_json'>){
 need(typeof key.assertion_policy_json==='string','host_wake_native_policy_unavailable',503);
 try{
  const p:unknown=JSON.parse(key.assertion_policy_json);need(p!==null&&typeof p==='object'&&!Array.isArray(p));const r=p as Record<string,unknown>,v2=r.profile==='host_wake_apple_assertion_properties_v2';
  exact(r,['profile','app_identifier','bundle_version',...(v2?['launch_validation_category_b64']:[])]);
  need((r.profile==='host_wake_apple_assertion_properties_v1'||v2)&&typeof r.app_identifier==='string'&&new RegExp('^[A-Z0-9]{10}\\.'+key.host_bundle.replaceAll('.','\\.')+'$').test(r.app_identifier)&&typeof r.bundle_version==='string'&&(v2?/^[0-9]{1,20}(?:\.[0-9]{1,20}){0,2}$/:/^[0-9]{1,20}$/).test(r.bundle_version));
  if(v2)decodeLaunchCategory(r.launch_validation_category_b64);need(canonical(r)===key.assertion_policy_json);
  return r as {profile:string;app_identifier:string;bundle_version:string;launch_validation_category_b64?:string};
 }catch{need(false,'host_wake_native_policy_unavailable',503);}
}

/** Reads its actual trusted enrollment/key and immutable original job from D1.
 * Fixed algorithm/key WebCrypto failures propagate; only malformed/false proof
 * returns null. A parsed DATA policy or key from a caller cannot enter this API. */
export async function verifySavedAssertion(db:D1Database,authorization:string,principal:string,challenge:string,claim:string,value:NativeProofData,window:RequestWindow):Promise<VerifiedAssertion|null>{
 const input=proof(value);need(input.kind==='app_attest_assertion','host_wake_native_attestation_unavailable',503);
 const store=new ReceivingStore(db,10000),job=await window.run(()=>store.nativeJob(challenge));
 need(job&&job.authorization_id===authorization&&job.outcome==='verifying'&&job.verification_claim===claim&&job.proof_kind===input.kind&&window.check()<job.expires_at,'host_wake_native_job_consumed',409);
 need(await window.run(()=>store.isLive(authorization,principal,window.check())),'host_wake_native_authority',403);
 const key=await window.run(()=>db.prepare(`SELECT n.* FROM host_wake_native_enrollments n JOIN host_wake_operator_authorizations a ON n.native_key_ref=json_extract(a.authorization_json,'$.native_key_ref') WHERE a.authorization_id=? AND n.disabled=0`).bind(authorization).first<Enrollment>());
 need(key,'host_wake_native_enrollment_unavailable',503);const p=decodeSavedAssertionPolicy(key),o=decodeNativeOriginal(JSON.parse(job.original_json)),c=decodeNativeChallenge(JSON.parse(job.challenge_json),o);
 if(p.profile==='host_wake_apple_assertion_properties_v2'){const selected=await currentNativePolicy(db,authorization,key.native_key_ref,window,o);need(selected.row.outcome==='enrolled'&&selected.row.policy_json===key.native_policy_json,'host_wake_native_authority',403);}else need(key.native_policy_json===null,'host_wake_native_policy_unavailable',503);
 need(key.native_key_id_b64===o.native_key_id_b64&&key.host_bundle===o.target.host_bundle_id&&key.install_id===o.target.installation_id&&key.platform===o.platform&&key.environment===o.apns_environment&&key.identity_policy_sha256===o.identity_policy_sha256&&key.deployment_policy_sha256===o.deployment_policy_sha256&&key.issued_at<=window.check()&&key.expires_at>window.check(),'host_wake_native_policy_changed',403);
 need(/^[a-f0-9]{64}$/.test(key.enrollment_receipt_sha256)&&/^[a-f0-9]{64}$/.test(key.signed_environment_receipt_sha256)&&Number.isSafeInteger(key.counter)&&key.counter>=0&&key.counter<=0xffffffff,'host_wake_native_policy_unavailable',503);
 need(job.challenge_id===c.challenge_id&&job.captured_at===c.captured_at_ms&&job.expires_at===c.expires_at_ms&&job.operation_id===o.operation_id&&job.generation===o.generation&&job.revision===o.revision,'host_wake_native_saved_context',503);
 const signing=nativeSigningData(o,c);let auth:Uint8Array,rawSig:Uint8Array,counter:number;
 try{
  const obj=closedMap(decode(bytes(input.bytes_b64)),['signature','authenticatorData']);const raw=obj.get('authenticatorData');valid(raw instanceof Uint8Array&&raw.length>=38&&raw.length<=2048);auth=raw;
  valid(auth[32]===0xc0);counter=new DataView(auth.buffer,auth.byteOffset,auth.byteLength).getUint32(33,false);valid(counter>key.counter);
  const props=closedMap(decode(auth.subarray(37)),['apple_bundle_version_01','apple_validation_category_01']);valid(props.get('apple_bundle_version_01')===p.bundle_version);
  const category=props.get('apple_validation_category_01');valid(category instanceof Uint8Array&&equal(category,p.profile==='host_wake_apple_assertion_properties_v2'?bytes(p.launch_validation_category_b64!):new Uint8Array([3,0,0,0])));
  rawSig=signature(obj.get('signature'));
 }catch{return null;}
 // These inputs/algorithms are fixed and trusted. Their exceptions are internal
 // failures, never an invalid-proof verdict or fake service acceptance.
 const appHash=await window.run(()=>digest(new TextEncoder().encode(p.app_identifier)));if(!equal(auth.subarray(0,32),appHash))return null;
 const imported=await window.run(()=>crypto.subtle.importKey('spki',bytes(key.public_key_spki_b64),{name:'ECDSA',namedCurve:'P-256'},true,['verify']));
 const exported=await window.run(()=>crypto.subtle.exportKey('raw',imported));need(exported instanceof ArrayBuffer,'host_wake_native_stored_key',503);const rawPoint=new Uint8Array(exported);
 const keyHash=await window.run(()=>digest(rawPoint));need(equal(keyHash,bytes(key.native_key_id_b64)),'host_wake_native_stored_key_identity',503);
 const clientHash=await window.run(()=>digest(signing.client_data));const nonce=await window.run(()=>digest(concat(auth,clientHash)));
 if(!await window.run(()=>crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},imported,rawSig,nonce)))return null;
 window.check();need(window.check()<job.expires_at,'host_wake_native_job_expired',409);
 const result=Object.freeze({kind:'host_wake_assertion_crypto_only' as const});verified.set(result,{db,job,key,principal,claim,counter,original:job.original_json});return result;
}
/** One branded actual-crypto receipt, actual SQL counter CAS, same private job
 * claim, current local principal/operator/policy. No positive result from JSON. */
export async function commitVerifiedAssertion(result:VerifiedAssertion,window:RequestWindow):Promise<boolean>{
 const saved=verified.get(result);need(saved,'host_wake_native_crypto_receipt_required',403);verified.delete(result);
 const {db,job,key,principal,claim,counter,original}=saved;const commitClaim=crypto.randomUUID();window.check();const SQL_NOW="CAST(unixepoch('subsec')*1000 AS INTEGER)";
 await window.run(()=>db.batch([
  db.prepare(`UPDATE host_wake_native_enrollments SET counter=?,counter_claim=? WHERE native_key_ref=? AND counter=? AND disabled=0
   AND issued_at<=${SQL_NOW} AND expires_at>${SQL_NOW} AND public_key_spki_b64=? AND assertion_policy_json=? AND native_policy_json IS ?
   AND identity_policy_sha256=? AND deployment_policy_sha256=? AND enrollment_receipt_sha256=? AND signed_environment_receipt_sha256=?
   AND host_bundle=? AND install_id=? AND platform=? AND environment=? AND native_key_id_b64=?
   AND EXISTS(SELECT 1 FROM host_wake_native_jobs j JOIN host_wake_operator_authorizations a ON a.authorization_id=j.authorization_id
    JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
    JOIN host_wake_issuer_once s ON s.authorization_id=j.authorization_id AND s.core_purpose_id=j.core_purpose_id
    WHERE j.challenge_id=? AND j.private_job_id=? AND j.verification_claim=? AND j.outcome='verifying' AND j.original_json=? AND j.expires_at>${SQL_NOW}
    AND j.proof_kind='app_attest_assertion' AND a.authorization_id=? AND a.outcome='authorized' AND a.expires_at>${SQL_NOW}
    AND i.id=? AND i.disabled=0 AND s.native_proof_kind='app_attest_assertion' AND s.outcome='issued' AND s.expires_at>${SQL_NOW} AND s.original_json=j.original_json
    AND json_extract(a.authorization_json,'$.native_key_ref')=host_wake_native_enrollments.native_key_ref)
   AND NOT EXISTS(SELECT 1 FROM host_wake_native_verifications WHERE challenge_id=?)`)
   .bind(counter,commitClaim,key.native_key_ref,key.counter,key.public_key_spki_b64,key.assertion_policy_json,key.native_policy_json,key.identity_policy_sha256,key.deployment_policy_sha256,key.enrollment_receipt_sha256,key.signed_environment_receipt_sha256,key.host_bundle,key.install_id,key.platform,key.environment,key.native_key_id_b64,job.challenge_id,job.private_job_id,claim,original,job.authorization_id,principal,job.challenge_id),
  db.prepare(`INSERT OR IGNORE INTO host_wake_native_verifications(challenge_id,private_job_id,native_key_ref,verified_counter,verified_at,original_json,commit_claim)
   SELECT ?,?,?,?,${SQL_NOW},?,? FROM host_wake_native_enrollments n WHERE n.native_key_ref=? AND n.counter=? AND n.counter_claim=?
   AND EXISTS(SELECT 1 FROM host_wake_native_jobs WHERE challenge_id=? AND verification_claim=? AND outcome='verifying' AND expires_at>${SQL_NOW})`)
   .bind(job.challenge_id,job.private_job_id,key.native_key_ref,counter,original,commitClaim,key.native_key_ref,counter,commitClaim,job.challenge_id,claim),
  db.prepare(`UPDATE host_wake_native_jobs SET outcome='verified' WHERE challenge_id=? AND verification_claim=? AND outcome='verifying'
   AND EXISTS(SELECT 1 FROM host_wake_native_verifications v WHERE v.challenge_id=? AND v.private_job_id=? AND v.native_key_ref=? AND v.verified_counter=? AND v.original_json=? AND v.commit_claim=?)`)
   .bind(job.challenge_id,claim,job.challenge_id,job.private_job_id,key.native_key_ref,counter,original,commitClaim)
 ]));
 return !!await window.run(()=>db.prepare("SELECT 1 FROM host_wake_native_jobs j JOIN host_wake_native_verifications v ON v.challenge_id=j.challenge_id WHERE j.challenge_id=? AND j.private_job_id=? AND j.verification_claim=? AND j.outcome='verified' AND v.commit_claim=?").bind(job.challenge_id,job.private_job_id,claim,commitClaim).first());
}
