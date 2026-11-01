/** Actual first-attestation verifier + opaque receipt + atomic enrolled-key SQL.
 * SOURCE ONLY: no SDK call, public route, caller CA, fake verdict port or default
 * app/build/environment. Initial production/native acceptance remains separate. */
import type {AppEnv} from '../../src/types';
import {sha256Hex} from '../../src/crypto';
import {seal} from '../../src/surface-push/crypto';
import {canonical} from '../../src/surface-push/wire';
import {integer,need} from '../host-app-wake/wire';
import {decodeNativeOriginal,decodeNativeChallenge,nativeSigningData,RECEIVING_VERSION} from './wire';
import {proof,type NativeProofData} from './server-wire';
import {ReceivingStore,type NativeJobRow} from './receiving-store';
import {currentNativePolicy,type NativePolicyRow} from './native-policy-store';
import {assertionPolicyForNative,type NativePolicy} from './native-policy';
import {verifyAppleAttestationEvidence,NativeReceiptStatusUnavailable} from './native-apple-evidence.mjs';
import {RequestWindow} from './request-window';
export interface VerifiedAttestation {readonly kind:'host_wake_first_attestation_crypto_only'}
interface Material {db:D1Database;job:NativeJobRow;principal:string;claim:string;policy:Readonly<NativePolicy>;policyRow:NativePolicyRow;authorizationJSON:string;spki:string;receiptHash:string;receiptCreated:number;expires:number;statusChecked:number;statusExpires:number;ciphertext:string;nonce:string;capacity:number}
const verified=new WeakMap<VerifiedAttestation,Material>();
export async function verifySavedAttestation(db:D1Database,env:AppEnv,authorization:string,principal:string,challenge:string,claim:string,value:NativeProofData,window:RequestWindow,fetcher:typeof fetch,capacity:number):Promise<VerifiedAttestation|null>{
 const input=proof(value);need(input.kind==='app_attest_attestation'&&env.DB===db,'host_wake_native_authority',403);integer(capacity,1,4096);
 const store=new ReceivingStore(db,capacity),job=await window.run(()=>store.nativeJob(challenge));
 need(job&&job.authorization_id===authorization&&job.outcome==='verifying'&&job.verification_claim===claim&&job.proof_kind===input.kind&&window.check()<job.expires_at,'host_wake_native_job_consumed',409);
 need(await window.run(()=>store.isLive(authorization,principal,window.check())),'host_wake_native_authority',403);
 const o=decodeNativeOriginal(JSON.parse(job.original_json)),c=decodeNativeChallenge(JSON.parse(job.challenge_json),o),saved=await currentNativePolicy(db,authorization,(JSON.parse((await window.run(()=>store.authorization(authorization)))!.authorization_json) as {native_key_ref:string}).native_key_ref,window,o),p=saved.policy;
 need(saved.row.outcome==='pending'&&saved.row.attestation_job_id===job.private_job_id,'host_wake_native_job_consumed',409);
 need(p.app_identifier===env.APNS_TEAM_ID+'.'+o.target.host_bundle_id&&p.apns_team_id===env.APNS_TEAM_ID&&env.APNS_TOPIC_IOS===o.target.host_bundle_id&&env.APNS_ENVIRONMENT===o.apns_environment,'host_wake_native_deployment_mismatch',503);
 need(job.challenge_id===c.challenge_id&&job.captured_at===c.captured_at_ms&&job.expires_at===c.expires_at_ms&&job.operation_id===o.operation_id&&job.generation===o.generation&&job.revision===o.revision,'host_wake_native_saved_context',503);
 const auth=await window.run(()=>store.authorization(authorization));need(auth,'host_wake_native_authority',403);
 const nativeLifetime=new AbortController(),nativeEnd=Math.min(window.expiresAt,job.expires_at),nativeTimer=setTimeout(()=>nativeLifetime.abort(),Math.max(1,nativeEnd-window.check())),nativeSignal=AbortSignal.any([window.signal,nativeLifetime.signal]);
 const actualWindow={signal:nativeSignal,check(){const at=window.check();need(at<job.expires_at&&!nativeSignal.aborted,'host_wake_native_job_expired',409);return at;},run<T>(work:()=>Promise<T>,stage?:AbortSignal){this.check();return window.run(work,stage?AbortSignal.any([nativeSignal,stage]):nativeSignal).then(value=>{this.check();return value;});}};
 try{
 let evidence:Awaited<ReturnType<typeof verifyAppleAttestationEvidence>>;
 try{evidence=await verifyAppleAttestationEvidence(Uint8Array.from(atob(input.bytes_b64),v=>v.charCodeAt(0)),nativeSigningData(o,c).client_data,o.native_key_id_b64,p,actualWindow,fetcher);}
 catch(error){if(error instanceof NativeReceiptStatusUnavailable)need(false,'host_wake_native_status_unavailable',503);throw error;}
 if(!evidence)return null;actualWindow.check();
 need(evidence.scope==='APPLE_ATTESTATION_AND_RECEIPT_CRYPTO_STATUS_ONLY_NO_ENROLLMENT'&&evidence.receipt instanceof Uint8Array&&evidence.receipt.length>0&&evidence.receipt.length<=16384&&typeof evidence.public_key_spki_b64==='string','host_wake_native_receipt_unavailable',503);
 const spkiBytes=Uint8Array.from(atob(evidence.public_key_spki_b64),c=>c.charCodeAt(0));need(spkiBytes.length>0&&spkiBytes.length<=2048&&btoa(String.fromCharCode(...spkiBytes))===evidence.public_key_spki_b64,'host_wake_native_receipt_unavailable',503);
 const imported=await actualWindow.run(()=>crypto.subtle.importKey('spki',spkiBytes,{name:'ECDSA',namedCurve:'P-256'},true,['verify'])),point=await actualWindow.run(()=>crypto.subtle.exportKey('raw',imported));need(point instanceof ArrayBuffer,'host_wake_native_receipt_unavailable',503);
 const returnedId=new Uint8Array(await actualWindow.run(()=>crypto.subtle.digest('SHA-256',point)));need(btoa(String.fromCharCode(...returnedId))===p.native_key_id_b64,'host_wake_native_receipt_unavailable',503);
 const at=actualWindow.check();need(evidence.receiptCreated<=at&&at-evidence.receiptCreated<=300000&&evidence.statusCheckedAt<=at&&evidence.statusExpiresAt>at,'host_wake_native_status_unavailable',503);
 const receiptHash=await actualWindow.run(()=>sha256Hex(evidence.receipt)),expires=Math.min(saved.row.expires_at,evidence.expires,evidence.statusExpiresAt);need(expires>actualWindow.check(),'host_wake_native_job_expired',409);
 const aad=canonical([RECEIVING_VERSION,'native-attestation-receipt',p.native_key_ref,p.native_key_id_b64,saved.row.request_hash,saved.row.issued_at,saved.row.expires_at]);
 const sealed=await actualWindow.run(()=>seal(btoa(String.fromCharCode(...evidence.receipt)),env.APNS_TOKEN_ENCRYPTION_KEY,aad));actualWindow.check();
 const result=Object.freeze({kind:'host_wake_first_attestation_crypto_only' as const});verified.set(result,{db,job,principal,claim,policy:p,policyRow:saved.row,authorizationJSON:auth.authorization_json,spki:evidence.public_key_spki_b64,receiptHash,receiptCreated:evidence.receiptCreated,expires,statusChecked:evidence.statusCheckedAt,statusExpires:evidence.statusExpiresAt,ciphertext:sealed.ciphertext,nonce:sealed.nonce,capacity});return result;
 }finally{clearTimeout(nativeTimer);nativeLifetime.abort();}
}
/** Only a real verifier-created opaque receipt can install a key. No caller
 * verdict, CA, clock boolean, JSON receipt or old QA approval is accepted. */
export async function commitVerifiedAttestation(result:VerifiedAttestation,window:RequestWindow):Promise<boolean>{
 const material=verified.get(result);need(material,'host_wake_native_crypto_receipt_required',403);verified.delete(result);window.check();
 const {db,job,principal,claim,policy:p,policyRow:r,authorizationJSON,spki,receiptHash,receiptCreated,expires,statusChecked,statusExpires,ciphertext,nonce,capacity}=material,commit=crypto.randomUUID(),now="CAST(unixepoch('subsec')*1000 AS INTEGER)";
 // The insert guards abort this whole D1 transaction if the native nonce or
 // local ownership or signed common-status freshness crosses its boundary
 // between the conditional statements. The key lifetime is clipped to that
 // original status interval; no background refresh or fresh lease is implied.
 await window.run(()=>db.batch([
  db.prepare(`UPDATE host_wake_native_pending_policies SET outcome='enrolled',enrollment_claim=?
   WHERE native_key_ref=? AND native_key_id_b64=? AND authorization_id=? AND policy_json=? AND outcome='pending' AND attestation_job_id=?
   AND issued_at<=${now} AND expires_at>${now} AND ?>${now} AND ?>${now}
   AND NOT EXISTS(SELECT 1 FROM host_wake_native_enrollments WHERE native_key_ref=? OR native_key_id_b64=?)
   AND (SELECT COUNT(*) FROM host_wake_native_enrollments)<?
   AND EXISTS(SELECT 1 FROM host_wake_native_jobs j JOIN host_wake_operator_authorizations a ON a.authorization_id=j.authorization_id
    JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
    JOIN host_wake_issuer_once s ON s.authorization_id=j.authorization_id AND s.core_purpose_id=j.core_purpose_id
    WHERE j.private_job_id=? AND j.challenge_id=? AND j.verification_claim=? AND j.outcome='verifying' AND j.proof_kind='app_attest_attestation' AND j.original_json=? AND j.expires_at>${now}
    AND a.authorization_id=? AND a.authorization_json=? AND a.outcome='authorized' AND a.expires_at>${now} AND i.id=? AND i.disabled=0
    AND s.native_proof_kind='app_attest_attestation' AND s.outcome='issued' AND s.original_json=j.original_json AND s.expires_at>${now})`)
   .bind(commit,p.native_key_ref,p.native_key_id_b64,p.authorization_id,r.policy_json,job.private_job_id,statusExpires,expires,p.native_key_ref,p.native_key_id_b64,capacity,job.private_job_id,job.challenge_id,claim,job.original_json,p.authorization_id,authorizationJSON,principal),
  db.prepare(`INSERT INTO host_wake_native_enrollments
   (native_key_ref,native_key_id_b64,public_key_spki_b64,assertion_policy_json,native_policy_json,enrollment_job_id,enrollment_claim,receipt_ciphertext,receipt_nonce,receipt_created_at,common_status_checked_at,common_status_expires_at,host_bundle,install_id,platform,environment,identity_policy_sha256,deployment_policy_sha256,enrollment_receipt_sha256,signed_environment_receipt_sha256,issued_at,expires_at,counter,counter_claim,disabled)
   SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,${now},?,0,?,0 FROM host_wake_native_pending_policies p WHERE p.native_key_ref=? AND p.outcome='enrolled' AND p.enrollment_claim=?`)
   .bind(p.native_key_ref,p.native_key_id_b64,spki,assertionPolicyForNative(p),r.policy_json,job.private_job_id,commit,ciphertext,nonce,receiptCreated,statusChecked,statusExpires,p.scope.target.host_bundle_id,p.scope.target.installation_id,p.scope.platform,p.scope.apns_environment,p.scope.identity_policy_sha256,p.scope.deployment_policy_sha256,receiptHash,p.signed_environment_receipt_sha256,expires,commit,p.native_key_ref,commit),
  db.prepare(`INSERT INTO host_wake_native_verifications(challenge_id,private_job_id,native_key_ref,verified_counter,verified_at,commit_claim,original_json)
   SELECT ?,?,?,0,${now},?,? FROM host_wake_native_enrollments n WHERE n.native_key_ref=? AND n.enrollment_claim=? AND n.enrollment_job_id=?`)
   .bind(job.challenge_id,job.private_job_id,p.native_key_ref,commit,job.original_json,p.native_key_ref,commit,job.private_job_id),
  db.prepare(`UPDATE host_wake_native_jobs SET outcome='verified' WHERE challenge_id=? AND private_job_id=? AND verification_claim=? AND outcome='verifying'
   AND EXISTS(SELECT 1 FROM host_wake_native_verifications v WHERE v.challenge_id=? AND v.private_job_id=? AND v.native_key_ref=? AND v.verified_counter=0 AND v.commit_claim=? AND v.original_json=?)`)
   .bind(job.challenge_id,job.private_job_id,claim,job.challenge_id,job.private_job_id,p.native_key_ref,commit,job.original_json)
 ]));
 return !!await window.run(()=>db.prepare(`SELECT 1 FROM host_wake_native_jobs j JOIN host_wake_native_verifications v ON v.challenge_id=j.challenge_id JOIN host_wake_native_enrollments n ON n.native_key_ref=v.native_key_ref WHERE j.challenge_id=? AND j.private_job_id=? AND j.verification_claim=? AND j.outcome='verified' AND v.commit_claim=? AND n.enrollment_claim=? AND n.disabled=0 AND n.expires_at>${now} AND n.common_status_checked_at<=${now} AND n.common_status_expires_at>${now} AND n.expires_at<=n.common_status_expires_at`).bind(job.challenge_id,job.private_job_id,claim,commit,commit).first());
}
