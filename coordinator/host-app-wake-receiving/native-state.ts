/** Actual saved native or pending-custodian state. No caller verifier/policy
 * callback and no imported fixed-QA application or signing environment. */
import type {AppEnv} from '../../src/types';
import {need} from '../host-app-wake/wire';
import {canonical} from '../../src/surface-push/wire';
import {decodeSavedAssertionPolicy} from './native-assertion';
import {currentNativePolicy} from './native-policy-store';
import {requireNativeCategory,strictNativeBase64,type NativePolicy} from './native-policy';
import {RequestWindow} from './request-window';
import type {OperatorAuthorizationData,NativeOriginalData} from './wire';
export interface NativeEnrollment {native_key_ref:string;native_key_id_b64:string;public_key_spki_b64:string;assertion_policy_json:string|null;native_policy_json:string|null;enrollment_job_id:string|null;enrollment_claim:string|null;host_bundle:string;install_id:string;platform:string;environment:string;identity_policy_sha256:string;deployment_policy_sha256:string;enrollment_receipt_sha256:string;signed_environment_receipt_sha256:string;issued_at:number;expires_at:number;counter:number;disabled:number}
export async function loadNativeState(db:D1Database,auth:Readonly<OperatorAuthorizationData>,env:AppEnv,window:RequestWindow,original?:Readonly<NativeOriginalData>){
 const n=await window.run(()=>db.prepare('SELECT * FROM host_wake_native_enrollments WHERE native_key_ref=?').bind(auth.native_key_ref).first<NativeEnrollment>());let policy:Readonly<NativePolicy>|undefined;
 let keyId:string,appId:string;
 if(n){
  need(n.disabled===0&&n.issued_at<=window.check()&&n.expires_at>window.check(),'host_wake_native_enrollment_unavailable',503);
  keyId=n.native_key_id_b64;strictNativeBase64(keyId,32);
  need(n.host_bundle===auth.target.host_bundle_id&&n.install_id===auth.target.installation_id&&n.platform===auth.platform&&n.environment===auth.apns_environment&&n.identity_policy_sha256===auth.identity_policy_sha256&&n.deployment_policy_sha256===auth.deployment_policy_sha256,'host_wake_native_authority',403);
  need(/^[a-f0-9]{64}$/.test(n.enrollment_receipt_sha256)&&/^[a-f0-9]{64}$/.test(n.signed_environment_receipt_sha256),'host_wake_native_policy_unavailable',503);
  const assertion=decodeSavedAssertionPolicy(n);appId=assertion.app_identifier;
  need(assertion.profile==='host_wake_apple_assertion_properties_v2'&&n.native_policy_json!==null,'host_wake_native_policy_unavailable',503);
  {
   const saved=await currentNativePolicy(db,auth.authorization_id,auth.native_key_ref,window,original);policy=saved.policy;
   need(assertion.app_identifier===policy.app_identifier&&assertion.bundle_version===policy.bundle_version,'host_wake_native_authority',403);requireNativeCategory(policy,assertion.launch_validation_category_b64!);
   need(saved.row.outcome==='enrolled'&&n.native_policy_json===saved.row.policy_json&&policy.native_key_id_b64===keyId&&policy.signed_environment_receipt_sha256===n.signed_environment_receipt_sha256,'host_wake_native_authority',403);
  }
  const raw=Uint8Array.from(atob(n.public_key_spki_b64),c=>c.charCodeAt(0)),key=await window.run(()=>crypto.subtle.importKey('spki',raw,{name:'ECDSA',namedCurve:'P-256'},true,['verify']));
  const point=await window.run(()=>crypto.subtle.exportKey('raw',key));need(point instanceof ArrayBuffer,'host_wake_native_policy_unavailable',503);const id=new Uint8Array(await window.run(()=>crypto.subtle.digest('SHA-256',point)));need(btoa(String.fromCharCode(...id))===keyId,'host_wake_native_policy_unavailable',503);
 }else{
  const saved=await currentNativePolicy(db,auth.authorization_id,auth.native_key_ref,window,original);policy=saved.policy;
  need(saved.row.outcome==='pending'&&(original!==undefined||saved.row.attestation_job_id===null),'host_wake_native_policy_unavailable',503);keyId=policy.native_key_id_b64;appId=policy.app_identifier;
 }
 if(original)need(original.native_key_id_b64===keyId&&original.target.host_bundle_id===auth.target.host_bundle_id&&original.target.installation_id===auth.target.installation_id&&original.platform===auth.platform&&original.apns_environment===auth.apns_environment,'host_wake_native_authority',403);
 need(appId===env.APNS_TEAM_ID+'.'+auth.target.host_bundle_id&&env.APNS_TOPIC_IOS===auth.target.host_bundle_id&&env.APNS_ENVIRONMENT===auth.apns_environment&&(!policy||policy.apns_team_id===env.APNS_TEAM_ID),'host_wake_native_deployment_mismatch',503);
 return {kind:n?'app_attest_assertion' as const:'app_attest_attestation' as const,key:n,native_key_id_b64:keyId,policy};
}
