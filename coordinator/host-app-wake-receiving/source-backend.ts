/** Concrete Source181 binding to actual stored receiving authority. SOURCE ONLY;
 * not imported/admitted by the public Worker root. No generic approval callback. */
import type {AppEnv} from '../../src/types';
import {createSurfaceProvider,type SurfaceProvider} from '../../src/surface-push/provider';
import {canonical} from '../../src/surface-push/wire';
import {createHostAppWakeService} from '../host-app-wake/service';
import {original,need,type Input,type OriginalPurpose,VERSION} from '../host-app-wake/wire';
import {ReceivingStore,type IssuerRow} from './receiving-store';
import {decodeNativeOriginal,decodeOperatorAuthorization,nativeTokenSha256} from './wire';
import {RequestWindow} from './request-window';
import {decodeSavedAssertionPolicy} from './native-assertion';
const fields=['DB','APNS_TEAM_ID','APNS_KEY_ID','APNS_PRIVATE_KEY','APNS_TOKEN_ENCRYPTION_KEY','APNS_ENVIRONMENT','APNS_TOPIC_IOS'] as const;
export async function bindSource181(env:AppEnv,issuer:IssuerRow,principal:string,window:RequestWindow,fetcher:typeof fetch,capacity:number){
 const db=env.DB,store=new ReceivingStore(db,capacity),o=decodeNativeOriginal(JSON.parse(issuer.original_json));
 const a=await window.run(()=>store.authorization(issuer.authorization_id));need(a&&a.core_install_token_record_id===principal,'host_wake_principal_scope',403);
 const savedIssuer=await window.run(()=>store.issuer(issuer.authorization_id,issuer.core_purpose_id));need(savedIssuer&&canonical(savedIssuer)===canonical(issuer),'host_wake_issuer_original',403);
 const auth=decodeOperatorAuthorization(JSON.parse(a.authorization_json));
 const scope=original({version:VERSION,purpose_id:issuer.private_purpose_id,token_role:'host_app_wake',owner_binding:o.owner_binding,device_binding:o.device_binding,source_binding:o.source_binding,target:o.target,apns_environment:o.apns_environment,platform:o.platform,issued_at_ms:o.original_wake_issued_at_ms,expires_at_ms:o.original_wake_expires_at_ms,display_expires_at_ms:o.original_display_expires_at_ms,max_operations:auth.max_operations,max_wakes:auth.max_reserved_sends});
 const snapshot=Object.fromEntries(fields.map(f=>[f,env[f]]));let closed=false,provider:SurfaceProvider|undefined;
 const current=()=>{need(!closed&&fields.every(f=>env[f]===snapshot[f]),'host_wake_receiving_retired',503);window.check();};
 const live=async()=>{current();need(await window.run(()=>store.isLive(issuer.authorization_id,principal,window.check())),'host_wake_native_authority',403);current();};
 /** The stored signed-environment/enrollment receipts remain mandatory. This is
  * actual configuration binding, not derivation from App Attest AAGUID or ios. */
 async function nativePolicy(){
  await live();const row=await window.run(()=>db.prepare(`SELECT public_key_spki_b64,native_key_id_b64,host_bundle,install_id,platform,environment,identity_policy_sha256,deployment_policy_sha256,enrollment_receipt_sha256,signed_environment_receipt_sha256,assertion_policy_json FROM host_wake_native_enrollments WHERE native_key_ref=? AND disabled=0 AND issued_at<=? AND expires_at>?`).bind(auth.native_key_ref,window.check(),window.check()).first<Record<string,unknown>>());
  need(typeof o.native_key_id_b64==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(o.native_key_id_b64)&&atob(o.native_key_id_b64).length===32&&btoa(atob(o.native_key_id_b64))===o.native_key_id_b64,'host_wake_native_policy_unavailable',503);
  need(row&&row.native_key_id_b64===o.native_key_id_b64&&row.host_bundle===o.target.host_bundle_id&&row.install_id===o.target.installation_id&&row.platform===o.platform&&row.environment===o.apns_environment&&row.identity_policy_sha256===o.identity_policy_sha256&&row.deployment_policy_sha256===o.deployment_policy_sha256,'host_wake_native_enrollment_unavailable',503);
  need(typeof row.enrollment_receipt_sha256==='string'&&/^[a-f0-9]{64}$/.test(row.enrollment_receipt_sha256)&&typeof row.signed_environment_receipt_sha256==='string'&&/^[a-f0-9]{64}$/.test(row.signed_environment_receipt_sha256),'host_wake_native_policy_unavailable',503);
  need(typeof row.public_key_spki_b64==='string','host_wake_native_policy_unavailable',503);
  const key=await window.run(()=>crypto.subtle.importKey('spki',Uint8Array.from(atob(row.public_key_spki_b64 as string),c=>c.charCodeAt(0)),{name:'ECDSA',namedCurve:'P-256'},true,['verify']));
  const point=await window.run(()=>crypto.subtle.exportKey('raw',key));need(point instanceof ArrayBuffer,'host_wake_native_policy_unavailable',503);
  const keyId=new Uint8Array(await window.run(()=>crypto.subtle.digest('SHA-256',point)));need(btoa(String.fromCharCode(...keyId))===o.native_key_id_b64,'host_wake_native_policy_unavailable',503);
  const policy=decodeSavedAssertionPolicy({host_bundle:o.target.host_bundle_id,assertion_policy_json:typeof row.assertion_policy_json==='string'?row.assertion_policy_json:null});
  need(policy.app_identifier===env.APNS_TEAM_ID+'.'+o.target.host_bundle_id&&env.APNS_TOPIC_IOS===o.target.host_bundle_id&&env.APNS_ENVIRONMENT===o.apns_environment,'host_wake_native_deployment_mismatch',503);current();
 }
 await nativePolicy();
 const service=createHostAppWakeService({db,capacity,
  async admitOriginalPurpose(){await nativePolicy();const saved=await window.run(()=>store.issuer(issuer.authorization_id,issuer.core_purpose_id));need(saved&&saved.claim_id===issuer.claim_id&&saved.request_hash===issuer.request_hash&&saved.outcome==='reserved'&&saved.original_json===issuer.original_json&&saved.private_purpose_id===issuer.private_purpose_id,'host_wake_issuer_consumed',409);return scope;},
  /** Checks this original authenticated receiving context synchronously; it does
   * not claim to synchronously observe remote Core RAM or asynchronously read D1.
   * Registration/dispatch triggers supply the atomic current-local-state check. */
  assertCurrent(p:OriginalPurpose){current();need(canonical(p)===canonical(scope),'host_wake_original_scope',403);},
  async admitNativeRegistration(p:OriginalPurpose,i:Input){
   current();need(canonical(p)===canonical(scope),'host_wake_original_scope',403);if(i.operation_id!==o.operation_id||i.generation!==o.generation||i.revision!==o.revision){await store.withdrawIssuer(issuer.authorization_id,issuer.core_purpose_id,principal);need(false,'host_wake_original_registration',403);}await nativePolicy();
   const raw=Uint8Array.from(i.apns_token!.match(/../g)!,b=>Number.parseInt(b,16));if(await window.run(()=>nativeTokenSha256(raw))!==o.native_token_sha256){await store.withdrawIssuer(issuer.authorization_id,issuer.core_purpose_id,principal);need(false,'host_wake_original_native_token',403);}
   const row=await window.run(()=>db.prepare(`SELECT 1 FROM host_wake_native_jobs j JOIN host_wake_native_verifications v ON v.challenge_id=j.challenge_id
    WHERE j.authorization_id=? AND j.core_purpose_id=? AND j.operation_id=? AND j.generation=? AND j.revision=? AND j.outcome='verified'
    AND j.original_json=? AND v.original_json=j.original_json AND v.native_key_ref=? AND v.verified_at>=j.captured_at AND v.verified_at<j.expires_at AND v.consumed_at IS NULL`)
    .bind(issuer.authorization_id,issuer.core_purpose_id,o.operation_id,o.generation,o.revision,issuer.original_json,auth.native_key_ref).first());need(row,'host_wake_actual_native_verification_required',403);current();
  },now:()=>{current();return window.check();},encryptionKey:()=>{current();return env.APNS_TOKEN_ENCRYPTION_KEY;},
  authorizeProvider:async()=>{current();provider??=createSurfaceProvider(env,()=>window.check());const token=await window.run(()=>provider!.authorizeProvider());current();return token;},
  fetcher:async(input,init)=>{current();const response=await window.run(()=>fetcher(input,init));current();return response;}
 });
 return Object.freeze({scope,service,proofKind:'app_attest_assertion' as const,
  close(){closed=true;service.close();provider?.close();},
  async assertLocal(){await nativePolicy();}
 });
}
