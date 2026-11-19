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
import {loadNativeState} from './native-state';
const fields=['DB','APNS_TEAM_ID','APNS_KEY_ID','APNS_PRIVATE_KEY','APNS_TOKEN_ENCRYPTION_KEY','APNS_ENVIRONMENT','APNS_TOPIC_IOS'] as const;
export async function bindSource181(env:AppEnv,issuer:IssuerRow,principal:string,window:RequestWindow,fetcher:typeof fetch,capacity:number){
 const db=env.DB,store=new ReceivingStore(db,capacity),o=decodeNativeOriginal(JSON.parse(issuer.original_json));
 const a=await window.run(()=>store.authorization(issuer.authorization_id));need(a&&a.core_install_token_record_id===principal,'host_wake_principal_scope',403);
 const savedIssuer=await window.run(()=>store.issuer(issuer.authorization_id,issuer.core_purpose_id));need(savedIssuer&&canonical(savedIssuer)===canonical(issuer),'host_wake_issuer_original',403);
 const auth=decodeOperatorAuthorization(JSON.parse(a.authorization_json));
 const scope=original({version:VERSION,purpose_id:issuer.private_purpose_id,token_role:'host_app_wake',owner_binding:o.owner_binding,device_binding:o.device_binding,source_binding:o.source_binding,target:o.target,apns_environment:o.apns_environment,platform:o.platform,issued_at_ms:o.original_wake_issued_at_ms,expires_at_ms:o.original_wake_expires_at_ms,display_expires_at_ms:o.original_display_expires_at_ms,max_operations:auth.max_operations,max_wakes:auth.max_reserved_sends});
 const snapshot=Object.fromEntries(fields.map(f=>[f,env[f]]));let firstSourceClock=true,closed=false,provider:SurfaceProvider|undefined;
 const current=()=>{need(!closed&&fields.every(f=>env[f]===snapshot[f]),'host_wake_receiving_retired',503);window.check();};
 const live=async()=>{current();need(await window.run(()=>store.isLive(issuer.authorization_id,principal,window.check())),'host_wake_native_authority',403);current();};
 /** The stored signed-environment/enrollment receipts remain mandatory. This is
  * actual configuration binding, not derivation from App Attest AAGUID or ios. */
 async function nativePolicy(){
  await live();const result=await loadNativeState(db,auth,env,window,o);
  if(result.kind!==issuer.native_proof_kind){
   need(issuer.native_proof_kind==='app_attest_attestation'&&result.key,'host_wake_native_authority',403);
   const own=await window.run(()=>db.prepare(`SELECT 1 FROM host_wake_native_jobs j JOIN host_wake_native_verifications v ON v.challenge_id=j.challenge_id AND v.private_job_id=j.private_job_id JOIN host_wake_native_enrollments n ON n.native_key_ref=v.native_key_ref WHERE j.authorization_id=? AND j.core_purpose_id=? AND j.original_json=? AND j.proof_kind='app_attest_attestation' AND j.outcome='verified' AND v.verified_counter=0 AND n.native_key_ref=? AND n.enrollment_job_id=j.private_job_id AND n.enrollment_claim=v.commit_claim AND n.disabled=0`).bind(issuer.authorization_id,issuer.core_purpose_id,issuer.original_json,auth.native_key_ref).first());need(own,'host_wake_native_authority',403);
  }
  current();return {...result,kind:issuer.native_proof_kind};
 }
 const selectedNative=await nativePolicy();

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
  // One binding per delegated HTTP callback: inherit its first pre-await capture.
  },now:()=>{current();const at=window.check();if(firstSourceClock){firstSourceClock=false;return window.capturedAt;}return at;},encryptionKey:()=>{current();return env.APNS_TOKEN_ENCRYPTION_KEY;},
  authorizeProvider:async()=>{current();provider??=createSurfaceProvider(env,()=>window.check());const token=await window.run(()=>provider!.authorizeProvider());current();return token;},
  fetcher:async(input,init)=>{current();const response=await window.run(()=>fetcher(input,init));current();return response;}
 });
 return Object.freeze({scope,service,proofKind:selectedNative.kind,
  close(){closed=true;service.close();provider?.close();},
  async assertLocal(){await nativePolicy();}
 });
}
