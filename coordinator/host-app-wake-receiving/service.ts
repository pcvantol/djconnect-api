/** SOURCE ONLY private receiving composition. Not imported by public root.
 * Existing enrolled-key assertions only; first enrollment remains unavailable. */
import type {AppEnv} from '../../src/types';
import {HttpError} from '../../src/http';
import {sha256Hex,base64Url} from '../../src/crypto';
import {canonical} from '../../src/surface-push/wire';
import {integer,need,WakeError} from '../host-app-wake/wire';
import {decodeNativeOriginal,decodeNativeChallenge,decodeOperatorAuthorization,nativeSigningData,RECEIVING_VERSION,OPERATOR_AUTHORIZE,OPERATOR_WITHDRAW} from './wire';
import {loadNativeState} from './native-state';
import {ReceivingStore,type IssuerRow,type NativeJobRow} from './receiving-store';
import {receivePrivate,readBoundedPrivateBody,type PrivateIntake} from './private-intake';
import {RequestWindow} from './request-window';
import {bindSource181} from './source-backend';
import {verifySavedAttestation,commitVerifiedAttestation} from './native-attestation';
import {authorizeNativePolicy,withdrawNativePolicy} from './native-policy-store';
import {OPERATOR_NATIVE_POLICY,OPERATOR_NATIVE_WITHDRAW} from './native-policy';
import {verifySavedAssertion,commitVerifiedAssertion} from './native-assertion';
import {decodePrivateReply,privateBase,privateError,type PrivateState} from './server-reply';
import {authenticateOperator} from './operator-auth';
import {resolveAuthorization,RESOLVE_PATH} from './authorization-resolve';
import {requireReceivingGuards} from './guard-schema';
import {receiveTarget} from './target-transport';
import {SERVER_PREFIX} from './server-wire';
export interface ReceivingOptions {env:AppEnv;now:()=>number;fetcher:typeof fetch;capacity:number}
const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'};
const json=(v:unknown)=>new Response(JSON.stringify(v),{headers});
/** No default clock, fake verifier, public key callback, implicit auth supplier,
 * retrying transport, deployment policy, native enrollment or provider is added. */
export function createReceivingService(options:ReceivingOptions){
 const {env,now,fetcher,capacity}=options;need(env?.DB&&typeof now==='function'&&typeof fetcher==='function','host_wake_receiving_unavailable',503);integer(capacity,1,4096);
 const db=env.DB,store=new ReceivingStore(db,capacity);let closed=false,highWater=0;
 const fields=['DB','DJCONNECT_RELAY_SECRET','APNS_TEAM_ID','APNS_KEY_ID','APNS_PRIVATE_KEY','APNS_TOPIC_IOS','APNS_ENVIRONMENT','APNS_TOKEN_ENCRYPTION_KEY'] as const;
 const config=Object.fromEntries(fields.map(k=>[k,env[k]]));
 const clock=()=>{try{need(!closed&&options.env===env&&options.now===now&&options.fetcher===fetcher&&options.capacity===capacity&&fields.every(k=>env[k]===config[k]),'host_wake_receiving_unavailable',503);const at=now();integer(at);need(at>=highWater,'host_wake_receiving_unavailable',503);highWater=at;return at;}catch(error){closed=true;throw error;}};
 async function issuerFor(i:PrivateIntake):Promise<IssuerRow>{
  const s=await i.window.run(()=>store.issuer(i.input.authorization_id,i.input.core_purpose_id));need(s,'host_wake_history_unknown',404);need(s.issuer_operation_id===i.input.issuer_operation_id,'host_wake_header_body_scope',403);return s;
 }
 async function publicState(i:PrivateIntake,s:IssuerRow):Promise<PrivateState>{
  const a=await i.window.run(()=>store.authorization(s.authorization_id));
  if(a?.outcome==='withdrawn'||s.outcome==='withdrawn')return 'withdrawn';
  if((s.outcome==='reserved'&&s.original_request_expires_at<=i.window.check())||s.outcome==='expired'||s.expires_at<=i.window.check()||a?.outcome==='expired'||(a&&a.expires_at<=i.window.check()))return 'expired';
  if(!await i.window.run(()=>store.isLive(s.authorization_id,i.principal.id,i.window.check())))return 'unknown';
  return s.outcome==='issued'?'issued':s.outcome==='reserved'?'pending':'unknown';
 }
 async function privateRoute(request:Request):Promise<Response>{
  let intake:PrivateIntake|undefined,backend:Awaited<ReturnType<typeof bindSource181>>|undefined,s:IssuerRow|undefined,ownIssuerClaim:string|undefined,proofClaim:string|undefined,job:NativeJobRow|undefined;
  try{
   intake=await receivePrivate(request,env,clock,capacity);const i=intake,w=i.window,input=i.input;
   const hash=i.intent?.request_hash??await w.run(()=>sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST',SERVER_PREFIX+i.route,input])));need(hash);
   if(i.route==='issuer/withdraw'){
    // Negative authority depends on the actual selected principal/role, never
    // on recovering a capability, creating a new native proof or provider key.
    const before=await w.run(()=>store.issuer(input.authorization_id,input.core_purpose_id));if(before)need(before.issuer_operation_id===input.issuer_operation_id,'host_wake_header_body_scope',403);
    need(await w.run(()=>store.withdrawIssuer(input.authorization_id,input.core_purpose_id,i.principal.id)),'host_wake_receiving_unavailable',503);
    s=await issuerFor(i);const o=decodeNativeOriginal(JSON.parse(s.original_json));const reply=await decodePrivateReply(i.route,input,o,hash,privateBase(input,o,hash,'withdrawn'));w.check();return json(reply);
   }
   if(i.route==='issuer/issue'){
    await requireReceivingGuards(db,w);const auth=await w.run(()=>store.authorization(input.authorization_id));need(auth,'host_wake_native_authority',403);const native=await loadNativeState(db,decodeOperatorAuthorization(JSON.parse(auth.authorization_json)),env,w,input.original);const claim=crypto.randomUUID();ownIssuerClaim=claim;s=await w.run(()=>store.reserveIssuer(input.authorization_id,i.principal.id,input.issuer_operation_id,hash,input.original!,crypto.randomUUID(),claim,w.capturedAt,w.check(),native.kind));
    need(s.claim_id===claim&&s.outcome==='reserved','host_wake_issuer_consumed',409);
    backend=await w.run(()=>bindSource181(env,s!,i.principal.id,w,fetcher,capacity));const issued=await w.run(()=>backend!.service.issueOriginal(undefined,w.signal));
    await w.run(()=>store.finishIssuer(s!.authorization_id,s!.core_purpose_id,'issued',w.check(),claim,hash,i.principal.id));s=await issuerFor(i);need(s.outcome==='issued'&&s.claim_id===claim,'host_wake_issuer_consumed',409);await backend.assertLocal();need(await w.run(()=>db.prepare("SELECT 1 FROM host_wake_issuer_once WHERE authorization_id=? AND core_purpose_id=? AND claim_id=? AND outcome='issued' AND expires_at>?").bind(s!.authorization_id,s!.core_purpose_id,claim,w.check()).first()),'host_wake_issuer_consumed',409);
    const o=decodeNativeOriginal(JSON.parse(s.original_json)),reply=await decodePrivateReply(i.route,input,o,hash,{...privateBase(input,o,hash,'issued'),purpose_id:s.private_purpose_id,credential_state:'available',credential:issued.credential,expires_at_ms:issued.expires_at_ms,native_proof_kind:backend.proofKind,registration_mode:'single_original_no_rotation',original:o});
    await w.run(()=>store.finishIntent(i.intent!,'completed'));w.check();return json(reply);
   }
   s=await issuerFor(i);const o=decodeNativeOriginal(JSON.parse(s.original_json)),state=await publicState(i,s);
   if(i.route==='issuer/status'){const reply=await decodePrivateReply(i.route,input,o,hash,{...privateBase(input,o,hash,state),purpose_id:s.private_purpose_id,credential_state:'unavailable'});w.check();return json(reply);}
   if(i.route==='native/challenge'){
    need(state==='issued','host_wake_native_authority',403);await requireReceivingGuards(db,w);backend=await w.run(()=>bindSource181(env,s!,i.principal.id,w,fetcher,capacity));
    const challenge=decodeNativeChallenge({challenge_id:input.challenge_id,nonce_b64url:base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer),captured_at_ms:w.capturedAt,expires_at_ms:Math.min(w.expiresAt,o.original_wake_expires_at_ms)},o);
    job=await w.run(()=>store.reserveNativeJob(input.authorization_id,i.principal.id,o,challenge,hash,backend!.proofKind,w.check()));need(job.outcome==='reserved'&&job.challenge_json===canonical(challenge),'host_wake_native_job_consumed',409);
    const data=nativeSigningData(o,challenge),digest=await w.run(()=>sha256Hex(new TextDecoder().decode(data.client_data)));
    const reply=await decodePrivateReply(i.route,input,o,hash,{...privateBase(input,o,hash,'pending'),native_proof_kind:job.proof_kind,original:o,challenge,canonical_transcript_utf8:data.canonical_utf8,client_data_sha256:digest},job.proof_kind);
    await w.run(()=>store.finishIntent(i.intent!,'completed'));w.check();return json(reply);
   }
   job=(await w.run(()=>store.nativeJob(input.challenge_id!)))??undefined;need(job&&job.authorization_id===input.authorization_id&&job.core_purpose_id===input.core_purpose_id&&job.original_json===s.original_json,'host_wake_history_unknown',404);
   if(i.route==='native/complete'){
    need(state==='issued'&&job.proof_kind===s.native_proof_kind&&job.proof_kind===input.native_proof!.kind,'host_wake_native_authority',403);await requireReceivingGuards(db,w);backend=await w.run(()=>bindSource181(env,s!,i.principal.id,w,fetcher,capacity));proofClaim=crypto.randomUUID();
    need(await w.run(()=>store.claimNativeProof(input.authorization_id,i.principal.id,input.challenge_id!,input.native_proof!.kind,proofClaim!,w.check())),'host_wake_native_job_consumed',409);
    const first=input.native_proof!.kind==='app_attest_attestation',proof=first?await verifySavedAttestation(db,env,input.authorization_id,i.principal.id,input.challenge_id!,proofClaim,input.native_proof!,w,fetcher,capacity):await verifySavedAssertion(db,input.authorization_id,i.principal.id,input.challenge_id!,proofClaim,input.native_proof!,w);
    if(!proof){await store.failNativeProof(input.authorization_id,input.challenge_id!,proofClaim,'rejected');need(false,'host_wake_native_proof_rejected',403);}
    need(await (proof.kind==='host_wake_first_attestation_crypto_only'?commitVerifiedAttestation(proof,w):commitVerifiedAssertion(proof,w)),'host_wake_native_authority',403);job=(await w.run(()=>store.nativeJob(input.challenge_id!)))!;
   }
   let result:PrivateState=state==='withdrawn'||job.outcome==='withdrawn'?'withdrawn':state==='expired'?'expired':state!=='issued'?'unknown':'pending';let verifiedAt:number|undefined;
   if(result==='pending'&&job.outcome==='verified'){
    // Historical proof status supplies no new registration permission; still
    // require the actual current key/operator/config and durable original job.
    backend??=await w.run(()=>bindSource181(env,s!,i.principal.id,w,fetcher,capacity));await backend.assertLocal();
    const v=await w.run(()=>db.prepare(`SELECT v.verified_at FROM host_wake_native_verifications v JOIN host_wake_native_enrollments n ON n.native_key_ref=v.native_key_ref JOIN host_wake_native_jobs j ON j.challenge_id=v.challenge_id AND j.private_job_id=v.private_job_id JOIN host_wake_issuer_once s ON s.authorization_id=j.authorization_id AND s.core_purpose_id=j.core_purpose_id JOIN host_wake_operator_authorizations a ON a.authorization_id=s.authorization_id JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id WHERE s.outcome='issued' AND j.outcome='verified' AND a.outcome='authorized' AND i.disabled=0 AND s.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND a.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND v.challenge_id=? AND v.private_job_id=? AND v.original_json=? AND v.verified_at>=? AND v.verified_at<? AND n.disabled=0 AND n.counter>=v.verified_counter AND n.expires_at>?`).bind(job!.challenge_id,job!.private_job_id,s!.original_json,job!.captured_at,job!.expires_at,w.check()).first<{verified_at:number}>());
    if(v){result='native_verified';verifiedAt=v.verified_at;}else result='unknown';
   }else if(result==='pending'&&(job.outcome==='unknown'||job.outcome==='rejected'))result='unknown';
   else if(result==='pending'&&(job.outcome==='expired'||job.expires_at<=w.check()))result='expired';
   const reply=await decodePrivateReply(i.route,input,o,hash,{...privateBase(input,o,hash,result),challenge_id:input.challenge_id,native_proof_kind:job.proof_kind,original_sha256:await w.run(()=>sha256Hex(canonical(o))),...(result==='native_verified'?{native_verified_at_ms:verifiedAt}:{})},job.proof_kind);
   if(i.intent)await w.run(()=>store.finishIntent(i.intent!,'completed'));w.check();return json(reply);
  }catch(error){
   // Preserve durable UNKNOWN after interrupted SQL/crypto; never recover a
   // one-time capability or retry the original effect from a fresh request.
   if(intake){if(proofClaim&&job)try{await store.failNativeProof(job.authorization_id,job.challenge_id,proofClaim,'unknown');}catch{}
    if(s?.outcome==='reserved'&&ownIssuerClaim===s.claim_id)try{await store.finishIssuer(s.authorization_id,s.core_purpose_id,'unknown',Math.max(s.accepted_at,highWater),s.claim_id,s.request_hash,intake.principal.id);}catch{}
    if(intake.intent)try{await store.finishIntent(intake.intent,'unknown');}catch{}}
   throw error;
  }finally{backend?.close();intake?.close();}
 }
 async function operator(request:Request,kind:'authorize'|'withdraw'|'native_policy'|'native_policy_withdraw'){
  const w=new RequestWindow(clock,request.signal);try{
   const u=new URL(request.url);need(request.method==='POST'&&u.protocol==='https:'&&!request.url.includes('?')&&!request.url.includes('#'),'host_wake_operator_route',404);
   const {raw}=await readBoundedPrivateBody(request,w);const body=await w.run(()=>authenticateOperator(new Request(request.url,{method:request.method,headers:request.headers,body:raw,signal:w.signal}),env,kind));w.check();
   if(body.action==='native_policy'){const hash=await w.run(()=>sha256Hex(canonical(body))),row=await w.run(()=>authorizeNativePolicy(db,body,hash,w.capturedAt,w.check(),capacity));w.check();return json({version:RECEIVING_VERSION,native_key_ref:row.native_key_ref,outcome:row.outcome});}
   if(body.action==='native_policy_withdraw'){await w.run(()=>withdrawNativePolicy(db,body.native_key_ref,capacity));w.check();return json({version:RECEIVING_VERSION,native_key_ref:body.native_key_ref,outcome:'withdrawn'});}
   if(body.action==='withdraw'){need(await w.run(()=>store.authorization(body.authorization_id)),'host_wake_history_unknown',404);await w.run(()=>store.withdrawAuthorization(body.authorization_id));w.check();return json({version:RECEIVING_VERSION,authorization_id:body.authorization_id,outcome:'withdrawn'});}
   need(body.action==='authorize');const hash=await w.run(()=>sha256Hex(canonical(body)));const row=await w.run(()=>store.authorize(body,hash,w.capturedAt,w.check()));w.check();return json({version:RECEIVING_VERSION,authorization_id:row.authorization_id,outcome:row.outcome});
  }finally{w.close();}
 }
 return Object.freeze({close(){closed=true;},async handle(request:Request):Promise<Response>{try{
  clock();const path=new URL(request.url).pathname;
  if(path===RESOLVE_PATH)return json(await resolveAuthorization(request,env,clock));
  if(path===OPERATOR_AUTHORIZE||path===OPERATOR_WITHDRAW||path===OPERATOR_NATIVE_POLICY||path===OPERATOR_NATIVE_WITHDRAW)return await operator(request,path===OPERATOR_AUTHORIZE?'authorize':path===OPERATOR_WITHDRAW?'withdraw':path===OPERATOR_NATIVE_POLICY?'native_policy':'native_policy_withdraw');
  if(['register','wake','status','revoke'].some(kind=>path===SERVER_PREFIX+kind))return await receiveTarget(request,env,clock,fetcher,capacity);
  return await privateRoute(request);
 }catch(error){return error instanceof WakeError||error instanceof HttpError?privateError(error.code,error.status):privateError('host_wake_receiving_unavailable',503);}}});
}
