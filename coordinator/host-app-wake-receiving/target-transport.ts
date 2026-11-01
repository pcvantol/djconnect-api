/** Private Core transport of unchanged Source181 bodies and success replies.
 * This module does not activate a public route or create a native enrollment. */
import type {AppEnv} from '../../src/types';
import {sha256Hex} from '../../src/crypto';
import {canonical} from '../../src/surface-push/wire';
import {WakeStore,type Row,type Operation} from '../host-app-wake/store';
import {decode,exact,id,integer,need,WakeError,type Input,type Kind,VERSION} from '../host-app-wake/wire';
import {RequestWindow} from './request-window';
import {authenticateCore} from './principal';
import {privateScopeHeaders,readBoundedPrivateBody} from './private-intake';
import {ReceivingStore,type IntentRow} from './receiving-store';
import {decodeNativeOriginal,nativeTokenSha256,type NativeOriginalData} from './wire';
import {requireReceivingGuards} from './guard-schema';
import {bindSource181} from './source-backend';
import {SERVER_PREFIX} from './server-wire';
export const TARGET_CAPABILITY_HEADER='x-djconnect-host-wake-capability';
export const TARGET_OPERATION_HEADER='x-djconnect-host-wake-operation-id';
export const TARGET_REQUEST_HASH_HEADER='x-djconnect-host-wake-request-sha256';
/** Duplicate HTTP header values are combined with a comma by Headers; the
 * exact digest grammar rejects that representation as well as missing values. */
export function checkTargetCorrelation(value:string|null,expected:string){
 need(typeof value==='string'&&/^[a-f0-9]{64}$/.test(value)&&/^[a-f0-9]{64}$/.test(expected)&&value===expected);
}
export function targetKind(request:Request):Kind{
 const u=new URL(request.url),kind=u.pathname.startsWith(SERVER_PREFIX)?u.pathname.slice(SERVER_PREFIX.length):'';
 need(request.method==='POST'&&u.protocol==='https:'&&!request.url.includes('?')&&!request.url.includes('#')&&['register','wake','status','revoke'].includes(kind),'host_wake_receiving_route',404);
 for(const h of ['origin','cookie','x-djconnect-device-id','x-djconnect-client-type'])need(!request.headers.has(h),'host_wake_server_transport',403);
 return kind as Kind;
}
/** DATA-only success decoder. Core must separately join the response header to
 * its own exact private request and retain its own original child/once fences.
 * Historical operation_state=registered cannot override state=withdrawn. */
export function decodeTargetReply(value:unknown,input:Input,original:Readonly<NativeOriginalData>,privatePurpose:string){
 need(value!==null&&typeof value==='object'&&!Array.isArray(value));const v=value as Record<string,unknown>;
 need(input.purpose_id===privatePurpose&&v.purpose_id===privatePurpose&&v.operation_id===input.operation_id&&v.version===VERSION);
 if(!Object.hasOwn(v,'state')){exact(v,['version','purpose_id','operation_id','operation_state']);need(v.operation_state==='unknown');return Object.freeze({...v});}
 exact(v,['version','purpose_id','operation_id','state','generation','revision','expires_at_ms','transport_expires_at_ms','operation_state','provider_status']);
 need(['withdrawn','expired','registered','unregistered'].includes(v.state as string));need(v.expires_at_ms===original.original_wake_expires_at_ms);
 need((v.generation===null&&v.revision===0)||(v.generation===original.generation&&v.revision===original.revision));
 need(v.state!=='registered'||v.generation===original.generation);need(['unknown','registered','conflict','expired','provider_accepted','provider_rejected','not_sent'].includes(v.operation_state as string));
 if(v.transport_expires_at_ms!==null)integer(v.transport_expires_at_ms,original.original_wake_issued_at_ms,original.original_wake_expires_at_ms);
 if(v.provider_status!==null)integer(v.provider_status,100,599);
 return Object.freeze({...v});
}
function receipt(r:Row,op:Operation|null,operation:string,at:number){
 return {version:VERSION,purpose_id:r.purpose_id,operation_id:operation,state:r.withdrawn?'withdrawn':at>=r.expires_at?'expired':r.ciphertext?'registered':'unregistered',generation:r.generation,revision:r.revision,expires_at_ms:r.expires_at,transport_expires_at_ms:op?.kind==='wake'?op.expires_at:null,operation_state:op?.outcome==='dispatch_started'||op?.outcome==='reserved'?'unknown':op?.outcome??'unknown',provider_status:op?.provider_status??null};
}
export async function receiveTarget(request:Request,env:AppEnv,now:()=>number,fetcher:typeof fetch,capacity:number,originalCapture?:number):Promise<Response>{
 const window=new RequestWindow(now,request.signal,originalCapture),db=env.DB,store=new ReceivingStore(db,capacity),source=new WakeStore(db);let intent:IntentRow|undefined,backend:Awaited<ReturnType<typeof bindSource181>>|undefined;
 try{
  const kind=targetKind(request),scope=privateScopeHeaders(request),cap=request.headers.get(TARGET_CAPABILITY_HEADER);need(cap&&/^djchw_[A-Za-z0-9_-]{43}$/.test(cap),'host_wake_core_auth',401);
  const positive=kind==='register'||kind==='wake';let operation:string|undefined;
  if(positive){operation=request.headers.get(TARGET_OPERATION_HEADER)??undefined;id(operation);}else need(!request.headers.has(TARGET_OPERATION_HEADER));
  const principal=await authenticateCore(request,db,window),a=await window.run(()=>store.authorization(scope.authorization_id));need(a&&a.core_install_token_record_id===principal.id&&a.ha_install_id===principal.ha_install_id,'host_wake_principal_scope',403);
  const issuer=await window.run(()=>store.issuer(scope.authorization_id,scope.core_purpose_id));need(issuer&&issuer.issuer_operation_id===scope.issuer_operation_id,'host_wake_history_unknown',404);
  const original=decodeNativeOriginal(JSON.parse(issuer.original_json));
  // Existing djci remains Authorization; the separate one-time capability is
  // matched to this SAME issuer's private purpose before body/intent allocation.
  const authenticated=await window.run(async()=>{try{return await source.authenticate('Bearer '+cap,issuer.private_purpose_id);}catch(error){if(error instanceof WakeError&&error.code==='host_wake_auth')throw new WakeError('host_wake_core_auth',401);throw error;}});
  if(positive){
   need(issuer.outcome==='issued'&&!authenticated.withdrawn&&issuer.expires_at>window.check()&&await window.run(()=>store.isLive(scope.authorization_id,principal.id,window.check())),'host_wake_native_authority',403);
   const claim=crypto.randomUUID(),row=await window.run(()=>store.reserveIntent(scope.authorization_id,principal.id,scope.core_purpose_id,scope.issuer_operation_id,'target/'+kind+'/'+operation,claim,window.capturedAt,window.check()));
   need(row.claim_id===claim&&row.outcome==='reserved','host_wake_intent_consumed',409);intent=Object.freeze(row);
  }
  const body=await readBoundedPrivateBody(request,window);need(body.raw.byteLength<=8192,'host_wake_size',413);const input=decode(kind,body.value);need(input.purpose_id===issuer.private_purpose_id&&(!positive||input.operation_id===operation),'host_wake_header_body_scope',403);
  const requestHash=await window.run(()=>sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST',SERVER_PREFIX+kind,input])));
  if(intent){need(await window.run(()=>store.bindIntent(intent!,requestHash,window.check())),'host_wake_intent_consumed',409);intent=Object.freeze({...intent,request_hash:requestHash});}
  // Single original registration: a changed target-token or revision cannot
  // silently enter Source181's standalone rotation path or recover a lost ACK.
  if(positive){
   let matches=input.generation===original.generation&&input.revision===original.revision;
   if(kind==='register')matches=matches&&input.operation_id===original.operation_id&&canonical(input.target)===canonical(original.target)&&input.apns_environment===original.apns_environment&&await window.run(()=>nativeTokenSha256(Uint8Array.from(input.apns_token!.match(/../g)!,v=>parseInt(v,16))))===original.native_token_sha256;
   if(!matches){await window.run(()=>store.withdrawIssuer(scope.authorization_id,scope.core_purpose_id,principal.id));need(false,'host_wake_original_scope',403);}
  }
  let value:unknown,status=200;
  if(kind==='revoke'){
   need(await window.run(()=>store.withdrawIssuer(scope.authorization_id,scope.core_purpose_id,principal.id)),'host_wake_receiving_unavailable',503);
   const row=await window.run(()=>source.row(issuer.private_purpose_id)),op=await window.run(()=>source.operation(row.purpose_id,input.operation_id));value=receipt(row,op,input.operation_id,window.check());
  }else{
   const row=await window.run(()=>source.row(issuer.private_purpose_id));
   if(kind==='status'&&(row.withdrawn||row.expires_at<=window.check()||!row.ciphertext)){
    const op=await window.run(()=>source.operation(row.purpose_id,input.operation_id));value=receipt(row,op,input.operation_id,window.check());
   }else{
    await requireReceivingGuards(db,window);backend=await window.run(()=>bindSource181(env,issuer,principal.id,window,fetcher,capacity));
    if(kind==='status')need(await window.run(()=>db.prepare(`SELECT 1 FROM host_wake_current_verified_targets e WHERE e.private_purpose_id=? AND e.consumed_at IS NOT NULL AND EXISTS(SELECT 1 FROM host_app_wake_operations r WHERE r.purpose_id=e.private_purpose_id AND r.operation_id=e.semantic_operation_id AND r.outcome='registered' AND r.claim_id=e.register_claim_id)`).bind(issuer.private_purpose_id).first()),'host_wake_native_authority',403);
    const response=await window.run(()=>backend!.service.handle(new Request(request.url,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+cap},body:body.raw,signal:window.signal})));
    status=response.status;value=await window.run(()=>response.json());
    if(!response.ok){const code=value&&typeof value==='object'&&(value as Record<string,unknown>).error;need(false,typeof code==='string'?code:'host_wake_receiving_unavailable',status);}
   }
  }
  const reply=decodeTargetReply(value,input,original,issuer.private_purpose_id);
  if(kind==='revoke')need(reply.state==='withdrawn','host_wake_receiving_unavailable',503);
  if(kind==='wake'&&reply.transport_expires_at_ms!==undefined&&reply.transport_expires_at_ms!==null)need((reply.transport_expires_at_ms as number)<=window.expiresAt);
  if(intent)await window.run(()=>store.finishIntent(intent!,'completed'));window.check();
  return new Response(JSON.stringify(reply),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff',[TARGET_REQUEST_HASH_HEADER]:requestHash}});
 }catch(error){if(intent)try{await store.finishIntent(intent,'unknown');}catch{}throw error;}
 finally{backend?.close();window.close();}
}
