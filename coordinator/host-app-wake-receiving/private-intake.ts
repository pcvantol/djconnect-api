/** Concrete prebody Core auth + SQL-once + bounded private HTTP decoding.
 * No positive native/provider handler or admission factory is produced here. */
import type {AppEnv} from '../../src/types';
import {sha256Hex} from '../../src/crypto';
import {canonical,parseStrictJson} from '../../src/surface-push/wire';
import {id,need} from '../host-app-wake/wire';
import {authenticateCore} from './principal';
import {RequestWindow} from './request-window';
import {ReceivingStore,type IntentRow} from './receiving-store';
import {decodeServer,serverRoute,SERVER_PREFIX,type ServerInput,type ServerRoute} from './server-wire';
const fields={authorization_id:'x-djconnect-host-wake-authorization-id',core_purpose_id:'x-djconnect-host-wake-core-purpose-id',issuer_operation_id:'x-djconnect-host-wake-issuer-operation-id'} as const;
export function privateScopeHeaders(request:Request){
 const out={} as {authorization_id:string;core_purpose_id:string;issuer_operation_id:string};
 for(const key of Object.keys(fields) as (keyof typeof fields)[]){const value=request.headers.get(fields[key]);id(value);out[key]=value;}
 return Object.freeze(out);
}
function strictIntegerJson(text:string){
 // Keep the old shared parser unchanged. Check numeric lexemes before JS can
 // normalize 1.0/1e0/-0, and bound actual nesting independently of value shape.
 let quoted=false,escaped=false,depth=0;
 for(let at=0;at<text.length;at++){
  const ch=text[at];if(quoted){if(escaped){escaped=false;continue;}if(ch==='\\'){escaped=true;continue;}if(ch==='"')quoted=false;continue;}
  if(ch==='"'){quoted=true;continue;}if(ch==='{'||ch==='['){need(++depth<=8);continue;}if(ch==='}'||ch===']'){depth--;continue;}
  if(ch==='-'||/[0-9]/.test(ch)){const token=/^[^\s,}\]]+/.exec(text.slice(at))![0];need(/^(?:0|[1-9][0-9]*)$/.test(token)&&Number.isSafeInteger(Number(token)));at+=token.length-1;}
 }
 return parseStrictJson(text);
}
export async function readBoundedPrivateBody(request:Request,window:RequestWindow){
 need(request.headers.get('content-type')?.trim().toLowerCase()==='application/json','host_wake_media',415);need(!request.headers.has('content-encoding'));
 const bodyEnd=window.capturedAt+10000;need(window.check()<bodyEnd,'host_wake_body_timeout',409);
 const stage=new AbortController(),timer=setTimeout(()=>stage.abort(),Math.max(1,bodyEnd-window.check()));
 const reader=request.body?.getReader();need(reader);const chunks:Uint8Array[]=[];let size=0;
 try{
  for(;;){const part=await window.run(()=>reader.read(),stage.signal);need(window.check()<bodyEnd,'host_wake_body_timeout',409);if(part.done)break;size+=part.value.byteLength;need(size<=16384,'host_wake_size',413);chunks.push(part.value);}
  const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}
  return {value:strictIntegerJson(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw)),raw};
 }catch(e){void reader.cancel().catch(()=>{});throw e;}finally{clearTimeout(timer);reader.releaseLock();}
}
export interface PrivateIntake {route:ServerRoute;input:Readonly<ServerInput>;principal:Readonly<{id:string;ha_install_id:string}>;window:RequestWindow;intent:IntentRow|null;close():void}
/** The owner must finish the returned intent exactly once and close its window.
 * Missing/invalid identity never reserves an intent. Every mutation after intake
 * must recheck the original window and its own atomic SQL eligibility. */
export async function receivePrivate(request:Request,env:AppEnv,now:()=>number,capacity:number):Promise<PrivateIntake>{
 const db=env.DB,store=new ReceivingStore(db,capacity),window=new RequestWindow(now,request.signal);let intent:IntentRow|null=null;
 try{
  const route=serverRoute(request),scope=privateScopeHeaders(request),principal=await authenticateCore(request,db,window);
  const auth=await window.run(()=>store.authorization(scope.authorization_id));need(auth&&auth.core_install_token_record_id===principal.id&&auth.ha_install_id===principal.ha_install_id,'host_wake_principal_scope',403);
  const mutation=route!=='issuer/status'&&route!=='native/status'&&route!=='issuer/withdraw';
  if(mutation){const claim=crypto.randomUUID();const candidate=await window.run(()=>store.reserveIntent(scope.authorization_id,principal.id,scope.core_purpose_id,scope.issuer_operation_id,route,claim,window.capturedAt,window.check()));need(candidate.claim_id===claim&&candidate.outcome==='reserved','host_wake_intent_consumed',409);intent=Object.freeze(candidate);}
  const input=decodeServer(route,(await readBoundedPrivateBody(request,window)).value);for(const key of Object.keys(fields) as (keyof typeof fields)[])need(input[key]===scope[key],'host_wake_header_body_scope',403);
  if(intent){const hash=await window.run(()=>sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST',SERVER_PREFIX+route,input])));need(await window.run(()=>store.bindIntent(intent!,hash,window.check())),'host_wake_intent_consumed',409);intent=Object.freeze({...intent,request_hash:hash});}
  return Object.freeze({route,input,principal,window,intent,close(){window.close();}});
 }catch(e){if(intent)try{await store.finishIntent(intent,'unknown');}catch{/* UNKNOWN remains unrecoverable; never run a positive action here. */}window.close();throw e;}
}
