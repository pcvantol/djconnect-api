import {base64Url,sha256Hex} from '../../src/crypto';
import {seal,unseal} from '../../src/surface-push/crypto';
import {BODY,PREFIX,VERSION,canonical,integer,need,original,read,WakeError,type Input,type Kind,type OriginalPurpose} from './wire';
import {WakeStore,type Row,type Operation} from './store';
export interface WakePorts {
 db:D1Database;
 /** Server-only original-proof verifier. No implementation/default trust or
  * public issue route is supplied by this source candidate. Must return a stable
  * original purpose identity, never a client operation UUID reminted as purpose. */
 admitOriginalPurpose(attempt:unknown,signal:AbortSignal):Promise<OriginalPurpose>;
 /** Genuine separately authenticated host-app token observation/enrollment.
  * A structurally valid client token or possession of a capability is not
  * proof that the token came from the admitted native installation. */
 admitNativeRegistration(purpose:OriginalPurpose,input:Input,signal:AbortSignal):Promise<void>;
 /** Actual original scope/custody/clock-continuity/current owner check, mandatory
  * on issue and every active request. Returning a promise or boolean is refused. */
 assertCurrent(purpose:OriginalPurpose):void;
 now():number;
 encryptionKey():string;
 authorizeProvider():Promise<string>;
 fetcher:typeof fetch;
 /** Selected server capacity, no eviction or implicit renewal. */
 capacity:number;
}
const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'};
const json=(v:unknown,status=200)=>new Response(JSON.stringify(v),{status,headers});
function aad(p:OriginalPurpose,generation:string,revision:number):string{return canonical([VERSION,'host-token',p,generation,revision]);}
/** Explicit-port SOURCE ONLY: not imported by src/index or surface composition. */
export function createHostAppWakeService(ports:WakePorts){
 need(ports&&typeof ports==='object','host_wake_ports',503);
 const {db,admitOriginalPurpose:admit,admitNativeRegistration:nativeRegistration,assertCurrent:assert,now:time,encryptionKey:key,authorizeProvider:authorize,fetcher,capacity}=ports;
 need(db&&[admit,nativeRegistration,assert,time,key,authorize,fetcher].every(v=>typeof v==='function'),'host_wake_ports',503);integer(capacity,1,4096);
 const store=new WakeStore(db);let closed=false,highWater=0;
 const clock=()=>{
  need(!closed,'host_wake_closed',503);
  if(ports.db!==db||ports.admitOriginalPurpose!==admit||ports.admitNativeRegistration!==nativeRegistration||ports.assertCurrent!==assert||ports.now!==time||ports.encryptionKey!==key||ports.authorizeProvider!==authorize||ports.fetcher!==fetcher||ports.capacity!==capacity){closed=true;throw new WakeError('host_wake_retired',503);}
  let at:number;try{at=time.call(ports);integer(at);need(at>=highWater,'host_wake_clock',503);}catch(e){closed=true;throw e;}
  highWater=at;return at;
 };
 const guard=(p:OriginalPurpose,signal:AbortSignal)=>{
  need(!signal.aborted,'host_wake_cancelled',409);const at=clock();need(p.issued_at_ms<=at&&at<p.expires_at_ms,'host_wake_expired',409);
  need(assert.call(ports,p)===undefined,'host_wake_authority',503);need(!signal.aborted,'host_wake_cancelled',409);
  const after=clock();need(p.issued_at_ms<=after&&after<p.expires_at_ms,'host_wake_expired',409);return after;
 };
 async function receipt(purpose:string,operation:string){
  const [r,op]=await Promise.all([store.row(purpose),store.operation(purpose,operation)]);const at=clock();
  const state=r.withdrawn?'withdrawn':at>=r.expires_at?'expired':r.ciphertext?'registered':'unregistered';
  return json({version:VERSION,purpose_id:purpose,operation_id:operation,state,generation:r.generation,revision:r.revision,expires_at_ms:r.expires_at,
   transport_expires_at_ms:op?.kind==='wake'?op.expires_at:null,
   operation_state:op?.outcome==='dispatch_started'||op?.outcome==='reserved'?'unknown':op?.outcome??'unknown',provider_status:op?.provider_status??null});
 }
 async function send(p:OriginalPurpose,i:Input,r:Row,op:Operation,signal:AbortSignal){
  const current=()=>{const at=guard(p,signal);need(at<op.expires_at,'host_wake_transport_expired',409);return at;};
  let attempted=false,markerUncertain=false;let outcome='not_sent',status:number|null=null;
  try{
   current();need(r.ciphertext&&r.nonce&&r.generation===i.generation&&r.revision===i.revision);
   const token=await unseal(r.ciphertext,r.nonce,key.call(ports),aad(p,i.generation!,i.revision!));current();
   need(/^(?:[a-f0-9]{2}){16,2048}$/.test(token),'host_wake_configuration',503);
   const auth=await authorize.call(ports);current();
   need(typeof auth==='string'&&auth.length<=8192&&/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(auth),'host_wake_provider',503);
   markerUncertain=true;const marked=await store.mark(p,i,op.claim_id,current());
   if(!marked)return receipt(p.purpose_id,i.operation_id);
   markerUncertain=false;const at=current();
   const url=(p.apns_environment==='sandbox'?'https://api.sandbox.push.apple.com':'https://api.push.apple.com')+'/3/device/'+token;
   const init:RequestInit={method:'POST',headers:{authorization:'bearer '+auth,'apns-push-type':'background','apns-topic':p.target.host_bundle_id,'apns-priority':'5','apns-expiration':String(Math.floor(op.expires_at/1000)),'content-type':'application/json'},body:BODY,redirect:'error',signal:AbortSignal.any([signal,AbortSignal.timeout(Math.max(1,Math.min(10000,op.expires_at-at)))])};
   current();attempted=true;const result=await fetcher.call(ports,url,init);status=result.status;outcome=status===200?'provider_accepted':'provider_rejected';
   if(status===410)await store.invalidate(p.purpose_id,i.generation!,i.revision!);
  }catch{outcome=attempted||markerUncertain?'unknown':'not_sent';}
  try{await store.finish(p.purpose_id,i.operation_id,op.claim_id,outcome,status);}catch{return json({version:VERSION,purpose_id:p.purpose_id,operation_id:i.operation_id,operation_state:'unknown'},202);}
  try{guard(p,signal);}catch{return json({version:VERSION,purpose_id:p.purpose_id,operation_id:i.operation_id,operation_state:'unknown'},202);}
  return receipt(p.purpose_id,i.operation_id);
 }
 return Object.freeze({
  close(){closed=true;},
  async issueOriginal(attempt:unknown,signal:AbortSignal){
   need(signal instanceof AbortSignal&&!signal.aborted,'host_wake_cancelled',409);clock();
   const p=original(await admit.call(ports,attempt,signal));guard(p,signal);
   const credential='djchw_'+base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer);const hash=await sha256Hex(credential);guard(p,signal);
   const issued=await store.issue(p,hash,crypto.randomUUID(),capacity,guard(p,signal));guard(p,signal);
   need(issued,'host_wake_issue_consumed_or_capacity',409);
   return Object.freeze({version:VERSION,purpose_id:p.purpose_id,credential,expires_at_ms:p.expires_at_ms});
  },
  async handle(request:Request):Promise<Response>{
   try{
    const capturedAt=clock();const url=new URL(request.url),kind=url.pathname.startsWith(PREFIX)?url.pathname.slice(PREFIX.length):'';
    need(request.method==='POST'&&['register','wake','revoke','status'].includes(kind)&&!url.search&&!url.hash,'host_wake_route',404);
    need(!request.headers.has('origin')&&!request.headers.has('cookie'),'host_wake_server_transport',403);
    const input=await read(request,kind as Kind);clock();need(!request.signal.aborted,'host_wake_cancelled',409);
    const row=await store.authenticate(request.headers.get('authorization'),input.purpose_id);clock();need(!request.signal.aborted,'host_wake_cancelled',409);
    if(kind==='status')return receipt(input.purpose_id,input.operation_id);
    if(kind==='revoke'){await store.withdraw(input.purpose_id);return receipt(input.purpose_id,input.operation_id);}
    const p=store.scope(row);guard(p,request.signal);need(!row.withdrawn,'host_wake_withdrawn',409);
    const hash=await sha256Hex(canonical([VERSION,kind,input]));guard(p,request.signal);
    const previous=await store.operation(p.purpose_id,input.operation_id);guard(p,request.signal);
    if(previous){need(previous.kind===kind&&previous.request_hash===hash,'host_wake_operation_conflict',409);return receipt(p.purpose_id,input.operation_id);}
    const claim=crypto.randomUUID();
    if(kind==='register'){
     need(canonical(input.target)===canonical(p.target)&&input.token_role===p.token_role&&input.apns_environment===p.apns_environment,'host_wake_scope',403);
     need(await nativeRegistration.call(ports,p,input,request.signal)===undefined,'host_wake_native_registration',503);guard(p,request.signal);
     const sealed=await seal(input.apns_token!,key.call(ports),aad(p,input.generation!,input.revision!));guard(p,request.signal);
     await store.reserve('register',p,input,hash,claim,guard(p,request.signal),p.expires_at_ms,sealed);guard(p,request.signal);
    }else{
     const expiresAt=Math.min(capturedAt+30000,p.expires_at_ms);need(guard(p,request.signal)<expiresAt,'host_wake_transport_expired',409);
     await store.reserve('wake',p,input,hash,claim,capturedAt,expiresAt);guard(p,request.signal);
     const op=await store.operation(p.purpose_id,input.operation_id);guard(p,request.signal);
     if(op?.claim_id===claim&&op.outcome==='reserved')return send(p,input,await store.row(p.purpose_id),op,request.signal);
    }
    return receipt(p.purpose_id,input.operation_id);
   }catch(e){return json({version:VERSION,error:e instanceof WakeError?e.code:'host_wake_unavailable'},e instanceof WakeError?e.status:503);}
  },
 });
}
