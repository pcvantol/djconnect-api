// SHARED CANDIDATE INTERNAL: compiled product auth remains disabled; no native/production acceptance.
import {CommonStatusCache,prepareCommonStatusRequest} from './receipt-status-candidate.mjs';
const MAX_BYTES=65536,TIMEOUT_MS=4000;
const unavailable=()=>({ok:false,error:'status_unavailable'});
const clone=v=>{if(!(v instanceof Uint8Array)||!v.length||v.length>8192)throw new Error('status_unavailable');return v.slice();};
const hex=v=>[...v].map(x=>x.toString(16).padStart(2,'0')).join('');
const hash=async v=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',v)));
async function readLimited(response,signal){
 if(signal.aborted){response.body?.cancel().catch(()=>{});throw new Error('status_unavailable');}
 const length=response.headers.get('content-length');
 if(length!==null&&(!/^(0|[1-9][0-9]*)$/.test(length)||Number(length)>MAX_BYTES))throw new Error('status_unavailable');
 if(!response.body)throw new Error('status_unavailable');
 const reader=response.body.getReader(),chunks=[];let size=0;
 const cancel=()=>{reader.cancel().catch(()=>{});};signal.addEventListener('abort',cancel,{once:true});
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>MAX_BYTES)throw new Error('status_unavailable');chunks.push(value);}}
 finally{signal.removeEventListener('abort',cancel);cancel();}
 if(!size)throw new Error('status_unavailable');const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return bytes;
}
export class CommonStatusClient{
 #slots=new Map();#active=new Map();#notBefore=new Map();#fetch;#prepare;
 // Injection exists only for isolated tests. Production adoption requires its own review.
 constructor(fetcher=globalThis.fetch,prepare=prepareCommonStatusRequest){this.#fetch=fetcher;this.#prepare=prepare;}
 async check(kind,cert,issuer,root){
  try{
   cert=clone(cert);issuer=clone(issuer);root=clone(root);
   // Authenticate common certificate roles BEFORE emitting any CertID. No client URI/AIA dereference.
   const request=await this.#prepare(kind,cert,issuer,root);if(!request)return unavailable();
   const key=JSON.stringify([kind,await hash(cert),await hash(issuer),await hash(root)]);
   if(!['issuer-crl','issuer-ocsp','signer-ocsp'].includes(request.role))return unavailable();
   const slot=this.#slots.get(request.role);
   if(slot?.key===key){const cached=await slot.cache.get(kind,cert,issuer,root);if(cached)return {ok:true,source:'cache',...cached};}
   const active=this.#active.get(request.role);
   if(active)return active.key===key?{...await active.promise}:unavailable();
   if(Date.now()<(this.#notBefore.get(request.role)??0))return unavailable();
   this.#notBefore.set(request.role,Date.now()+2000);
   const operation={key,promise:null};this.#active.set(request.role,operation);
   operation.promise=this.#load(request,kind,cert,issuer,root).then(result=>{
    if(!result||this.#active.get(request.role)!==operation)return unavailable();
    this.#slots.set(request.role,{key,cache:result.cache});return {ok:true,source:'network',...result.status};
   }).finally(()=>{if(this.#active.get(request.role)===operation)this.#active.delete(request.role);});
   return {...await operation.promise}; // One active operation per fixed role, independent of tuple changes.
  }catch{return unavailable();}
 }
 async #load(request,kind,cert,issuer,root){
  const controller=new AbortController(),deadline=Date.now()+TIMEOUT_MS;let timer;
  const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error('status_unavailable'));},TIMEOUT_MS);});
  const work=async()=>{
   const headers={accept:request.accept};if(request.method==='POST')headers['content-type']='application/ocsp-request';
   const response=await this.#fetch(request.url,{method:request.method,body:request.body,headers,redirect:'manual',credentials:'omit',referrerPolicy:'no-referrer',cache:'no-store',signal:controller.signal});
   if(response.status!==200||response.redirected||response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!==request.accept){response.body?.cancel().catch(()=>{});throw new Error('status_unavailable');}
   const body=await readLimited(response,controller.signal),cache=new CommonStatusCache();
   if(controller.signal.aborted||!(await cache.put(kind,body,cert,issuer,root)))throw new Error('status_unavailable');
   const status=await cache.get(kind,cert,issuer,root);if(!status)throw new Error('status_unavailable');
   return {cache,status};
  };
  try{
   const result=await Promise.race([work(),timeout]);
   if(controller.signal.aborted||Date.now()>=deadline)throw new Error('status_unavailable');
   return result;
  }catch{return null;}
  finally{clearTimeout(timer);controller.abort();}
 }
}
