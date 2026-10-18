// LOCAL QUALIFICATION ONLY. No public router/allocation or genuine enrollment approval.
import {DurableObject} from 'cloudflare:workers';
import {base64Url,base64Decode} from 'djc-existing-crypto';
import {qualifyBrowserPublicJwk,qualifyCompactJwe,type BrowserPublicJwk} from './jwe-framing';
import {type ProofInput,type SubmitBinding} from './assertion-key-state';
import {type EnrollmentCoordinator} from './enrollment-key-state';
const V='djc-rendezvous/1',POLICY='ios-dev-qualification/1';
type ErrorCode='invalid_request'|'invalid_capability'|'expired'|'cancelled'|'already_consumed'|'already_submitted'|'not_ready'|'operation_conflict'|'invalid_sender_proof'|'service_unavailable'|'rate_limited';
const fail=(code:ErrorCode):never=>{throw new Failure(code);};
class Failure extends Error {constructor(readonly code:ErrorCode){super(code);}}
const need:(v:unknown,code?:ErrorCode)=>asserts v=(v,code='invalid_request')=>{if(!v)fail(code);};
const closed=(v:object,keys:string[])=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(','));
const integer=(v:number)=>Number.isSafeInteger(v)&&v>=0;
const uuid=(v:string)=>need(typeof v==='string'&&v.length===36&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v));
function bytes(v:string,max:number,exact?:number){need(typeof v==='string'&&v.length>0&&v.length<=Math.ceil(max*4/3)&&/^[A-Za-z0-9_-]+$/.test(v));const b=Uint8Array.from(atob(v.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(b.length<=max&&(exact===undefined||b.length===exact)&&base64Url(b.buffer)===v);return b;}
const opaque=(v:string)=>bytes(v,32,32);
const sha=async(v:Uint8Array)=>new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const jsonHash=async(v:unknown)=>sha(new TextEncoder().encode(JSON.stringify(v)));
const hex=(v:Uint8Array)=>Array.from(v,b=>b.toString(16).padStart(2,'0')).join('');
const same=(a:string,b:string)=>crypto.subtle.timingSafeEqual(opaque(a).buffer,opaque(b).buffer);
function keyId(v:string){need(typeof v==='string'&&v.length===44);const b=base64Decode(v);need(b.length===32&&btoa(String.fromCharCode(...b))===v);}
export interface Descriptor {id:string;createdAt:number;expiresAt:number}
// A trusted future allocator calls this before routing. Never accept a public descriptor.
export function newTransactionDescriptor():Descriptor {const createdAt=Date.now();return {id:crypto.randomUUID(),createdAt,expiresAt:createdAt+120000};}
export interface CreateTransaction {descriptor:Descriptor;generation:number;browserPublicKey:BrowserPublicJwk;claimCommitment:string}
export interface BrowserInput {transactionId:string;generation:number;claimSecret:string}
export interface ScanInput {transactionId:string;generation:number;qrCapability:string}
export interface SubmitInput extends ScanInput {keyId:string;challengeId:string;clientData:string;assertion:string;destinationEnvelope:string}
export interface TransactionEnv {TRANSACTION_STATE:DurableObjectNamespace;ENROLLMENT_COORDINATOR:DurableObjectNamespace<EnrollmentCoordinator>}
export type Authorizer=(key:string,proof:ProofInput)=>Promise<unknown>;
export function coordinatorAuthorizer(namespace:DurableObjectNamespace<EnrollmentCoordinator>):Authorizer {
  return async(key,proof)=>{keyId(key);const address=hex(await jsonHash(['development',POLICY,key]));return namespace.get(namespace.idFromName('djc-rendezvous-key/1/'+address)).authorize(proof);};
}
interface Row extends Descriptor {generation:number;thumbprint:string;claimCommitment:string;qrCommitment:string;state:'pending'|'ready'|'consumed'|'cancelled';browserPublicKey?:BrowserPublicJwk;envelope?:string;operationId?:string;requestDigest?:string;polls:number;lastPoll?:number}
interface Authorization {ok:true;kind:'submit-authorization';operationId:string;requestDigest:string;admittedAt:number;keyExpiresAt:number;authorizationExpiresAt:number;counter:number;binding:SubmitBinding}
export class TransactionState {
  #ctx:DurableObjectState;#namespace:DurableObjectNamespace;#authorize:Authorizer;#busy=false;#creating=false;
  constructor(ctx:DurableObjectState,namespace:DurableObjectNamespace,authorize:Authorizer){this.#ctx=ctx;this.#namespace=namespace;this.#authorize=authorize;ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS rendezvous_state (id INTEGER PRIMARY KEY CHECK(id=1), expires_at INTEGER NOT NULL, value TEXT NOT NULL)');}
  #load(){return this.#ctx.storage.sql.exec<{value:string}>('SELECT value FROM rendezvous_state WHERE id=1').toArray().map(r=>JSON.parse(r.value) as Row)[0];}
  #save(r:Row){this.#ctx.storage.sql.exec('INSERT INTO rendezvous_state(id,expires_at,value) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at,value=excluded.value',r.expiresAt,JSON.stringify(r));}
  #route(id:string){uuid(id);need(this.#namespace.idFromName(id).equals(this.#ctx.id),'invalid_capability');}
  #row(id:string,generation:number,commitment:string,kind:'claimCommitment'|'qrCommitment'){
    this.#route(id);const r=this.#load();need(r&&r.id===id&&r.generation===generation&&same(r[kind],commitment),'invalid_capability');const now=Date.now();need(now>=r.createdAt&&now<r.expiresAt,'expired');return r;
  }
  #result(error:unknown){return {ok:false as const,v:V,error:error instanceof Failure?error.code:'service_unavailable' as ErrorCode};}
  #accepted(r:Row){return {ok:true as const,v:V,accepted:true as const,operation_id:r.operationId!};}
  async create(input:CreateTransaction){
    if(this.#creating)return this.#result(new Failure('service_unavailable'));this.#creating=true;
    try{
      closed(input,['descriptor','generation','browserPublicKey','claimCommitment']);closed(input.descriptor,['id','createdAt','expiresAt']);
      input={...input,descriptor:{...input.descriptor},browserPublicKey:{...input.browserPublicKey}};const d=input.descriptor;this.#route(d.id);
      need(integer(d.createdAt)&&integer(d.expiresAt)&&d.expiresAt===d.createdAt+120000&&Date.now()>=d.createdAt&&Date.now()<d.expiresAt);need(Number.isInteger(input.generation)&&input.generation>=1&&input.generation<=2147483647);opaque(input.claimCommitment);
      const pub=await qualifyBrowserPublicJwk(input.browserPublicKey);need(pub.ok);const qr=base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer),qrCommitment=base64Url((await sha(opaque(qr))).buffer);
      const alarm=await this.#ctx.storage.getAlarm();await this.#ctx.storage.setAlarm(Math.min(alarm??d.expiresAt,d.expiresAt));
      return this.#ctx.storage.transactionSync(()=>{
        this.#route(d.id);need(Date.now()>=d.createdAt&&Date.now()<d.expiresAt,'expired');need(!this.#load(),'operation_conflict');
        const r:Row={...d,generation:input.generation,thumbprint:pub.thumbprint,browserPublicKey:pub.jwk,claimCommitment:input.claimCommitment,qrCommitment,state:'pending',polls:0};this.#save(r);
        return {ok:true as const,v:V,transaction_id:r.id,generation:r.generation,created_at:r.createdAt,expires_at:r.expiresAt,qr_payload:JSON.stringify({type:'djc-rendezvous-qr',v:V,service_origin:'https://api.djconnect.dev',transaction_id:r.id,generation:r.generation,expires_at:r.expiresAt,browser_key_thumbprint:r.thumbprint,qr_capability:qr})};
      });
    }catch(e){return this.#result(e);}finally{this.#creating=false;}
  }
  async inspect(input:ScanInput){try{closed(input,['transactionId','generation','qrCapability']);input={...input};const commitment=base64Url((await sha(opaque(input.qrCapability))).buffer);return this.#ctx.storage.transactionSync(()=>{const r=this.#row(input.transactionId,input.generation,commitment,'qrCommitment');need(r.state==='pending',r.state==='cancelled'?'cancelled':r.state==='consumed'?'already_consumed':'already_submitted');need(r.browserPublicKey);return {ok:true as const,v:V,browser_public_key:r.browserPublicKey,browser_key_thumbprint:r.thumbprint,generation:r.generation,expires_at:r.expiresAt};});}catch(e){return this.#result(e);}}
  async browser(input:BrowserInput,action:'poll'|'consume'|'cancel'){
    try{
      closed(input,['transactionId','generation','claimSecret']);input={...input};const commitment=base64Url((await sha(opaque(input.claimSecret))).buffer);
      return this.#ctx.storage.transactionSync(()=>{
        const r=this.#row(input.transactionId,input.generation,commitment,'claimCommitment');
        if(action==='poll'){const at=Date.now();need(r.polls<60&&(r.lastPoll===undefined||at-r.lastPoll>=2000),'rate_limited');r.polls++;r.lastPoll=at;this.#save(r);return {ok:true as const,v:V,state:r.state,expires_at:r.expiresAt,retry_after_ms:2000};}
        if(action==='consume'){need(r.state!=='consumed','already_consumed');need(r.state!=='cancelled','cancelled');need(r.state==='ready'&&r.envelope,'not_ready');const envelope=r.envelope;r.state='consumed';delete r.envelope;delete r.browserPublicKey;this.#save(r);return {ok:true as const,v:V,state:'consumed' as const,destination_envelope:envelope,expires_at:r.expiresAt};}
        need(action==='cancel');need(r.state!=='consumed','already_consumed');r.state='cancelled';delete r.envelope;delete r.browserPublicKey;this.#save(r);return {ok:true as const,v:V,state:'cancelled' as const};
      });
    }catch(e){return this.#result(e);}
  }
  async submit(input:SubmitInput){
    if(this.#busy)return this.#result(new Failure('service_unavailable'));this.#busy=true;
    try{
      closed(input,['transactionId','generation','qrCapability','keyId','challengeId','clientData','assertion','destinationEnvelope']);input={...input};need(Number.isInteger(input.generation)&&input.generation>=1&&input.generation<=2147483647);uuid(input.transactionId);keyId(input.keyId);opaque(input.challengeId);bytes(input.clientData,2048);bytes(input.assertion,4096);need(typeof input.destinationEnvelope==='string'&&input.destinationEnvelope.length>0&&input.destinationEnvelope.length<=8192);
      const qrCommitment=base64Url((await sha(opaque(input.qrCapability))).buffer);
      // Private typed-RPC digest binds exact string values, not raw HTTP JSON serialization.
      const requestDigest=hex(await jsonHash([V,'submit',input.transactionId,input.generation,input.qrCapability,input.keyId,input.challengeId,input.clientData,input.assertion,input.destinationEnvelope]));
      const snapshot=this.#ctx.storage.transactionSync(()=>this.#row(input.transactionId,input.generation,qrCommitment,'qrCommitment'));
      if(snapshot.operationId){need(snapshot.operationId===input.challengeId&&snapshot.requestDigest===requestDigest,'already_submitted');return this.#accepted(snapshot);}
      need(snapshot.state==='pending',snapshot.state==='cancelled'?'cancelled':'already_submitted');
      const envelope=await qualifyCompactJwe(input.destinationEnvelope,snapshot.thumbprint);need(envelope.ok);
      const address=hex(await jsonHash(['development',POLICY,input.keyId])),proofDigest=hex(await jsonHash(['submit',input.challengeId,address,input.clientData,input.assertion]));
      const result=await this.#authorize(input.keyId,{operationId:input.challengeId,action:'submit',clientData:input.clientData,assertion:input.assertion}) as Authorization|{ok:false;error:string};
      if(result?.ok===false&&(result.error==='rate_limited'||result.error==='service_unavailable'))fail(result.error);
      need(result?.ok&&result.kind==='submit-authorization','invalid_sender_proof');const auth=structuredClone(result);
      return this.#ctx.storage.transactionSync(()=>{
        const r=this.#row(input.transactionId,input.generation,qrCommitment,'qrCommitment'),now=Date.now();
        if(r.operationId){need(r.operationId===input.challengeId&&r.requestDigest===requestDigest,'already_submitted');return this.#accepted(r);}
        need(r.state==='pending',r.state==='cancelled'?'cancelled':'already_submitted');
        need(r.createdAt===snapshot.createdAt&&r.expiresAt===snapshot.expiresAt&&r.thumbprint===snapshot.thumbprint&&r.claimCommitment===snapshot.claimCommitment,'invalid_sender_proof');
        const b=auth.binding;need(b&&b.transactionId===r.id&&b.generation===r.generation&&b.browserThumbprint===r.thumbprint&&b.envelopeDigest===envelope.envelopeDigest&&b.expiresAt===r.expiresAt,'invalid_sender_proof');
        need(auth.operationId===input.challengeId&&auth.requestDigest===proofDigest&&integer(auth.counter)&&auth.counter>=1&&auth.counter<=0xffffffff,'invalid_sender_proof');
        need(integer(auth.admittedAt)&&integer(auth.authorizationExpiresAt)&&integer(auth.keyExpiresAt)&&auth.admittedAt>=r.createdAt&&now>=auth.admittedAt&&now<auth.authorizationExpiresAt&&auth.authorizationExpiresAt<=auth.admittedAt+5000&&auth.authorizationExpiresAt<=auth.keyExpiresAt&&auth.authorizationExpiresAt<=r.expiresAt,'invalid_sender_proof');
        r.state='ready';r.envelope=input.destinationEnvelope;r.operationId=input.challengeId;r.requestDigest=requestDigest;this.#save(r);return this.#accepted(r);
      });
    }catch(e){return this.#result(e);}finally{this.#busy=false;}
  }
  async alarm(){try{const r=this.#ctx.storage.transactionSync(()=>{this.#ctx.storage.sql.exec('DELETE FROM rendezvous_state WHERE expires_at<=?',Date.now());return this.#load();});if(r)await this.#ctx.storage.setAlarm(r.expiresAt);}catch{throw new Error('qualification_cleanup_failed');}}
}
export class TransactionCoordinator extends DurableObject<TransactionEnv> {
  #state:TransactionState;
  // Namespace choices are trusted constructor-only seams, never RPC input selectors.
  constructor(ctx:DurableObjectState,env:TransactionEnv,namespace=env.TRANSACTION_STATE,keys=env.ENROLLMENT_COORDINATOR,authorize:Authorizer=coordinatorAuthorizer(keys)){super(ctx,env);this.#state=new TransactionState(ctx,namespace,authorize);}
  create(input:CreateTransaction){return this.#state.create(input);}
  inspect(input:ScanInput){return this.#state.inspect(input);}
  submit(input:SubmitInput){return this.#state.submit(input);}
  poll(input:BrowserInput){return this.#state.browser(input,'poll');}
  consume(input:BrowserInput){return this.#state.browser(input,'consume');}
  cancel(input:BrowserInput){return this.#state.browser(input,'cancel');}
  alarm(){return this.#state.alarm();}
}
