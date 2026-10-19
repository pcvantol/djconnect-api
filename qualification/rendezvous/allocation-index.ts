// LOCAL QUALIFICATION ONLY. Private transaction routing, never owner/screen authority.
import {DurableObject} from 'cloudflare:workers';
import {base64Url} from 'djc-existing-crypto';
import {BUDGET_NAME,type BudgetIdentity,type BudgetResult,type AllocationBudget} from './allocation-budget';
import {newTransactionDescriptor,type Descriptor,type TransactionCoordinator,type BrowserInput,type ScanInput,type SubmitInput} from './transaction-state';
import {qualifyBrowserPublicJwk,type BrowserPublicJwk} from './jwe-framing';
export const INDEX_NAME='djc-rendezvous-index/1',INDEX_POLICY='djc-index-qualification/1';
type Code='invalid_request'|'invalid_capability'|'service_unavailable'|'rate_limited'|'expired';
type Denial={ok:false;error:Code;retry_after_ms?:number};
export type IndexResult={ok:true;descriptor:Descriptor}|Denial;
export interface IndexEnv {ALLOCATION_INDEX:DurableObjectNamespace;ADMISSION_STATE:DurableObjectNamespace<AllocationBudget>;INDEX_POLICY_ENABLED?:string}
export interface IndexPort {allocate(input:{identity:BudgetIdentity}):Promise<IndexResult>;lookup(input:{transactionId:string}):Promise<IndexResult>}
class Failure extends Error {constructor(readonly code:Code){super('index_rejected');}}
const need:(v:unknown,code?:Code)=>asserts v=(v,code='invalid_request')=>{if(!v)throw new Failure(code);};
const closed=(v:object,keys:string[])=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(','));
const uuid=(v:unknown)=>need(typeof v==='string'&&v.length===36&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v));
function opaque(v:unknown){need(typeof v==='string'&&v.length===43&&/^[A-Za-z0-9_-]+$/.test(v));const b=Uint8Array.from(atob(v.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(b.length===32&&base64Url(b.buffer)===v);}
function descriptor(value:Descriptor,id?:string){closed(value,['id','createdAt','expiresAt']);uuid(value.id);need(Number.isSafeInteger(value.createdAt)&&value.createdAt>=0&&Number.isSafeInteger(value.expiresAt)&&value.expiresAt===value.createdAt+120000&&(id===undefined||value.id===id),'service_unavailable');need(Date.now()>=value.createdAt&&Date.now()<value.expiresAt,'expired');}
function checkedDenial(value:Denial,allowed:Code[]):Denial {
  try{closed(value,value.retry_after_ms===undefined?['ok','error']:['ok','error','retry_after_ms']);need(value.ok===false&&allowed.includes(value.error));if(value.retry_after_ms!==undefined)need(Number.isSafeInteger(value.retry_after_ms)&&value.retry_after_ms>=1&&value.retry_after_ms<=60000);return {ok:false,error:value.error,...(value.retry_after_ms===undefined?{}:{retry_after_ms:value.retry_after_ms})};}catch{throw new Failure('service_unavailable');}
}
const result=(error:unknown):Denial=>({ok:false,error:error instanceof Failure?error.code:'service_unavailable'});
export class AllocationIndexState {
  #ctx:DurableObjectState;#env:IndexEnv;#busy=false;#admit:(identity:BudgetIdentity)=>Promise<BudgetResult>;#newDescriptor:()=>Descriptor;
  constructor(ctx:DurableObjectState,env:IndexEnv,admit=(identity:BudgetIdentity)=>env.ADMISSION_STATE.get(env.ADMISSION_STATE.idFromName(BUDGET_NAME)).admit({kind:'transaction',identity}),fresh=newTransactionDescriptor){
    this.#ctx=ctx;this.#env=env;this.#admit=admit;this.#newDescriptor=fresh;
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS allocation_index (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)');
  }
  #policy(){need(this.#env.INDEX_POLICY_ENABLED===INDEX_POLICY&&this.#env.ALLOCATION_INDEX.idFromName(INDEX_NAME).equals(this.#ctx.id),'service_unavailable');}
  #window(identity:BudgetIdentity){need(identity.minute===Math.floor(Date.now()/60000),'service_unavailable');}
  async allocate(input:{identity:BudgetIdentity}):Promise<IndexResult>{
    if(this.#busy)return result(new Failure('service_unavailable'));this.#busy=true;
    try{
      closed(input,['identity']);closed(input.identity,['minute','key']);input={identity:{...input.identity}};
      need(Number.isSafeInteger(input.identity.minute)&&input.identity.minute>=0);opaque(input.identity.key);this.#policy();this.#window(input.identity);
      const admission=await this.#admit({...input.identity});this.#policy();this.#window(input.identity);
      if(admission?.ok===false){closed(admission,admission.retry_after_ms===undefined?['ok','error']:['ok','error','retry_after_ms']);need(admission.error==='rate_limited'||admission.error==='service_unavailable','service_unavailable');if(admission.retry_after_ms!==undefined)need(Number.isSafeInteger(admission.retry_after_ms)&&admission.retry_after_ms>=1&&admission.retry_after_ms<=60000,'service_unavailable');return {...admission};}
      need(admission?.ok===true,'service_unavailable');closed(admission,['ok']);
      const d={...this.#newDescriptor()};descriptor(d);
      const alarm=await this.#ctx.storage.getAlarm();await this.#ctx.storage.setAlarm(Math.min(alarm??d.expiresAt,d.expiresAt));
      return this.#ctx.storage.transactionSync(()=>{
        this.#policy();this.#window(input.identity);descriptor(d);
        this.#ctx.storage.sql.exec('DELETE FROM allocation_index WHERE expires_at<=?',Date.now());
        need(this.#ctx.storage.sql.exec<{n:number}>('SELECT COUNT(*) AS n FROM allocation_index').toArray()[0].n<10000,'rate_limited');
        this.#ctx.storage.sql.exec('INSERT INTO allocation_index(id,created_at,expires_at) VALUES(?,?,?)',d.id,d.createdAt,d.expiresAt);
        return {ok:true as const,descriptor:{...d}};
      });
    }catch(e){return result(e);}finally{this.#busy=false;}
  }
  lookup(input:{transactionId:string}):IndexResult{
    try{closed(input,['transactionId']);input={...input};uuid(input.transactionId);this.#policy();
      const row=this.#ctx.storage.sql.exec<{id:string;created_at:number;expires_at:number}>('SELECT id,created_at,expires_at FROM allocation_index WHERE id=?',input.transactionId).toArray()[0];
      need(row,'invalid_capability');const d={id:row.id,createdAt:row.created_at,expiresAt:row.expires_at};descriptor(d,input.transactionId);return {ok:true,descriptor:d};
    }catch(e){return result(e);}
  }
  async alarm(){if(this.#busy)throw new Error('index_cleanup_busy');this.#busy=true;try{
    const next=this.#ctx.storage.transactionSync(()=>{this.#ctx.storage.sql.exec('DELETE FROM allocation_index WHERE expires_at<=?',Date.now());return this.#ctx.storage.sql.exec<{at:number|null}>('SELECT MIN(expires_at) AS at FROM allocation_index').toArray()[0].at;});
    if(next===null)await this.#ctx.storage.deleteAlarm();else await this.#ctx.storage.setAlarm(next);
  }catch{throw new Error('index_cleanup_failed');}finally{this.#busy=false;}}
}
export class AllocationIndex extends DurableObject<IndexEnv> {
  #state:AllocationIndexState;
  constructor(ctx:DurableObjectState,env:IndexEnv){super(ctx,env);this.#state=new AllocationIndexState(ctx,env);}
  allocate(input:{identity:BudgetIdentity}){return this.#state.allocate(input);}
  lookup(input:{transactionId:string}){return this.#state.lookup(input);}
  alarm(){return this.#state.alarm();}
}
export interface AllocateTransaction {identity:BudgetIdentity;generation:number;browserPublicKey:BrowserPublicJwk;claimCommitment:string}
type Operation='inspect'|'reserveSubmitChallenge'|'submit'|'poll'|'consume'|'cancel';
export class IndexedTransactionRouter {
  #index:IndexPort;#namespace:DurableObjectNamespace<TransactionCoordinator>;#enabled:()=>boolean;
  constructor(index:IndexPort,namespace:DurableObjectNamespace<TransactionCoordinator>,enabled:()=>boolean){this.#index=index;this.#namespace=namespace;this.#enabled=enabled;}
  #ready(){need(this.#enabled(),'service_unavailable');}
  #resolved(value:IndexResult,id?:string){if(value?.ok===false)throw new Failure(checkedDenial(value,['invalid_capability','expired','service_unavailable']).error);need(value?.ok===true,'service_unavailable');closed(value,['ok','descriptor']);const d={...value.descriptor};descriptor(d,id);return d;}
  async create(input:AllocateTransaction){try{
    this.#ready();closed(input,['identity','generation','browserPublicKey','claimCommitment']);closed(input.identity,['minute','key']);input={...input,identity:{...input.identity},browserPublicKey:{...input.browserPublicKey}};
    need(Number.isInteger(input.generation)&&input.generation>=1&&input.generation<=2147483647);opaque(input.claimCommitment);opaque(input.identity.key);need(Number.isSafeInteger(input.identity.minute)&&input.identity.minute>=0);
    const pub=await qualifyBrowserPublicJwk(input.browserPublicKey);need(pub.ok);this.#ready();
    const allocation=await this.#index.allocate({identity:{...input.identity}});this.#ready();
    if(allocation?.ok===false)return checkedDenial(allocation,['rate_limited','service_unavailable']);
    const d=this.#resolved(allocation);this.#ready();descriptor(d);
    const child=this.#namespace.get(this.#namespace.idFromName(d.id));
    const reply=await child.create({descriptor:d,generation:input.generation,browserPublicKey:pub.jwk,claimCommitment:input.claimCommitment});this.#ready();descriptor(d);return reply;
  }catch(e){return result(e);}}
  async route(operation:Operation,input:ScanInput|BrowserInput|SubmitInput){try{
    this.#ready();need(['inspect','reserveSubmitChallenge','submit','poll','consume','cancel'].includes(operation));
    const scanner=operation==='inspect'||operation==='reserveSubmitChallenge'||operation==='submit',fields=scanner?['transactionId','generation','qrCapability']:['transactionId','generation','claimSecret'];
    if(operation==='submit')fields.push('keyId','challengeId','clientData','assertion','destinationEnvelope');closed(input,fields);input={...input};uuid(input.transactionId);need(Number.isInteger(input.generation)&&input.generation>=1&&input.generation<=2147483647);
    if(scanner)opaque((input as ScanInput).qrCapability);else opaque((input as BrowserInput).claimSecret);
    if(operation==='submit'){const s=input as SubmitInput;opaque(s.challengeId);for(const [key,max] of [['keyId',44],['clientData',2731],['assertion',5462],['destinationEnvelope',8192]] as const)need(typeof s[key]==='string'&&s[key].length>0&&s[key].length<=max);}
    const lookup=await this.#index.lookup({transactionId:input.transactionId});this.#ready();const d=this.#resolved(lookup,input.transactionId);descriptor(d);
    const child=this.#namespace.get(this.#namespace.idFromName(d.id));
    const reply=operation==='reserveSubmitChallenge'?await child.reserveSubmitChallenge(input as ScanInput):operation==='inspect'?await child.inspect(input as ScanInput):operation==='submit'?await child.submit(input as SubmitInput):operation==='poll'?await child.poll(input as BrowserInput):operation==='consume'?await child.consume(input as BrowserInput):await child.cancel(input as BrowserInput);
    this.#ready();descriptor(d);return reply;
  }catch(e){return result(e);}}
}
