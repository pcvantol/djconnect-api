import {readRetryHint,hintFields} from './retry-hint';
// SHARED CANDIDATE INTERNAL: compiled product auth remains disabled; no native/production acceptance.
import {base64Decode,base64Url} from 'djc-existing-crypto';
import {type BudgetResult,type BudgetIdentity} from './allocation-budget';
import {type EnrollmentCoordinator,type RegisterInput} from './enrollment-key-state';
import {type IssueInput,type ProofInput,type SubmitBinding} from './assertion-key-state';
import {type Authorizer} from './transaction-state';
export interface KeyCallBudget {admitKeyCall():Promise<BudgetResult>;admit(input:{kind:'key';identity:BudgetIdentity}):Promise<BudgetResult>}
type FailureCode='invalid_request'|'service_unavailable'|'rate_limited';
class Failure extends Error {constructor(readonly code:FailureCode,readonly retryAfter?:number){super('key_route_rejected');}}
const need:(v:unknown,code?:FailureCode)=>asserts v=(v,code='invalid_request')=>{if(!v)throw new Failure(code);};
const closed=(v:object,keys:string[])=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(','));
const opaque=(v:unknown)=>{need(typeof v==='string'&&v.length===43&&/^[A-Za-z0-9_-]+$/.test(v));const b=Uint8Array.from(atob(v.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(base64Url(b.buffer)===v);};
function keyId(value:string){need(typeof value==='string'&&value.length===44&&/^[A-Za-z0-9+/]{43}=$/.test(value));const b=base64Decode(value);need(b.length===32&&btoa(String.fromCharCode(...b))===value);}
function encoded(value:string,max:number){need(typeof value==='string'&&value.length>0&&value.length%4!==1&&value.length<=Math.ceil(max*4/3)&&/^[A-Za-z0-9_-]+$/.test(value));const b=Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(b.length<=max&&base64Url(b.buffer)===value);}
function binding(value:SubmitBinding){closed(value,['transactionId','generation','browserThumbprint','envelopeDigest','expiresAt']);need(typeof value.transactionId==='string'&&value.transactionId.length===36&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.transactionId));need(Number.isInteger(value.generation)&&value.generation>=1&&value.generation<=2147483647);opaque(value.browserThumbprint);opaque(value.envelopeDigest);need(Number.isSafeInteger(value.expiresAt)&&value.expiresAt>Date.now()&&value.expiresAt-Date.now()<=120000);}
function admitted(value:BudgetResult){
  try{need(value&&typeof value==='object');if(value.ok===true){closed(value,['ok']);return;}
    need(value.ok===false&&(value.error==='rate_limited'||value.error==='service_unavailable'));closed(value,value.retry_after_ms===undefined?['ok','error']:['ok','error','retry_after_ms']);if(value.retry_after_ms!==undefined)need(Number.isSafeInteger(value.retry_after_ms)&&value.retry_after_ms>=1&&value.retry_after_ms<=60000);
  }catch{throw new Failure('service_unavailable');}
  throw new Failure(value.error,readRetryHint(value));
}
export type KeyRequest=
 |{operation:'issueEnrollment';keyId:string}
 |{operation:'enroll';keyId:string;challengeId:string;attestation:Uint8Array;identity:BudgetIdentity}
 |{operation:'issueAction';keyId:string;action:IssueInput['action'];binding?:SubmitBinding}
 |({operation:'authorize';keyId:string}&ProofInput);
export class KeyRpcRouter {
  #budget:KeyCallBudget;#namespace:DurableObjectNamespace<EnrollmentCoordinator>;#enabled:()=>boolean;
  constructor(budget:KeyCallBudget,namespace:DurableObjectNamespace<EnrollmentCoordinator>,enabled:()=>boolean){this.#budget=budget;this.#namespace=namespace;this.#enabled=enabled;}
  #ready(){need(this.#enabled(),'service_unavailable');}
  async route(input:KeyRequest){try{
    this.#ready();need(input&&typeof input==='object');keyId(input.keyId);
    if(input.operation==='issueEnrollment'){closed(input,['operation','keyId']);input={...input};}
    else if(input.operation==='enroll'){
      closed(input,['operation','keyId','challengeId','attestation','identity']);opaque(input.challengeId);closed(input.identity,['minute','key']);opaque(input.identity.key);need(Number.isSafeInteger(input.identity.minute)&&input.identity.minute>=0);
      need(input.attestation instanceof Uint8Array&&input.attestation.length>0&&input.attestation.length<=32768);input={...input,identity:{...input.identity},attestation:Uint8Array.from(input.attestation)};
    }else if(input.operation==='issueAction'){
      need(['recover-key','delete-key','submit'].includes(input.action));closed(input,input.action==='submit'?['operation','keyId','action','binding']:['operation','keyId','action']);if(input.action==='submit'){need(input.binding);binding(input.binding);}input={...input,...(input.binding?{binding:{...input.binding}}:{})};
    }else{
      need(input.operation==='authorize');closed(input,['operation','keyId','operationId','action','clientData','assertion']);need(['recover-key','delete-key','submit'].includes(input.action));opaque(input.operationId);encoded(input.clientData,2048);encoded(input.assertion,4096);input={...input};
    }
    const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(['development','ios-dev-qualification/1',input.keyId]))),address=Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('');this.#ready();
    const day=Math.floor(Date.now()/86400000);admitted(await this.#budget.admitKeyCall());this.#ready();need(Math.floor(Date.now()/86400000)===day,'service_unavailable');
    if(input.operation==='enroll'){admitted(await this.#budget.admit({kind:'key',identity:{...input.identity}}));this.#ready();need(input.identity.minute===Math.floor(Date.now()/60000),'service_unavailable');}
    need(Math.floor(Date.now()/86400000)===day,'service_unavailable');
    const child=this.#namespace.get(this.#namespace.idFromName('djc-rendezvous-key/1/'+address));
    const reply=input.operation==='issueEnrollment'?await child.issueEnrollment({keyId:input.keyId}):input.operation==='enroll'?await child.enroll({keyId:input.keyId,challengeId:input.challengeId,attestation:input.attestation} satisfies RegisterInput):input.operation==='issueAction'?await child.issueAction({action:input.action,keyId:input.keyId,...(input.binding?{binding:input.binding}:{})}):await child.authorize({operationId:input.operationId,action:input.action,clientData:input.clientData,assertion:input.assertion});
    this.#ready();return reply;
  }catch(error){return {ok:false as const,error:error instanceof Failure?error.code:'service_unavailable' as FailureCode,...hintFields(error instanceof Failure?error.retryAfter:undefined)};}}
}
// Constructor-only server adapter: never accept a caller-provided grant or budget selector.
export function keyRoutedAuthorizer(router:KeyRpcRouter):Authorizer {
  return async(keyId:string,input:ProofInput)=>{try{closed(input,['operationId','action','clientData','assertion']);return await router.route({operation:'authorize',keyId,operationId:input.operationId,action:input.action,clientData:input.clientData,assertion:input.assertion});}catch{return {ok:false,error:'invalid_request'};}};
}
