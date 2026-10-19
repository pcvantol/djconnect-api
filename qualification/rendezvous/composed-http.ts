import {readRetryHint,hintFields} from './retry-hint';
// LOCAL QUALIFICATION ONLY. This factory is not a product route or deployment.
import {createIngress,matchesWireSchema,parseWireJson,type WireObject,type IngressRoute} from './http-ingress';
import {INDEX_NAME,IndexedTransactionRouter,type AllocationIndex} from './allocation-index';
import {BUDGET_NAME,type BudgetIdentity,type BudgetResult,type AllocationBudget} from './allocation-budget';
import {KeyRpcRouter,keyRoutedAuthorizer} from './key-routing';
import {TransactionCoordinator,type TransactionEnv} from './transaction-state';
import {qualifyBrowserPublicJwk,type BrowserPublicJwk} from './jwe-framing';
export const COMPOSED_POLICY='djc-http-composition-qualification/1';
const V='djc-rendezvous/1';
export interface ComposedEnv extends TransactionEnv {
  COMPOSED_TRANSACTIONS:DurableObjectNamespace<TransactionCoordinator>;
  ALLOCATION_INDEX:DurableObjectNamespace<AllocationIndex>;
  ADMISSION_STATE:DurableObjectNamespace<AllocationBudget>;
  COMPOSED_POLICY_ENABLED?:string;
}
export type TrustedIdentityResolver=(request:Request)=>Promise<BudgetIdentity>;
const status:Record<string,number>={invalid_request:400,invalid_capability:401,invalid_sender_proof:401,operation_conflict:409,already_submitted:409,already_consumed:409,cancelled:409,not_ready:409,expired:410,rate_limited:429,attestation_unavailable:503,service_unavailable:503};
class Failure extends Error {constructor(readonly code:string,readonly retryAfter?:number){super('composition_rejected');}}
const need:(v:unknown,code?:string)=>asserts v=(v,code='service_unavailable')=>{if(!v)throw new Failure(code);};
function success(value:unknown,kind?:string):WireObject {
  need(value&&typeof value==='object'&&!Array.isArray(value));const r=value as WireObject;
  if(r.ok===false){const code=r.error==='registration_rejected'||r.error==='proof_rejected'?'invalid_sender_proof':r.error;if(code==='rate_limited'||code==='service_unavailable'){let hint:number|undefined;try{hint=readRetryHint(r);}catch{throw new Failure('service_unavailable');}throw new Failure(code,hint);}throw new Failure(typeof code==='string'&&Object.hasOwn(status,code)?code:'service_unavailable');}
  need(r.ok===true&&(r.v===undefined||r.v===V));need(kind===undefined?!Object.hasOwn(r,'kind'):r.kind===kind);return r;
}
function current(expiry:unknown){
  need(typeof expiry==='number'&&Number.isSafeInteger(expiry)&&expiry>=0);
  need(Date.now()<expiry,'expired');
}
const fromUrl=(value:string)=>Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
export class BudgetedTransactionCoordinator extends TransactionCoordinator {
  constructor(ctx:DurableObjectState,env:ComposedEnv,namespace=env.COMPOSED_TRANSACTIONS,keys=env.ENROLLMENT_COORDINATOR){
    const budget=env.ADMISSION_STATE.get(env.ADMISSION_STATE.idFromName(BUDGET_NAME));
    const router=new KeyRpcRouter(budget,keys,()=>env.COMPOSED_POLICY_ENABLED===COMPOSED_POLICY);
    super(ctx,env,namespace,keys,keyRoutedAuthorizer(router));
  }
}
export function createComposedHandler(env?:ComposedEnv,resolveIdentity?:TrustedIdentityResolver,beforeBody?:(route:IngressRoute)=>Promise<BudgetResult>,requestEnabled?:()=>boolean){
  const enabled=()=>env?.COMPOSED_POLICY_ENABLED===COMPOSED_POLICY&&typeof resolveIdentity==='function'&&(!requestEnabled||requestEnabled());
  return async(request:Request):Promise<Response>=>{
    // Identity belongs to this invocation, never a shared handler/DO context.
    let identity:BudgetIdentity|undefined;
    return createIngress({enabled,beforeBody,
      admit:async route=>{
        if(route==='/create'||route==='/attestation/register')identity=structuredClone(await resolveIdentity!(request));
        return {ok:true}; // Allocation/key adapters own the single actual charge point.
      },
      dispatch:async(route:IngressRoute,b:WireObject)=>{
        try{
          need(enabled());const e=env!,budget=e.ADMISSION_STATE.get(e.ADMISSION_STATE.idFromName(BUDGET_NAME)),index=e.ALLOCATION_INDEX.get(e.ALLOCATION_INDEX.idFromName(INDEX_NAME));
          const tx=new IndexedTransactionRouter(index,e.COMPOSED_TRANSACTIONS,enabled),keys=new KeyRpcRouter(budget,e.ENROLLMENT_COORDINATOR,enabled);
          const scan=()=>({transactionId:b.transaction_id as string,generation:b.generation as number,qrCapability:b.qr_capability as string});
          const browser=()=>({transactionId:b.transaction_id as string,generation:b.generation as number,claimSecret:b.claim_secret as string});
          let result:WireObject,body:unknown,code=200;
          if(route==='/create'){
            need(identity);const pub=await qualifyBrowserPublicJwk(b.browser_public_key);need(pub.ok);need(enabled());
            result=success(await tx.create({identity,generation:b.generation as number,browserPublicKey:b.browser_public_key as BrowserPublicJwk,claimCommitment:b.claim_commitment as string}));
            need(typeof result.qr_payload==='string');const qrBytes=new TextEncoder().encode(result.qr_payload);need(qrBytes.length<=1024);const qr=parseWireJson(qrBytes);
            need(matchesWireSchema('qr_payload',qr)&&qr.transaction_id===result.transaction_id&&qr.generation===b.generation&&result.generation===b.generation&&qr.expires_at===result.expires_at&&qr.browser_key_thumbprint===pub.thumbprint);
            const allocated=await index.lookup({transactionId:result.transaction_id as string});need(enabled());need(allocated.ok);
            need(allocated.descriptor.id===result.transaction_id&&allocated.descriptor.createdAt===result.created_at&&allocated.descriptor.expiresAt===result.expires_at);current(result.expires_at);
            body={v:V,transaction_id:result.transaction_id,generation:result.generation,created_at:result.created_at,expires_at:result.expires_at,browser_key_thumbprint:pub.thumbprint,qr_payload:qr};code=201;
          }else if(route==='/inspect'){
            result=success(await tx.route('inspect',scan()));current(result.expires_at);
            body={v:V,transaction_id:b.transaction_id,generation:result.generation,expires_at:result.expires_at,browser_public_key:result.browser_public_key,browser_key_thumbprint:result.browser_key_thumbprint};
          }else if(route==='/submit-challenge'){
            const inspected=success(await tx.route('inspect',scan()));current(inspected.expires_at);need(inspected.generation===b.generation);
            result=success(await keys.route({operation:'issueAction',keyId:b.key_id as string,action:'submit',binding:{transactionId:b.transaction_id as string,generation:b.generation as number,browserThumbprint:inspected.browser_key_thumbprint as string,envelopeDigest:b.envelope_digest as string,expiresAt:inspected.expires_at as number}}));
            need(enabled());current(inspected.expires_at);need(result.expires_at===inspected.expires_at);
            body={v:V,challenge_id:result.challenge_id,challenge:result.challenge,client_data:result.client_data,expires_at:result.expires_at};
          }else if(route==='/submit'){
            result=success(await tx.route('submit',{...scan(),keyId:b.key_id as string,challengeId:b.challenge_id as string,clientData:b.client_data as string,assertion:b.assertion as string,destinationEnvelope:b.destination_envelope as string}));
            need(result.accepted===true);body={v:V,accepted:true,operation_id:result.operation_id};code=202;
          }else if(route==='/poll'||route==='/consume'||route==='/cancel'){
            result=success(await tx.route(route==='/poll'?'poll':route==='/consume'?'consume':'cancel',browser()));
            body=route==='/poll'?{v:V,state:result.state,expires_at:result.expires_at,retry_after_ms:result.retry_after_ms}:route==='/consume'?{v:V,state:result.state,destination_envelope:result.destination_envelope,expires_at:result.expires_at}:{v:V,state:result.state};
          }else if(route==='/attestation/challenge'){
            result=success(await keys.route(b.action==='register'?{operation:'issueEnrollment',keyId:b.key_id as string}:{operation:'issueAction',keyId:b.key_id as string,action:b.action as 'delete-key'|'recover-key'}));
            current(result.expires_at);body=b.action==='register'?{v:V,challenge_id:result.challenge_id,challenge:result.challenge,expires_at:result.expires_at}:{v:V,challenge_id:result.challenge_id,challenge:result.challenge,client_data:result.client_data,expires_at:result.expires_at};
          }else if(route==='/attestation/register'){
            need(identity);result=success(await keys.route({operation:'enroll',keyId:b.key_id as string,challengeId:b.challenge_id as string,attestation:fromUrl(b.attestation as string),identity}));current(result.key_expires_at);
            body={v:V,key_expires_at:result.key_expires_at};code=201;
          }else{
            const deleting=route==='/attestation/delete';need(deleting||route==='/attestation/recover');
            result=success(await keys.route({operation:'authorize',keyId:b.key_id as string,operationId:b.challenge_id as string,action:deleting?'delete-key':'recover-key',clientData:b.client_data as string,assertion:b.assertion as string}),deleting?'deleted':'recovery-receipt');
            if(!deleting)current(result.keyExpiresAt);
            body=deleting?{v:V,state:'revoked',purge_at:result.purgeAt}:{v:V,key_expires_at:result.keyExpiresAt};
          }
          need(enabled());return {status:code,body};
        }catch(error){const code=error instanceof Failure&&Object.hasOwn(status,error.code)?error.code:'service_unavailable';return {status:status[code],body:{v:V,error:code,...hintFields(error instanceof Failure?error.retryAfter:undefined)}};}
      },
    })(request);
  };
}
