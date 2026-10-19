// SHARED CANDIDATE INTERNAL: compiled product auth remains disabled; no native/production acceptance.
import {ReceiptKeyStore,type StoreEnv,type StoreMaterial} from './receipt-key-store';
import {qualifyAssertionCore} from 'djc-qualified-assertion';
import {base64Decode,base64Url} from 'djc-existing-crypto';
export interface CoordinatorEnv extends StoreEnv { ASSERTION_POLICY_ENABLED?:string; ASSERTION_POLICY_EXPIRES_AT?:string }
type Action='recover-key'|'delete-key'|'submit';
export interface SubmitBinding {transactionId:string;generation:number;browserThumbprint:string;envelopeDigest:string;expiresAt:number}
export interface IssueInput {action:Action;keyId:string;binding?:SubmitBinding}
export interface ProofInput {operationId:string;action:Action;clientData:string;assertion:string}
interface Operation {id:string;action:Action;keyAddress:string;createdAt:number;expiresAt:number;status:'challenge'|'authorized';clientData?:string;nonce?:string;binding?:SubmitBinding;requestDigest?:string;counter?:number;admittedAt?:number;authorizationExpiresAt?:number;keyExpiresAt?:number}
const POLICY='ios-dev-qualification/1',ORIGIN='https://api.djconnect.dev',VERSION='djc-rendezvous/1';
const need:(v:unknown)=>asserts v=v=>{if(!v)throw new Error('proof_rejected');};
const closed=(v:object,names:string[])=>need(v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===names.sort().join(','));
const integer=(v:number)=>Number.isSafeInteger(v)&&v>=0;
function b64url(s:string,max:number,exact?:number){need(typeof s==='string'&&s.length>0&&s.length<=Math.ceil(max*4/3));const bytes=Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(bytes.length<=max&&(exact===undefined||bytes.length===exact)&&base64Url(bytes.buffer)===s);return bytes;}
const opaque=(s:string)=>b64url(s,32,32);
const random=()=>base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer);
async function digest(value:unknown){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(value)))),v=>v.toString(16).padStart(2,'0')).join('');}
export class AssertionKeyState extends ReceiptKeyStore {
 private verifying=false;
 constructor(ctx:DurableObjectState,env:CoordinatorEnv){super(ctx,env);ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS proof_operations (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, value TEXT NOT NULL)');}
 protected override removingKeyEvidence(){this.ctx.storage.sql.exec('DELETE FROM proof_operations');}
 protected override nextCleanupAt(){return this.ctx.storage.sql.exec<{at:number|null}>('SELECT MIN(expires_at) AS at FROM proof_operations').toArray()[0]?.at??undefined;}
 private cleanup(now:number){this.ctx.storage.sql.exec('DELETE FROM proof_operations WHERE expires_at<=?',now);return this.expire(now);}
 private policy(now:number){const e=this.env as CoordinatorEnv,until=Number(e.ASSERTION_POLICY_EXPIRES_AT);need(e.ASSERTION_POLICY_ENABLED===POLICY&&integer(until)&&now<until);return until;}
 private active(now:number){this.policy(now);const r=this.cleanup(now);need(r?.status==='active'&&r.objectId===this.ctx.id.toString()&&r.appPolicy===POLICY&&r.environment==='development'&&now>=r.createdAt&&now<r.expiresAt);return r;}
 private operation(id:string){return this.ctx.storage.sql.exec<{value:string}>('SELECT value FROM proof_operations WHERE id=?',id).toArray().map(r=>JSON.parse(r.value) as Operation)[0];}
 private saveOperation(op:Operation){this.ctx.storage.sql.exec('INSERT INTO proof_operations(id,expires_at,value) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at,value=excluded.value',op.id,op.expiresAt,JSON.stringify(op));}
 private response(op:Operation){need(op.status==='challenge'&&op.clientData&&op.nonce);return {v:VERSION,challenge_id:op.id,challenge:op.nonce,expires_at:op.expiresAt,client_data:op.clientData};}
 private async issueInternal(input:IssueInput){
  input={...input,...(input.binding?{binding:{...input.binding}}:{})};closed(input,input.action==='submit'?['action','keyId','binding']:['action','keyId']);need(['recover-key','delete-key','submit'].includes(input.action));
  need(typeof input.keyId==='string'&&input.keyId.length===44);const keyBytes=base64Decode(input.keyId);need(keyBytes.length===32&&btoa(String.fromCharCode(...keyBytes))===input.keyId);
  const keyAddress=await digest(['development',POLICY,input.keyId]);let binding:SubmitBinding|undefined;
  if(input.action==='submit'){
   need(input.binding);closed(input.binding,['transactionId','generation','browserThumbprint','envelopeDigest','expiresAt']);binding={...input.binding};
   need(/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(binding.transactionId));need(Number.isInteger(binding.generation)&&binding.generation>=1&&binding.generation<=2147483647);opaque(binding.browserThumbprint);opaque(binding.envelopeDigest);
  }
  const now=Date.now();this.policy(now);const expiresAt=binding?.expiresAt??now+120000;need(integer(expiresAt)&&expiresAt>now&&expiresAt-now<=120000);
  const id=random(),nonce=random(),body=binding?{v:VERSION,action:input.action,service_origin:ORIGIN,transaction_id:binding.transactionId,generation:binding.generation,browser_key_thumbprint:binding.browserThumbprint,expires_at:expiresAt,key_id:input.keyId,challenge_id:id,challenge:nonce,envelope_digest:binding.envelopeDigest}:{v:VERSION,action:input.action,service_origin:ORIGIN,key_id:input.keyId,challenge_id:id,challenge:nonce,expires_at:expiresAt};
  const op:Operation={id,nonce,action:input.action,keyAddress,createdAt:now,expiresAt,status:'challenge',clientData:base64Url(JSON.stringify(body)),...(binding?{binding}:{})};
  return this.locked(async()=>{
   const alarm=await this.ctx.storage.getAlarm();await this.ctx.storage.setAlarm(Math.min(alarm??expiresAt,expiresAt));
   return this.ctx.storage.transactionSync(()=>{
    const at=Date.now();this.policy(at);const row=this.cleanup(at);need(at>=now&&at<expiresAt);if(row)need(row.keyAddress===keyAddress);
    const ops=this.ctx.storage.sql.exec<{value:string}>('SELECT value FROM proof_operations').toArray().map(r=>JSON.parse(r.value) as Operation);
    if(input.action!=='submit'){const existing=ops.find(v=>v.status==='challenge'&&v.action===input.action&&v.keyAddress===keyAddress);if(existing)return {ok:true as const,...this.response(existing)};}
    need(ops.length<32&&ops.filter(v=>v.action===input.action).length<(input.action==='submit'?28:2)&&!this.operation(op.id));this.saveOperation(op);return {ok:true as const,...this.response(op)};
   });
  });
 }
 private disposition(op:Operation,requestDigest:string,now:number){
  const row=this.active(now),policyUntil=this.policy(now);need(op.status==='authorized'&&op.requestDigest===requestDigest&&op.keyAddress===row.keyAddress&&now>=op.admittedAt!&&now<op.expiresAt);
  if(op.action==='submit'){need(op.authorizationExpiresAt!==undefined&&now<op.authorizationExpiresAt&&op.authorizationExpiresAt<=policyUntil);return {kind:'submit-authorization' as const,operationId:op.id,requestDigest,admittedAt:op.admittedAt!,keyExpiresAt:op.keyExpiresAt!,authorizationExpiresAt:op.authorizationExpiresAt,counter:op.counter!,binding:op.binding!};}
  need(op.action==='recover-key');return {kind:'recovery-receipt' as const,keyExpiresAt:op.keyExpiresAt!,counter:op.counter!};
 }
 private async authorizeInternal(input:ProofInput){
  input={...input};closed(input,['operationId','action','clientData','assertion']);opaque(input.operationId);need(['recover-key','delete-key','submit'].includes(input.action));
  const client=b64url(input.clientData,2048),proof=b64url(input.assertion,4096),now=Date.now();
  const snapshot=this.ctx.storage.transactionSync(()=>{const row=this.active(now),op=this.operation(input.operationId);need(op&&op.action===input.action&&op.keyAddress===row.keyAddress&&now>=op.createdAt&&now<op.expiresAt);return {row,op};});
  const requestDigest=await digest([input.action,input.operationId,snapshot.row.keyAddress,input.clientData,input.assertion]);
  if(snapshot.op.status==='authorized')return this.ctx.storage.transactionSync(()=>{const op=this.operation(input.operationId);need(op);return this.disposition(op,requestDigest,Date.now());});
  need(snapshot.op.clientData===input.clientData);
  const verified=await qualifyAssertionCore(proof,client,base64Decode(snapshot.row.publicPoint),snapshot.row.counter);need(verified);
  const result=this.ctx.storage.transactionSync(()=>{
   const at=Date.now(),row=this.active(at),op=this.operation(input.operationId);need(op&&op.status==='challenge'&&op.action===input.action&&op.keyAddress===row.keyAddress&&op.clientData===input.clientData&&at>=op.createdAt&&at<op.expiresAt);
   need(row.publicPoint===snapshot.row.publicPoint&&row.createdAt===snapshot.row.createdAt&&row.expiresAt===snapshot.row.expiresAt&&verified.counter>row.counter&&verified.counter<=0xffffffff);
   if(input.action==='delete-key'){const tombstone=this.tombstone(row);this.save(tombstone);return {kind:'deleted' as const,purgeAt:tombstone.purgeAt};}
   row.counter=verified.counter;row.revision++;this.save(row);
   const receipt:Operation={id:op.id,action:op.action,keyAddress:op.keyAddress,createdAt:op.createdAt,expiresAt:Math.min(op.expiresAt,row.expiresAt),status:'authorized',requestDigest,counter:verified.counter,admittedAt:at,keyExpiresAt:row.expiresAt,...(op.binding?{binding:op.binding,authorizationExpiresAt:Math.min(at+5000,op.expiresAt,row.expiresAt,this.policy(at))}:{})};
   this.saveOperation(receipt);return this.disposition(receipt,requestDigest,at);
  });
  await this.arm();if(result.kind==='deleted')return result;
  return this.ctx.storage.transactionSync(()=>{const op=this.operation(input.operationId);need(op);return this.disposition(op,requestDigest,Date.now());});
 }
 // Single active verification per key. No queue of unbounded crypto requests.
 async authorize(input:ProofInput){if(this.verifying)return {ok:false as const,error:'proof_rejected' as const};this.verifying=true;try{return {ok:true as const,...await this.authorizeInternal(input)};}catch{return {ok:false as const,error:'proof_rejected' as const};}finally{this.verifying=false;}}
 async issue(input:IssueInput){try{return await this.issueInternal(input);}catch{return {ok:false as const,error:'proof_rejected' as const};}}
 async lookupSubmit(operationId:string,requestDigest:string){try{opaque(operationId);need(/^[a-f0-9]{64}$/.test(requestDigest));const result=this.ctx.storage.transactionSync(()=>{const op=this.operation(operationId);need(op?.action==='submit');return this.disposition(op,requestDigest,Date.now());});return {ok:true as const,...result};}catch{return {ok:false as const,error:'proof_rejected' as const};}}
 // Direct fixture APIs disabled. Inherited QA helpers/protected hooks are NOT a hardened untrusted RPC boundary.
 override async install(_m:StoreMaterial){return {ok:false as const,error:'store_rejected' as const};}
 override async advance(_counter:number){return {ok:false as const,error:'store_rejected' as const};}
 override async evidence(){return {ok:false as const,error:'store_rejected' as const};}
 override async alarm(){try{this.ctx.storage.transactionSync(()=>{this.cleanup(Date.now());});await super.alarm();}catch{throw new Error('qualification_cleanup_failed');}}
}
