// SHARED CANDIDATE INTERNAL: compiled product auth remains disabled; no native/production acceptance.
import {DurableObject} from 'cloudflare:workers';
import {AssertionKeyState,type CoordinatorEnv,type IssueInput,type ProofInput} from './assertion-key-state';
import {validReceiptActiveKey,type StoreMaterial} from './receipt-key-store';
import {createEnrollmentEvidenceVerifier,type EnrollmentVerifier,type EnrollmentEvidence,type SavedEnrollmentState} from './enrollment-evidence-candidate.mjs';
import {base64Url,base64Decode} from 'djc-existing-crypto';

export interface EnrollmentEnv extends CoordinatorEnv {ENROLLMENT_POLICY_REVISION?:string}
export interface RegisterInput {challengeId:string;keyId:string;attestation:Uint8Array}
interface EnrollmentOperation {id:string;internalId:string;keyAddress:string;createdAt:number;expiresAt:number;policyRevision:string;policyExpiresAt:number;status:'challenge'|'registered';nonce?:string;requestDigest?:string;keyExpiresAt?:number}
interface Intent {id:string;keyId:string;keyAddress:string;nonce:string;requestDigest:string;evidence?:EnrollmentEvidence;materialSnapshot?:string;encryptionKey?:string;policyRevision:string;policyExpiresAt:number}
class EnrollmentConfigUnavailable extends Error {}
const POLICY='ios-dev-qualification/1',VERSION='djc-rendezvous/1';
const need:(value:unknown)=>asserts value=value=>{if(!value)throw new Error('registration_rejected');};
const integer=(v:number)=>Number.isSafeInteger(v)&&v>=0;
const closed=(v:object,keys:string[])=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.sort().join(','));
const b64=(v:Uint8Array)=>btoa(String.fromCharCode(...v));
function keyId(v:string){need(typeof v==='string'&&v.length===44);const bytes=base64Decode(v);need(bytes.length===32&&b64(bytes)===v);}
function opaque(v:string){need(typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v));const bytes=Uint8Array.from(atob(v.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(bytes.length===32&&base64Url(bytes.buffer)===v);}
const hash=async(v:unknown)=>new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(v))));
const hex=(v:Uint8Array)=>Array.from(v,n=>n.toString(16).padStart(2,'0')).join('');
const random=()=>base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer);

export class EnrollmentKeyState extends AssertionKeyState {
  #busy=false;
  #intent:Intent|undefined;
  #verifier:EnrollmentVerifier|undefined;
  constructor(ctx:DurableObjectState,env:EnrollmentEnv){
    super(ctx,env);
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS enrollment_operation (id INTEGER PRIMARY KEY CHECK(id=1), expires_at INTEGER NOT NULL, value TEXT NOT NULL)');
  }
  #configuration(){if(!validReceiptActiveKey(this.env))throw new EnrollmentConfigUnavailable();}
  protected enrollmentPolicy(now:number){
    const env=this.env as EnrollmentEnv,until=Number(env.ASSERTION_POLICY_EXPIRES_AT),revision=env.ENROLLMENT_POLICY_REVISION;
    need(env.ASSERTION_POLICY_ENABLED===POLICY&&integer(until)&&now<until&&typeof revision==='string'&&revision.length>0&&revision.length<=128);
    return {id:POLICY as typeof POLICY,revision,enabled:true,expiresAt:until};
  }
  protected enrollmentOperation(){return this.ctx.storage.sql.exec<{value:string}>('SELECT value FROM enrollment_operation WHERE id=1').toArray().map(r=>JSON.parse(r.value) as EnrollmentOperation)[0];}
  protected saveEnrollment(op:EnrollmentOperation){this.ctx.storage.sql.exec('INSERT INTO enrollment_operation(id,expires_at,value) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at,value=excluded.value',op.expiresAt,JSON.stringify(op));}
  protected cleanupEnrollment(now:number){this.ctx.storage.sql.exec('DELETE FROM enrollment_operation WHERE expires_at<=?',now);}
  protected override removingKeyEvidence(){super.removingKeyEvidence();this.ctx.storage.sql.exec('DELETE FROM enrollment_operation');}
  protected override nextCleanupAt(){const own=this.enrollmentOperation()?.expiresAt,other=super.nextCleanupAt();return own===undefined?other:other===undefined?own:Math.min(own,other);}
  protected enrollmentSnapshot():SavedEnrollmentState {
    const intent=this.#intent,policy=this.enrollmentPolicy(Date.now()),op=this.enrollmentOperation();
    need(intent&&op?.status==='challenge'&&op.id===intent.id&&op.keyAddress===intent.keyAddress&&op.nonce&&op.policyRevision===policy.revision&&op.policyExpiresAt===policy.expiresAt);
    return {policy,challenge:{id:op.id,keyId:intent.keyId,action:'register',createdAt:op.createdAt,expiresAt:op.expiresAt,clientData:Uint8Array.from(atob(op.nonce.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0))}};
  }
  protected verifyEnrollment(request:RegisterInput){this.#verifier??=createEnrollmentEvidenceVerifier(()=>this.enrollmentSnapshot());return this.#verifier.verify(request);}
  protected allowedEvidenceScope():EnrollmentEvidence['scope']{return 'COMPOSED_PRIVATE_EVIDENCE_ONLY_NO_ATOMIC_REGISTRATION';}
  protected override beforeInstallCommit(m:StoreMaterial,now:number){
    const intent=this.#intent,op=this.enrollmentOperation(),policy=this.enrollmentPolicy(now),e=intent?.evidence;
    need(intent&&e&&op?.status==='challenge'&&op.id===intent.id&&op.keyAddress===intent.keyAddress&&op.internalId===m.operationId&&now>=op.createdAt&&now<op.expiresAt);
    need(op.nonce===intent.nonce&&op.policyRevision===intent.policyRevision&&op.policyExpiresAt===intent.policyExpiresAt);
    need(this.load()===undefined&&intent.materialSnapshot===JSON.stringify(m));
    need(policy.revision===intent.policyRevision&&policy.expiresAt===intent.policyExpiresAt&&e.scope===this.allowedEvidenceScope()&&e.policy===POLICY&&e.policyRevision===policy.revision);
    need(e.challengeId===op.id&&e.keyId===intent.keyId&&e.challengeCreatedAt===op.createdAt&&e.challengeExpiresAt===op.expiresAt&&integer(e.verifiedAt)&&e.verifiedAt>=op.createdAt&&e.verifiedAt<=now&&integer(e.validUntil)&&now<e.validUntil&&e.validUntil<=op.expiresAt&&e.validUntil<=policy.expiresAt);
    this.#configuration();need(intent.encryptionKey===this.env.RECEIPT_ACTIVE_KEY);
    need(m.keyAddress===op.keyAddress&&m.requestDigest===intent.requestDigest&&m.receiptCreatedAt===e.receiptCreatedAt&&m.receipt===b64(e.initialReceipt)&&m.publicPoint===b64(e.publicPoint));
  }
  protected override didInstallCommit(m:StoreMaterial,expiresAt:number){
    const op=this.enrollmentOperation();need(op?.status==='challenge');
    this.saveEnrollment({id:op.id,internalId:op.internalId,keyAddress:op.keyAddress,createdAt:op.createdAt,expiresAt:op.expiresAt,policyRevision:op.policyRevision,policyExpiresAt:op.policyExpiresAt,status:'registered',requestDigest:m.requestDigest,keyExpiresAt:expiresAt});
  }
  private registered(id:string,address:string,digest:string){
    const now=Date.now(),policy=this.enrollmentPolicy(now),op=this.enrollmentOperation(),row=this.expire(now);
    need(op?.status==='registered'&&op.id===id&&op.keyAddress===address&&op.requestDigest===digest&&now>=op.createdAt&&now<op.expiresAt);
    need(op.policyRevision===policy.revision&&op.policyExpiresAt===policy.expiresAt);
    need(row?.status==='active'&&row.objectId===this.ctx.id.toString()&&row.keyAddress===address&&row.appPolicy===POLICY&&row.environment==='development'&&now>=row.createdAt&&now<row.expiresAt&&op.keyExpiresAt===row.expiresAt);
    return {ok:true as const,v:VERSION,key_expires_at:row.expiresAt};
  }
  async issueEnrollment(input:{keyId:string}){
    try{
      this.#configuration();input={...input};closed(input,['keyId']);keyId(input.keyId);
      const address=hex(await hash(['development',POLICY,input.keyId])),now=Date.now(),policy=this.enrollmentPolicy(now);
      const op:EnrollmentOperation={id:random(),internalId:crypto.randomUUID(),nonce:random(),keyAddress:address,createdAt:now,expiresAt:Math.min(now+120000,policy.expiresAt),policyRevision:policy.revision,policyExpiresAt:policy.expiresAt,status:'challenge'};
      return await this.locked(async()=>{
        const alarm=await this.ctx.storage.getAlarm();await this.ctx.storage.setAlarm(Math.min(alarm??op.expiresAt,op.expiresAt));
        return this.ctx.storage.transactionSync(()=>{
          const at=Date.now(),currentPolicy=this.enrollmentPolicy(at);this.#configuration();need(currentPolicy.revision===policy.revision&&currentPolicy.expiresAt===policy.expiresAt);this.cleanupEnrollment(at);const row=this.expire(at),existing=this.enrollmentOperation();need(at>=now&&at<op.expiresAt);if(row)need(row.keyAddress===address);
          if(existing){need(existing.keyAddress===address&&existing.status==='challenge'&&existing.policyRevision===policy.revision&&existing.policyExpiresAt===policy.expiresAt);return {ok:true as const,v:VERSION,challenge_id:existing.id,challenge:existing.nonce!,expires_at:existing.expiresAt};}
          this.saveEnrollment(op);return {ok:true as const,v:VERSION,challenge_id:op.id,challenge:op.nonce!,expires_at:op.expiresAt};
        });
      });
    }catch(error){return {ok:false as const,error:error instanceof EnrollmentConfigUnavailable?'service_unavailable' as const:'registration_rejected' as const};}
  }
  async enroll(input:RegisterInput){
    if(this.#busy)return {ok:false as const,error:'registration_rejected' as const};this.#busy=true;
    try{
      this.#configuration();closed(input,['keyId','challengeId','attestation']);keyId(input.keyId);opaque(input.challengeId);need(input.attestation instanceof Uint8Array&&input.attestation.length>0&&input.attestation.length<=32768);
      input={keyId:input.keyId,challengeId:input.challengeId,attestation:Uint8Array.from(input.attestation)};
      const address=hex(await hash(['development',POLICY,input.keyId])),digest=hex(await hash([VERSION,'register',input.challengeId,input.keyId,b64(input.attestation)]));
      const policy=this.enrollmentPolicy(Date.now()),op=this.enrollmentOperation();need(op&&op.id===input.challengeId&&op.keyAddress===address&&Date.now()>=op.createdAt&&Date.now()<op.expiresAt&&op.policyRevision===policy.revision&&op.policyExpiresAt===policy.expiresAt);
      if(op.status==='registered')return this.ctx.storage.transactionSync(()=>this.registered(op.id,address,digest));
      this.#configuration();need(op.nonce);this.#intent={id:op.id,keyId:input.keyId,keyAddress:address,nonce:op.nonce,requestDigest:digest,policyRevision:policy.revision,policyExpiresAt:policy.expiresAt};
      const verified=await this.verifyEnrollment(input);
      need(Date.now()>=op.createdAt&&Date.now()<op.expiresAt);this.enrollmentSnapshot();this.#configuration();
      if(verified.ok===false&&verified.error==='attestation_unavailable'){closed(verified,['ok','error']);return {ok:false as const,error:'attestation_unavailable' as const};}
      need(verified.ok);
      const e:EnrollmentEvidence={...verified.evidence,initialReceipt:Uint8Array.from(verified.evidence.initialReceipt),publicPoint:Uint8Array.from(verified.evidence.publicPoint)};
      need(e.publicPoint.length===65&&e.publicPoint[0]===4&&e.initialReceipt.length>0&&e.initialReceipt.length<=16384);
      need(b64(new Uint8Array(await crypto.subtle.digest('SHA-256',e.publicPoint)))===input.keyId);
      need(Date.now()>=op.createdAt&&Date.now()<op.expiresAt);this.enrollmentSnapshot();this.#configuration();
      const m:StoreMaterial={keyAddress:address,appPolicy:POLICY,environment:'development',publicPoint:b64(e.publicPoint),receipt:b64(e.initialReceipt),receiptCreatedAt:e.receiptCreatedAt,challengeCreatedAt:op.createdAt,challengeExpiresAt:op.expiresAt,operationId:op.internalId,requestDigest:digest};
      this.#intent.evidence=e;this.#intent.materialSnapshot=JSON.stringify(m);this.#intent.encryptionKey=this.env.RECEIPT_ACTIVE_KEY;
      await this.installInternal(m);
      return this.ctx.storage.transactionSync(()=>this.registered(op.id,address,digest));
    }catch(error){return {ok:false as const,error:error instanceof EnrollmentConfigUnavailable?'service_unavailable' as const:'registration_rejected' as const};}finally{this.#intent=undefined;this.#busy=false;}
  }
  override async alarm(){try{this.ctx.storage.transactionSync(()=>this.cleanupEnrollment(Date.now()));await super.alarm();}catch{throw new Error('qualification_cleanup_failed');}}
}

/** Only this containment facade is a candidate DO binding. No inherited QA helpers on its prototype. */
export class EnrollmentCoordinator extends DurableObject<EnrollmentEnv> {
  #state:EnrollmentKeyState;
  // Third argument is a trusted constructor-only QA seam, never an RPC/request/env selector.
  constructor(ctx:DurableObjectState,env:EnrollmentEnv,State:typeof EnrollmentKeyState=EnrollmentKeyState){super(ctx,env);this.#state=new State(ctx,env);}
  issueEnrollment(input:{keyId:string}){return this.#state.issueEnrollment(input);}
  enroll(input:RegisterInput){return this.#state.enroll(input);}
  issueAction(input:IssueInput){return this.#state.issue(input);}
  authorize(input:ProofInput){return this.#state.authorize(input);}
  lookupSubmit(id:string,digest:string){return this.#state.lookupSubmit(id,digest);}
  alarm(){return this.#state.alarm();}
}
