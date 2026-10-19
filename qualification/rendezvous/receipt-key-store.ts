// SHARED CANDIDATE INTERNAL: compiled product auth remains disabled; no native/production acceptance.
import { DurableObject } from 'cloudflare:workers';
import { encryptSecret, decryptSecret, base64Decode, base64Url } from 'djc-existing-crypto';
export interface StoreEnv { RECEIPT_ACTIVE_KEY?: string; RECEIPT_PREVIOUS_KEY?: string }
export interface StoreMaterial {
  keyAddress: string; appPolicy: string; environment: 'development'; publicPoint: string;
  receipt: string; receiptCreatedAt: number; challengeCreatedAt: number; challengeExpiresAt: number;
  operationId: string; requestDigest: string;
}
interface Context { objectId:string; keyAddress:string; appPolicy:string; environment:'development'; createdAt:number; expiresAt:number; receiptCreatedAt:number; keyVersion:string; publicPoint:string }
interface Active extends Context { status:'active'; version:1; revision:number; publicPoint:string; counter:number; ciphertext:string; nonce:string; operationId?:string; requestDigest?:string; challengeExpiresAt?:number }
interface Tombstone { status:'revoked'; version:1; keyAddress:string; expiresAt:number; purgeAt:number }
type RecordState=Active|Tombstone;
const DAY=86400000;
const need:(v:unknown)=>asserts v=(v)=>{if(!v)throw new Error('qualification_store_rejected');};
const integer=(v:number)=>Number.isSafeInteger(v)&&v>=0;
const context=(r:Active|Context):Context=>({objectId:r.objectId,keyAddress:r.keyAddress,appPolicy:r.appPolicy,environment:r.environment,createdAt:r.createdAt,expiresAt:r.expiresAt,receiptCreatedAt:r.receiptCreatedAt,keyVersion:r.keyVersion,publicPoint:r.publicPoint});
function canonicalBase64(s:string,max:number,exact?:number){need(typeof s==='string'&&s.length>0&&s.length<=Math.ceil(max/3)*4);const b=base64Decode(s);need(b.length<=max&&(exact===undefined||b.length===exact)&&btoa(String.fromCharCode(...b))===s);return b;}
export function validReceiptActiveKey(env:StoreEnv):boolean{try{canonicalBase64(env.RECEIPT_ACTIVE_KEY!,32,32);return true;}catch{return false;}}
async function keyVersion(key:string){canonicalBase64(key,32,32);return base64Url(await crypto.subtle.digest('SHA-256',base64Decode(key))).slice(0,16);}
export class ReceiptKeyStore extends DurableObject<StoreEnv> {
  constructor(ctx:DurableObjectState,env:StoreEnv){super(ctx,env);ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS key_state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)');}
  private queue:Promise<void>=Promise.resolve();
  protected locked<T>(fn:()=>Promise<T>):Promise<T>{const operation=this.queue.then(fn,fn);this.queue=operation.then(()=>{},()=>{});return operation;}
  protected load():RecordState|undefined{return this.ctx.storage.sql.exec<{value:string}>('SELECT value FROM key_state WHERE id=1').toArray().map(r=>JSON.parse(r.value) as RecordState)[0];}
  protected save(row:RecordState){this.ctx.storage.sql.exec('INSERT INTO key_state(id,value) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',JSON.stringify(row));}
  protected removingKeyEvidence():void{}
  protected nextCleanupAt():number|undefined{return undefined;}
  protected beforeInstallCommit(_m:StoreMaterial,_now:number):void{}
  protected didInstallCommit(_m:StoreMaterial,_expiresAt:number):void{}
  protected tombstone(r:Active):Tombstone{this.removingKeyEvidence();return {version:1,status:'revoked',keyAddress:r.keyAddress,expiresAt:r.expiresAt,purgeAt:r.expiresAt+120000};}
  protected expire(now:number){
    const r=this.load();if(r?.status==='active'){
      if(now>=r.expiresAt){this.save(this.tombstone(r));return this.load();}
      if(r.challengeExpiresAt!==undefined&&now>=r.challengeExpiresAt){delete r.operationId;delete r.requestDigest;delete r.challengeExpiresAt;r.revision++;this.save(r);}
    }return r;
  }
  protected async arm(){await this.locked(async()=>{const r=this.load(),extra=this.nextCleanupAt();const at=Math.min(r?(r.status==='active'?Math.min(r.challengeExpiresAt??r.expiresAt,r.expiresAt):r.purgeAt):Infinity,extra??Infinity);if(Number.isFinite(at))await this.ctx.storage.setAlarm(at);else await this.ctx.storage.deleteAlarm();});}
  private material(m:StoreMaterial,now:number){
    need(m&&Object.keys(m).sort().join(',')==='appPolicy,challengeCreatedAt,challengeExpiresAt,environment,keyAddress,operationId,publicPoint,receipt,receiptCreatedAt,requestDigest');
    need(/^[a-f0-9]{64}$/.test(m.keyAddress)&&m.appPolicy==='ios-dev-qualification/1'&&m.environment==='development');
    need(/^[a-f0-9]{64}$/.test(m.requestDigest)&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(m.operationId));
    need(canonicalBase64(m.publicPoint,65,65)[0]===4);canonicalBase64(m.receipt,16384);
    need(integer(m.receiptCreatedAt)&&now>=m.receiptCreatedAt&&now-m.receiptCreatedAt<=300000);
    need(integer(m.challengeCreatedAt)&&integer(m.challengeExpiresAt)&&m.challengeExpiresAt>m.challengeCreatedAt&&m.challengeExpiresAt-m.challengeCreatedAt<=120000&&now>=m.challengeCreatedAt&&now<m.challengeExpiresAt);
  }
  // Trusted internal material only. This method does NOT validate App Attest/CMS/status/wire admission.
  protected async installInternal(m:StoreMaterial){
    const now=Date.now();this.material(m,now);const activeKey=this.env.RECEIPT_ACTIVE_KEY;need(activeKey);const version=await keyVersion(activeKey);
    const row:Active={version:1,status:'active',objectId:this.ctx.id.toString(),keyAddress:m.keyAddress,appPolicy:m.appPolicy,environment:m.environment,createdAt:now,expiresAt:now+30*DAY,receiptCreatedAt:m.receiptCreatedAt,keyVersion:version,revision:1,publicPoint:m.publicPoint,counter:0,ciphertext:'',nonce:'',operationId:m.operationId,requestDigest:m.requestDigest,challengeExpiresAt:m.challengeExpiresAt};
    const encrypted=await encryptSecret(JSON.stringify({context:context(row),receipt:m.receipt}),activeKey);
    need(encrypted.keyVersion===version);row.ciphertext=encrypted.ciphertext;row.nonce=encrypted.nonce;
    const result=await this.locked(async()=>{
      const prior=await this.ctx.storage.getAlarm();
      await this.ctx.storage.setAlarm(Math.min(prior??row.expiresAt,row.expiresAt,m.challengeExpiresAt));
      // Durable cleanup trigger is acknowledged BEFORE any sensitive SQL commit.
      return this.ctx.storage.transactionSync(()=>{
      const at=Date.now();this.material(m,at);this.beforeInstallCommit(m,at);need(activeKey===this.env.RECEIPT_ACTIVE_KEY);const old=this.expire(at);
      if(old){need(old.status==='active'&&old.objectId===this.ctx.id.toString()&&old.keyAddress===m.keyAddress&&old.operationId===m.operationId&&old.requestDigest===m.requestDigest&&old.challengeExpiresAt!==undefined&&at<old.challengeExpiresAt);return {scope:'STORE_ONLY_NO_ENROLLMENT',expiresAt:old.expiresAt,duplicate:true};}
      need(at<row.expiresAt);this.save(row);this.didInstallCommit(m,row.expiresAt);return {scope:'STORE_ONLY_NO_ENROLLMENT',expiresAt:row.expiresAt,duplicate:false};
      });
    });
    // A failed later alarm acknowledgement leaves an unknown outcome, never triggers a second key/expiry.
    await this.arm();return result;
  }
  private async evidenceInternal(){
    const at=Date.now(),row=this.ctx.storage.transactionSync(()=>this.expire(at));
    need(row?.status==='active'&&row.objectId===this.ctx.id.toString()&&at<row.expiresAt);
    const keys=[this.env.RECEIPT_ACTIVE_KEY,this.env.RECEIPT_PREVIOUS_KEY].filter((k):k is string=>Boolean(k));
    let plaintext:string|undefined;
    for(const key of keys)if(await keyVersion(key)===row.keyVersion){plaintext=await decryptSecret(row.ciphertext,row.nonce,key);break;}
    need(plaintext);const parsed=JSON.parse(plaintext) as {context:Context;receipt:string};
    need(Object.keys(parsed).sort().join(',')==='context,receipt'&&JSON.stringify(parsed.context)===JSON.stringify(context(row)));
    canonicalBase64(parsed.receipt,16384);
    const current=this.ctx.storage.transactionSync(()=>this.expire(Date.now()));
    need(current?.status==='active'&&current.revision===row.revision&&current.objectId===this.ctx.id.toString()&&Date.now()<current.expiresAt);
    return {scope:'PRIVATE_STORE_EVIDENCE_ONLY_NOT_PUBLIC_RESPONSE',receipt:parsed.receipt,expiresAt:current.expiresAt,counter:current.counter};
  }
  private advanceInternal(counter:number){return this.ctx.storage.transactionSync(()=>{const row=this.expire(Date.now());need(row?.status==='active'&&row.objectId===this.ctx.id.toString()&&Number.isInteger(counter)&&counter>row.counter&&counter<=0xffffffff);row.counter=counter;row.revision++;this.save(row);return {scope:'STORE_COUNTER_ONLY_NOT_ASSERTION_ADMISSION',counter};});}
  private async revokeInternal(){this.ctx.storage.transactionSync(()=>{const row=this.load();if(row?.status==='active')this.save(this.tombstone(row));});await this.arm();return {scope:'STORE_ONLY_NO_HARDWARE_ERASURE'};}
  private async rotateInternal(){
    const before=this.load();need(before?.status==='active'&&this.env.RECEIPT_ACTIVE_KEY);
    const evidence=await this.evidenceInternal();const version=await keyVersion(this.env.RECEIPT_ACTIVE_KEY);
    const updated={...before,keyVersion:version,revision:before.revision+1};
    const encrypted=await encryptSecret(JSON.stringify({context:context(updated),receipt:evidence.receipt}),this.env.RECEIPT_ACTIVE_KEY);
    need(encrypted.keyVersion===version);
    this.ctx.storage.transactionSync(()=>{const current=this.expire(Date.now());need(current?.status==='active'&&current.revision===before.revision&&current.objectId===this.ctx.id.toString());updated.ciphertext=encrypted.ciphertext;updated.nonce=encrypted.nonce;this.save(updated);});
    return {scope:'STORE_ROTATION_ONLY',expiresAt:updated.expiresAt};
  }
  // Generic typed failures avoid leaking private error details or throwing expected denials through RPC.
  async install(m:StoreMaterial){try{return {ok:true as const,...await this.installInternal(m)};}catch{return {ok:false as const,error:'store_rejected' as const};}}
  async evidence(){try{return {ok:true as const,...await this.evidenceInternal()};}catch{return {ok:false as const,error:'store_rejected' as const};}}
  async advance(counter:number){try{return {ok:true as const,...this.advanceInternal(counter)};}catch{return {ok:false as const,error:'store_rejected' as const};}}
  async revoke(){try{return {ok:true as const,...await this.revokeInternal()};}catch{return {ok:false as const,error:'store_rejected' as const};}}
  async rotate(){try{return {ok:true as const,...await this.rotateInternal()};}catch{return {ok:false as const,error:'store_rejected' as const};}}
  async alarm(){
    try {
    this.ctx.storage.transactionSync(()=>{const row=this.expire(Date.now());if(row?.status==='revoked'&&Date.now()>=row.purgeAt)this.ctx.storage.sql.exec('DELETE FROM key_state WHERE id=1');});
    await this.arm();
    } catch { throw new Error('qualification_cleanup_failed'); }
  }
}
