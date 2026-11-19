/** Installation R2 transaction engine. No production authority/provider is supplied. */
import {canonical} from '../../src/surface-push/wire';
import {checkBootstrapChain,checkOriginalWithdrawal,checkCommittedWithdrawalData,decodeRecord,type RecordData} from '../installation-principal/codec-data';
import {verifyPossessionData} from '../principal-possession/possession-data';

export const CLASSIFICATION='INSTALLATION_REGISTRY_TRANSACTION_DATA_ONLY' as const;
type Row=Record<string,SqlStorageValue>;
type Action='initialize'|'prepare'|'admit'|'withdraw'|'read';
export interface OriginalContext {
  readonly action:Action;
  readonly storage:DurableObjectStorage;
  readonly registry_identity_sha256:string;
  readonly registry_restore_policy_sha256:string;
  /** Exact owned primitive records, not bearer credentials or authority by themselves. */
  readonly records:Readonly<Record<string,string>>;
  readonly signal:AbortSignal;
}
/** Must independently authenticate management/install/custody/currentness/clock/withdrawal.
 * No implementation, Boolean grant, default owner or production factory is provided here. */
export interface RegistryAuthority {assertOriginal(context:OriginalContext):unknown}
export class RegistryTransactionError extends Error {
  constructor(readonly code:'CONFLICT'|'CAPACITY'|'CLOSED'|'INVALID'='CONFLICT') {super('installation_registry_'+code.toLowerCase());}
}
function need(ok:unknown,code:RegistryTransactionError['code']='INVALID'):asserts ok {if(!ok)throw new RegistryTransactionError(code);}
function hash(v:unknown):asserts v is string {need(typeof v==='string'&&/^[a-f0-9]{64}$/.test(v));}
function uuid(v:unknown):asserts v is string {need(typeof v==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v));}
function integer(v:unknown,min=0):asserts v is number {need(Number.isSafeInteger(v)&&(v as number)>=min&&(v as number)<Number.MAX_SAFE_INTEGER);}
const CHAIN=['generation','receipt','subject','context','proof','original_expected_transcript'] as const;
function snapshot(input:unknown,fields:readonly string[]):Readonly<Record<string,string>> {
  need(input!==null&&typeof input==='object'&&(Object.getPrototypeOf(input)===Object.prototype||Object.getPrototypeOf(input)===null));
  const descriptors=Object.getOwnPropertyDescriptors(input);need(Reflect.ownKeys(descriptors).length===fields.length);
  const result:Record<string,string>={};
  for(const k of fields){const d=descriptors[k];need(d&&Object.hasOwn(d,'value')&&typeof d.value==='string'&&d.value.length<=32768);result[k]=d.value;}
  return Object.freeze(result);
}
function equal(a:unknown,b:unknown){need(a===b,'CONFLICT');}
const DDL=`
CREATE TABLE IF NOT EXISTS ir_meta(id INTEGER PRIMARY KEY CHECK(id=1),identity TEXT NOT NULL,restore TEXT NOT NULL,state_revision INTEGER NOT NULL,ledger_revision INTEGER NOT NULL,max_intents INTEGER NOT NULL,max_claims INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS ir_claims(namespace TEXT NOT NULL,value TEXT NOT NULL,operation TEXT NOT NULL,PRIMARY KEY(namespace,value)) STRICT;
CREATE TABLE IF NOT EXISTS ir_intents(operation TEXT PRIMARY KEY,principal TEXT NOT NULL,epoch INTEGER NOT NULL,subject TEXT NOT NULL,intent TEXT NOT NULL,chain TEXT NOT NULL,stage TEXT NOT NULL,UNIQUE(principal,epoch)) STRICT;
CREATE TABLE IF NOT EXISTS ir_operations(operation TEXT PRIMARY KEY,kind TEXT NOT NULL,preparation TEXT NOT NULL,tag TEXT NOT NULL,result TEXT,revision INTEGER,withdrawal TEXT) STRICT;
CREATE TABLE IF NOT EXISTS ir_principals(principal TEXT NOT NULL,epoch INTEGER NOT NULL,operation TEXT NOT NULL UNIQUE,body TEXT NOT NULL,PRIMARY KEY(principal,epoch)) STRICT;
CREATE TABLE IF NOT EXISTS ir_retired(operation TEXT PRIMARY KEY,withdrawal TEXT NOT NULL UNIQUE,preparation TEXT NOT NULL,body TEXT NOT NULL) STRICT;
`;
/** The store is one actual DO SQLite transaction domain, distinct from Core's once ledger.
 * Required owner ports are injected only by an independently qualified composition. */
export class InstallationRegistry {
  readonly #storage:DurableObjectStorage;
  readonly #assertOriginal:(context:OriginalContext)=>unknown;
  readonly #identity:string;
  readonly #restore:string;
  #closed=false;
  constructor(storage:DurableObjectStorage,authority:RegistryAuthority,identity:string,restore:string){
    hash(identity);hash(restore);const assertOriginal=authority?.assertOriginal;need(storage&&typeof assertOriginal==='function');
    // Capture the exact original port; replacing a property during crypto cannot swap authority.
    this.#storage=storage;this.#assertOriginal=context=>assertOriginal.call(authority,context);this.#identity=identity;this.#restore=restore;
  }
  /** Local positive fence only; independently authorized negative withdrawal remains possible. */
  close():void {this.#closed=true;}
  #sql(sql:string,...args:SqlStorageValue[]):Row[]{return this.#storage.sql.exec(sql,...args).toArray();}
  #meta():Row {const m=this.#sql('SELECT * FROM ir_meta WHERE id=1')[0];need(m,'CLOSED');equal(m.identity,this.#identity);equal(m.restore,this.#restore);return m;}
  #guard(action:Action,records:Readonly<Record<string,string>>,signal:AbortSignal):void {
    need(signal&&typeof signal.aborted==='boolean'&&!signal.aborted,'CLOSED');
    need(action==='withdraw'||!this.#closed,'CLOSED');
    const context=Object.freeze({action,storage:this.#storage,registry_identity_sha256:this.#identity,registry_restore_policy_sha256:this.#restore,records,signal});
    // Not awaited: an asynchronous validator cannot authorize the final synchronous SQL boundary.
    const result=this.#assertOriginal(context);need(result===undefined,'CLOSED');
    need(!signal.aborted&&(action==='withdraw'||!this.#closed),'CLOSED');
  }
  #tick(m:Row,state=false):number {
    const ledger=Number(m.ledger_revision)+1;integer(ledger,1);
    const revision=Number(m.state_revision)+(state?1:0);integer(revision);
    this.#sql('UPDATE ir_meta SET ledger_revision=?,state_revision=? WHERE id=1',ledger,revision);
    return revision;
  }
  #claims(operation:string,challenge:string,nonce:string):void {
    uuid(operation);uuid(challenge);hash(nonce);
    for(const [ns,value]of [['operation',operation],['challenge',challenge],['nonce',nonce]])
      this.#sql('INSERT INTO ir_claims VALUES(?,?,?)',ns,value,operation);
  }
  #capacity(m:Row):void {
    const used=Number(this.#sql('SELECT count(*) AS n FROM ir_claims')[0].n);
    const pending=Number(this.#sql("SELECT count(*) AS n FROM ir_intents WHERE stage!='RETIRED'")[0].n);
    const count=Number(this.#sql('SELECT count(*) AS n FROM ir_intents')[0].n);
    // Every new intent spends three identity claims and retains three for ONE withdrawal.
    need(count<Number(m.max_intents)&&used+3*pending+6<=Number(m.max_claims),'CAPACITY');
  }
  #original(row:Row,v:Readonly<Record<string,string>>):void {equal(row.chain,canonical(Object.fromEntries(CHAIN.map(k=>[k,v[k]]))));equal(row.intent,v.intent);}
  #binding(values:Readonly<Record<string,unknown>>):void {equal(values.registry_identity_sha256,this.#identity);equal(values.registry_restore_policy_sha256,this.#restore);}
  async initialize(maxIntents:number,maxClaims:number,signal:AbortSignal):Promise<void> {
    integer(maxIntents,1);integer(maxClaims,6);
    const records=Object.freeze({max_intents:String(maxIntents),max_claims:String(maxClaims)});
    this.#storage.transactionSync(()=>{this.#guard('initialize',records,signal);this.#sql(DDL);need(this.#sql('SELECT * FROM ir_meta').length===0,'CONFLICT');
      this.#sql('INSERT INTO ir_meta VALUES(1,?,?,0,0,?,?)',this.#identity,this.#restore,maxIntents,maxClaims);});
    await this.#storage.sync();this.#guard('initialize',records,signal);this.#meta();
  }
  async prepare(input:unknown,signal:AbortSignal):Promise<string> {
    const v=snapshot(input,[...CHAIN,'intent']);const b=await checkBootstrapChain(Object.fromEntries(CHAIN.map(k=>[k,v[k]])));
    const i=await decodeRecord(v.intent,'original_admission_intent'),iv=i.values,t=b.transcript.values,s=b.subject.values;
    equal(iv.bootstrap_preparation_sha256,b.proof.digest);equal(iv.admission_context_sha256,b.context.digest);equal(iv.subject_sha256,b.subject.digest);
    for(const k of ['registration_operation_id','challenge_id','challenge_nonce_sha256','expected_registry_revision','original_authorization_deadline_unix_ms'])equal(iv[k],t[k]);
    this.#binding(t);need(t.registration_operation_id!==b.generation.values.custody_operation_id,'CONFLICT');
    this.#storage.transactionSync(()=>{
      this.#guard('prepare',v,signal);const m=this.#meta();equal(m.state_revision,t.expected_registry_revision);this.#capacity(m);
      const head=this.#sql('SELECT epoch,stage FROM ir_intents WHERE principal=? ORDER BY epoch DESC LIMIT 1',s.principal_id as string)[0];
      if(head){equal(s.principal_epoch,Number(head.epoch)+1);equal(head.stage,'RETIRED');}else equal(s.principal_epoch,1);
      const op=t.registration_operation_id as string;this.#claims(op,t.challenge_id as string,t.challenge_nonce_sha256 as string);
      this.#sql("INSERT INTO ir_intents VALUES(?,?,?,?,?,?,'PREPARED')",op,s.principal_id as string,s.principal_epoch as number,b.subject.digest,v.intent,canonical(Object.fromEntries(CHAIN.map(k=>[k,v[k]]))));
      this.#sql("INSERT INTO ir_operations VALUES(?,'registry_admission',?,'RESERVED',NULL,NULL,NULL)",op,b.proof.digest);this.#tick(m);
    });
    await this.#storage.sync();this.#guard('prepare',v,signal);this.#meta();
    const row=this.#sql('SELECT * FROM ir_intents WHERE operation=?',t.registration_operation_id as string)[0];equal(row?.stage,'PREPARED');this.#original(row,v);
    return this.#status(t.registration_operation_id as string,b.proof.digest,v,signal);
  }
  async admit(input:unknown,signal:AbortSignal):Promise<string> {
    const v=snapshot(input,[...CHAIN,'intent','proof_body','signature_b64url','accepted_independent_authority_bundle_sha256']);hash(v.accepted_independent_authority_bundle_sha256);
    const b=await checkBootstrapChain(Object.fromEntries(CHAIN.map(k=>[k,v[k]])));this.#binding(b.transcript.values);
    const op=b.transcript.values.registration_operation_id as string;
    // Durable attempt consumption precedes awaited crypto. No retry on invalid proof or failure.
    this.#storage.transactionSync(()=>{
      this.#guard('admit',v,signal);const m=this.#meta();equal(m.state_revision,b.transcript.values.expected_registry_revision);
      const row=this.#sql('SELECT * FROM ir_intents WHERE operation=?',op)[0];need(row,'CONFLICT');this.#original(row,v);equal(row.stage,'PREPARED');
      this.#sql("UPDATE ir_intents SET stage='ATTEMPTED' WHERE operation=?",op);
      this.#sql("UPDATE ir_operations SET tag='UNKNOWN' WHERE operation=?",op);this.#tick(m);
    });
    await this.#storage.sync();this.#guard('admit',v,signal);
    const proof=await verifyPossessionData(b.transcript.canonical_text,v.proof_body,v.signature_b64url);need(proof,'INVALID');
    this.#storage.transactionSync(()=>{
      this.#guard('admit',v,signal);const m=this.#meta();equal(m.state_revision,b.transcript.values.expected_registry_revision);
      const row=this.#sql('SELECT * FROM ir_intents WHERE operation=?',op)[0];need(row,'CONFLICT');this.#original(row,v);equal(row.stage,'ATTEMPTED');
      need(this.#sql('SELECT * FROM ir_retired WHERE operation=?',op).length===0,'CLOSED');
      const revision=this.#tick(m,true);
      const body=canonical({accepted_independent_authority_bundle_sha256:v.accepted_independent_authority_bundle_sha256,
        bootstrap_preparation_sha256:b.proof.digest,challenge_id:proof.challenge_id,crypto_possession_body_sha256:proof.body_sha256,
        crypto_signing_input_sha256:proof.signing_input_sha256,kind:'installation-principal-record/2',
        original_authorization_deadline_unix_ms:proof.original_authorization_deadline_unix_ms,public_key_pin_sha256:proof.public_key_pin_sha256,
        registration_operation_id:op,registry_committed_revision:revision,subject_sha256:b.subject.digest,version:2});
      this.#sql('INSERT INTO ir_principals VALUES(?,?,?,?)',b.subject.values.principal_id as string,b.subject.values.principal_epoch as number,op,body);
      this.#sql("UPDATE ir_intents SET stage='COMMITTED' WHERE operation=?",op);
      this.#sql("UPDATE ir_operations SET tag='COMMITTED',result=?,revision=? WHERE operation=?",body,revision,op);
    });
    await this.#storage.sync();return this.#status(op,b.proof.digest,v,signal);
  }
  async withdrawOriginal(input:unknown,signal:AbortSignal):Promise<string> {
    const v=snapshot(input,[...CHAIN,'intent','withdrawal']);const b=await checkOriginalWithdrawal(v);this.#binding(b.withdrawal.values);
    return this.#withdraw(v,b.withdrawal,b.subject.digest,undefined,signal);
  }
  async withdrawCommitted(input:unknown,signal:AbortSignal):Promise<string> {
    const v=snapshot(input,[...CHAIN,'principal','withdrawal']);const b=await checkCommittedWithdrawalData(v);this.#binding(b.withdrawal.values);
    return this.#withdraw(v,b.withdrawal,b.subject.digest,b.principal.canonical_text,signal);
  }
  async #withdraw(v:Readonly<Record<string,string>>,w:Readonly<RecordData>,subject:string,principal:string|undefined,signal:AbortSignal):Promise<string> {
    const x=w.values,op=x.registration_operation_id as string,withdrawal=x.withdrawal_operation_id as string;
    this.#guard('withdraw',v,signal);this.#meta();
    const original=this.#sql('SELECT intent FROM ir_intents WHERE operation=?',op)[0];need(original,'CONFLICT');
    const originalIntent=await decodeRecord(original.intent,'original_admission_intent');
    this.#storage.transactionSync(()=>{
      this.#guard('withdraw',v,signal);const m=this.#meta();
      const row=this.#sql('SELECT * FROM ir_intents WHERE operation=?',op)[0];need(row,'CONFLICT');equal(row.subject,subject);
      equal(row.intent,originalIntent.canonical_text);
      const chain=JSON.parse(row.chain as string) as Record<string,string>;for(const k of CHAIN)equal(chain[k],v[k]);
      const retired=this.#sql('SELECT * FROM ir_retired WHERE operation=?',op)[0];
      if(retired){equal(retired.withdrawal,withdrawal);equal(retired.preparation,w.canonical_text);return;}
      if(principal!==undefined){equal(m.state_revision,x.expected_registry_revision);equal(this.#sql('SELECT body FROM ir_principals WHERE operation=?',op)[0]?.body,principal);}
      else equal(row.intent,v.intent);
      const intent=JSON.parse(row.intent as string) as Record<string,unknown>;
      equal(x.withdrawal_policy_sha256,intent.withdrawal_policy_sha256);
      const challenge=(principal===undefined?x.withdrawal_challenge_id:x.challenge_id) as string;
      const nonce=(principal===undefined?x.withdrawal_challenge_nonce_sha256:x.challenge_nonce_sha256) as string;
      need(withdrawal!==op&&challenge!==intent.challenge_id&&nonce!==intent.challenge_nonce_sha256,'CONFLICT');
      // Both withdrawal variants share the THREE slots reserved by this one intent.
      this.#claims(withdrawal,challenge,nonce);const revision=this.#tick(m,true);
      const body=canonical({kind:'original-admission-retirement/2',original_admission_intent_sha256:originalIntent.digest,
        registration_challenge_id:intent.challenge_id,registration_challenge_nonce_sha256:intent.challenge_nonce_sha256,
        registration_operation_id:op,registry_committed_revision:revision,subject_sha256:subject,version:2,
        withdrawal_operation_id:withdrawal,withdrawal_preparation_sha256:w.digest});
      this.#sql('INSERT INTO ir_retired VALUES(?,?,?,?)',op,withdrawal,w.canonical_text,body);
      this.#sql("UPDATE ir_intents SET stage='RETIRED' WHERE operation=?",op);
      this.#sql("UPDATE ir_operations SET tag='RETIRED',revision=?,withdrawal=? WHERE operation=?",revision,withdrawal,op);
      this.#sql("INSERT INTO ir_operations VALUES(?,'withdrawal',?,'COMMITTED',?,?,NULL)",withdrawal,w.digest,body,revision);
    });
    await this.#storage.sync();return this.#status(withdrawal,w.digest,v,signal,true);
  }
  async readPrincipal(input:unknown,signal:AbortSignal):Promise<Readonly<RecordData>> {
    const v=snapshot(input,[...CHAIN,'intent']);const b=await checkBootstrapChain(Object.fromEntries(CHAIN.map(k=>[k,v[k]])));
    this.#binding(b.transcript.values);const operation=b.transcript.values.registration_operation_id as string;
    let body='',revision=0;
    const capture=()=>{this.#guard('read',v,signal);const m=this.#meta();
      const row=this.#sql('SELECT * FROM ir_intents WHERE operation=?',operation)[0];need(row,'CLOSED');this.#original(row,v);equal(row.stage,'COMMITTED');
      need(this.#sql('SELECT * FROM ir_retired WHERE operation=?',operation).length===0,'CLOSED');
      return {body:this.#sql('SELECT body FROM ir_principals WHERE operation=?',operation)[0]?.body,revision:m.state_revision};};
    this.#storage.transactionSync(()=>{const c=capture();need(typeof c.body==='string');body=c.body;revision=Number(c.revision);});
    const result=await decodeRecord(body,'installation_principal_record');
    this.#storage.transactionSync(()=>{const c=capture();equal(c.body,body);equal(c.revision,revision);});
    return result; // Original point-in-time DATA, never a currentness lease or signing capability.
  }
  async status(operation:string,preparation:string,kind:'registry_admission'|'withdrawal',signal:AbortSignal):Promise<string>{
    uuid(operation);hash(preparation);need(kind==='registry_admission'||kind==='withdrawal');
    return this.#status(operation,preparation,Object.freeze({operation,preparation,kind}),signal,false,kind);
  }
  async #status(operation:string,preparation:string,records:Readonly<Record<string,string>>,signal:AbortSignal,negative=false,expectedKind?:'registry_admission'|'withdrawal'):Promise<string>{
    this.#guard(negative?'withdraw':'read',records,signal);let row:Row|undefined,ledger=0;
    this.#storage.transactionSync(()=>{this.#meta();row=this.#sql('SELECT * FROM ir_operations WHERE operation=?',operation)[0];ledger=Number(this.#meta().ledger_revision);if(row)equal(row.preparation,preparation);});
    if(!row)return canonical({classification:CLASSIFICATION,status:{kind:'operation-status/1',ledger_revision:ledger,operation_id:operation,
      operation_kind:expectedKind??'registry_admission',outcome:{tag:'NOT_FOUND_DATA'},preparation_sha256:preparation,version:1}});
    if(expectedKind)equal(row.kind,expectedKind);
    const saved=row;let outcome:Record<string,unknown>;
    if(saved.tag==='COMMITTED'){
      const kind=saved.kind==='withdrawal'?'original_admission_retirement_tombstone':'installation_principal_record';
      const result=await decodeRecord(saved.result,kind);outcome={tag:'COMMITTED',committed_revision:saved.revision,result_sha256:result.digest};
    }else if(saved.tag==='RETIRED')outcome={tag:'RETIRED',committed_revision:saved.revision,withdrawal_operation_id:saved.withdrawal};
    else if(saved.tag==='UNKNOWN')outcome={tag:'UNKNOWN',cause_class:'INTERRUPTED_EFFECT'};
    else outcome={tag:'RESERVED'};
    this.#guard(negative?'withdraw':'read',records,signal);this.#meta();
    // Do not return a positive result captured before a concurrent withdrawal or mutation.
    equal(canonical(this.#sql('SELECT * FROM ir_operations WHERE operation=?',operation)[0]),canonical(saved));
    const wire=canonical({kind:'operation-status/1',ledger_revision:ledger,operation_id:operation,operation_kind:saved.kind,outcome,preparation_sha256:preparation,version:1});
    return canonical({classification:CLASSIFICATION,status:JSON.parse(wire)});
  }
}
