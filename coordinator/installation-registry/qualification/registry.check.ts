import {it,expect,vi,beforeEach,afterEach} from 'vitest';
import {env} from 'cloudflare:workers';
import {SELF,runInDurableObject} from 'cloudflare:test';
import type {QualificationRegistry} from './worker';
import {InstallationRegistry,RegistryTransactionError,type RegistryAuthority,type OriginalContext} from '../registry';
import {canonical} from '../../../src/surface-push/wire';
import {decodeRecord} from '../../installation-principal/codec-data';
import {fixture,H,U} from './fixtures';
import closedWorker,{createProductionInstallationRegistry} from '../worker';

declare global {namespace Cloudflare {interface Env {INSTALLATION_REGISTRY_TEST:DurableObjectNamespace<QualificationRegistry>}}}
declare module 'cloudflare:test' {interface ProvidedEnv {INSTALLATION_REGISTRY_TEST:DurableObjectNamespace<QualificationRegistry>}}
type F=Awaited<ReturnType<typeof fixture>>;
type Stub=DurableObjectStub<QualificationRegistry>;
const signal=()=>new AbortController().signal;
const owner:RegistryAuthority={assertOriginal(){/* Explicit synthetic authority, NOT live admission. */}};
async function using<T>(stub:Stub,f:F,fn:(r:InstallationRegistry,state:DurableObjectState)=>Promise<T>,authority=owner){
 return runInDurableObject(stub,async(_instance,state)=>fn(new InstallationRegistry(state.storage,authority,f.identity,f.restore),state));
}
async function setup(intents=4,claims=24){const f=await fixture(),s=env.INSTALLATION_REGISTRY_TEST.get(env.INSTALLATION_REGISTRY_TEST.newUniqueId());await using(s,f,async r=>r.initialize(intents,claims,signal()));return {s,f};}
const prepare=(s:Stub,f:F)=>using(s,f,async r=>JSON.parse(await r.prepare(f.prepare,signal())));
const admit=(s:Stub,f:F)=>using(s,f,async r=>JSON.parse(await r.admit(f.admit,signal())));
const withdraw=(s:Stub,f:F)=>using(s,f,async r=>JSON.parse(await r.withdrawOriginal(f.withdraw,signal())));
const status=(s:Stub,f:F)=>using(s,f,async r=>JSON.parse(await r.status(f.operation,f.proofHash,'registry_admission',signal())));
async function rows(s:Stub,table:string){return runInDurableObject(s,(_i,state)=>state.storage.sql.exec(`SELECT * FROM ${table}`).toArray());}
let noGenerate:ReturnType<typeof vi.spyOn>,noSign:ReturnType<typeof vi.spyOn>,noFetch:ReturnType<typeof vi.spyOn>;
beforeEach(()=>{noGenerate=vi.spyOn(crypto.subtle,'generateKey').mockImplementation(()=>{throw Error('generation forbidden');});noSign=vi.spyOn(crypto.subtle,'sign').mockImplementation(()=>{throw Error('signing forbidden');});noFetch=vi.spyOn(globalThis,'fetch').mockImplementation(()=>{throw Error('egress forbidden');});});
afterEach(()=>{expect(noGenerate).not.toHaveBeenCalled();expect(noSign).not.toHaveBeenCalled();expect(noFetch).not.toHaveBeenCalled();vi.restoreAllMocks();});

it('qualification Worker offers no command RPC or HTTP admission',async()=>{const res=await SELF.fetch('https://closed.invalid/register',{method:'POST'});expect(res.status).toBe(503);expect(res.headers.get('Cache-Control')).toBe('no-store');});
it('prepares original intent/claims and terminal reserve without changing state revision',async()=>{const {s,f}=await setup();expect((await prepare(s,f)).status.outcome.tag).toBe('RESERVED');expect(await rows(s,'ir_claims')).toHaveLength(3);expect((await rows(s,'ir_meta'))[0]).toMatchObject({state_revision:0,ledger_revision:1});expect(await rows(s,'ir_principals')).toHaveLength(0);});
it('performs actual public WebCrypto verify then atomic admission and exact status digest',async()=>{const {s,f}=await setup();await prepare(s,f);const reply=await admit(s,f);expect(reply.status.outcome.tag).toBe('COMMITTED');const body=(await rows(s,'ir_principals'))[0].body;const d=await decodeRecord(body,'installation_principal_record');expect(reply.status.outcome.result_sha256).toBe(d.digest);expect(d.values.registry_committed_revision).toBe(1);expect((await rows(s,'ir_meta'))[0]).toMatchObject({state_revision:1,ledger_revision:3});});
it('original pending withdrawal needs no principal result or caller current revision',async()=>{const {s,f}=await setup();await prepare(s,f);expect((await withdraw(s,f)).status.outcome.tag).toBe('COMMITTED');expect((await status(s,f)).status.outcome.tag).toBe('RETIRED');expect(await rows(s,'ir_principals')).toHaveLength(0);await expect(admit(s,f)).rejects.toThrow();});
it('original withdrawal resolves committed lost-reply principal and fences only its operation',async()=>{const {s,f}=await setup();await prepare(s,f);await admit(s,f);const w=await withdraw(s,f);const tomb=await decodeRecord((await rows(s,'ir_retired'))[0].body,'original_admission_retirement_tombstone');expect(w.status.outcome.result_sha256).toBe(tomb.digest);expect(tomb.values.original_admission_intent_sha256).toBe(f.intentHash);expect(await rows(s,'ir_principals')).toHaveLength(1);expect((await status(s,f)).status.outcome.tag).toBe('RETIRED');});
it('known-result withdrawal uses its exact closed variant and shared original terminal reserve',async()=>{const {s,f}=await setup(1,6);await prepare(s,f);await admit(s,f);const principal=(await rows(s,'ir_principals'))[0].body as string,p=await decodeRecord(principal,'installation_principal_record');const w=canonical({challenge_id:U(500),challenge_nonce_sha256:H(501),expected_registry_revision:1,kind:'installation-principal-withdrawal/2',original_withdrawal_deadline_unix_ms:1712345900000,principal_record_sha256:p.digest,registration_operation_id:f.operation,registry_identity_sha256:f.identity,registry_restore_policy_sha256:f.restore,subject_sha256:p.values.subject_sha256,version:2,withdrawal_authority_record_sha256:H(502),withdrawal_operation_id:U(503),withdrawal_policy_sha256:JSON.parse(f.intent).withdrawal_policy_sha256});const out=await using(s,f,async r=>JSON.parse(await r.withdrawCommitted({...f.chain,principal,withdrawal:w},signal())));expect(out.status.outcome.tag).toBe('COMMITTED');expect(await rows(s,'ir_claims')).toHaveLength(6);await expect(withdraw(s,f)).rejects.toThrow();});
it('a full intent/claim budget retains its reserved pending withdrawal',async()=>{const {s,f}=await setup(1,6);await prepare(s,f);const other=await fixture(2);await expect(prepare(s,other)).rejects.toMatchObject({code:'CAPACITY'});await withdraw(s,f);expect(await rows(s,'ir_claims')).toHaveLength(6);await expect(prepare(s,other)).rejects.toThrow();});
it('capacity counts reserved terminal identities even before actual principal exists',async()=>{const {s,f}=await setup(2,6);await prepare(s,f);await expect(prepare(s,await fixture(2))).rejects.toMatchObject({code:'CAPACITY'});await withdraw(s,f);});
it('does not let another original intent spend existing withdrawal capacity',async()=>{const {s,f}=await setup(2,12);await prepare(s,f);const g=await fixture(2);await prepare(s,g);await withdraw(s,f);await withdraw(s,g);expect(await rows(s,'ir_retired')).toHaveLength(2);expect(await rows(s,'ir_claims')).toHaveLength(12);});
it.each(['prepare','admit'] as const)('duplicate %s cannot create a second attempt or identity',async method=>{const {s,f}=await setup();await prepare(s,f);if(method==='admit')await admit(s,f);await expect(method==='prepare'?prepare(s,f):admit(s,f)).rejects.toThrow();expect(await rows(s,'ir_intents')).toHaveLength(1);expect(await rows(s,'ir_claims')).toHaveLength(3);});
it('same exact withdrawal only reads original result; alternate IDs cannot spend extra terminal slots',async()=>{const {s,f}=await setup();await prepare(s,f);const first=await withdraw(s,f),again=await withdraw(s,f);expect(again.status.outcome).toEqual(first.status.outcome);const w=canonical({...JSON.parse(f.withdrawal),withdrawal_operation_id:U(999)});await expect(using(s,f,async r=>r.withdrawOriginal({...f.withdraw,withdrawal:w},signal()))).rejects.toThrow();expect(await rows(s,'ir_claims')).toHaveLength(6);expect(await rows(s,'ir_operations')).toHaveLength(2);});
it('invalid proof is consumed before verification and cannot retry with a later valid proof',async()=>{const {s,f}=await setup();await prepare(s,f);const bad={...f.admit,signature_b64url:f.signature.slice(0,20)+(f.signature[20]==='A'?'B':'A')+f.signature.slice(21)};await expect(using(s,f,async r=>r.admit(bad,signal()))).rejects.toThrow();expect((await status(s,f)).status.outcome.tag).toBe('UNKNOWN');await expect(admit(s,f)).rejects.toThrow();expect(await rows(s,'ir_principals')).toHaveLength(0);await withdraw(s,f);});
it('original expected body is mandatory even when another well-formed transcript is supplied',async()=>{const {s,f}=await setup();await prepare(s,f);await expect(using(s,f,async r=>r.admit({...f.admit,proof_body:(await fixture(2)).body},signal()))).rejects.toThrow();expect((await status(s,f)).status.outcome.tag).toBe('UNKNOWN');});
it('unexpected crypto failures preserve identical original cause and durable consumed attempt',async()=>{const {s,f}=await setup();await prepare(s,f);const cause=new Error('original synthetic verify failure');const spy=vi.spyOn(crypto.subtle,'verify').mockRejectedValue(cause);try{await expect(admit(s,f)).rejects.toBe(cause);}finally{spy.mockRestore();}expect((await status(s,f)).status.outcome.tag).toBe('UNKNOWN');expect(await rows(s,'ir_principals')).toHaveLength(0);});
it('concurrent preparation has one winner and no partial claims from loser',async()=>{const {s,f}=await setup();const result=await Promise.allSettled([prepare(s,f),prepare(s,f)]);expect(result.filter(x=>x.status==='fulfilled')).toHaveLength(1);expect(await rows(s,'ir_claims')).toHaveLength(3);});
it('concurrent admission consumes one attempt and imports/verifies at most once',async()=>{const {s,f}=await setup();await prepare(s,f);const spy=vi.spyOn(crypto.subtle,'verify');const result=await Promise.allSettled([admit(s,f),admit(s,f)]);expect(result.filter(x=>x.status==='fulfilled')).toHaveLength(1);expect(spy).toHaveBeenCalledTimes(1);expect(await rows(s,'ir_principals')).toHaveLength(1);});
it('withdrawal while crypto is pending prevents later admission final CAS',async()=>{const {s,f}=await setup();await prepare(s,f);await using(s,f,async r=>{const original=crypto.subtle.verify.bind(crypto.subtle);let reached!:()=>void,release!:()=>void;const started=new Promise<void>(done=>reached=done),gate=new Promise<void>(done=>release=done);const spy=vi.spyOn(crypto.subtle,'verify').mockImplementation(async(...args)=>{reached();await gate;return original(...args);});try{const pending=r.admit(f.admit,signal());await started;await r.withdrawOriginal(f.withdraw,signal());release();await expect(pending).rejects.toThrow();}finally{release();spy.mockRestore();}});expect(await rows(s,'ir_principals')).toHaveLength(0);expect((await status(s,f)).status.outcome.tag).toBe('RETIRED');});
it('admission serializing first does not make subsequent original withdrawal stale',async()=>{const {s,f}=await setup();await prepare(s,f);await admit(s,f);await withdraw(s,f);expect((await rows(s,'ir_meta'))[0].state_revision).toBe(2);});
it('a state change invalidates other old-revision admissions without renewing their intent',async()=>{const {s,f}=await setup();const g=await fixture(2);await prepare(s,f);await prepare(s,g);await admit(s,f);await expect(admit(s,g)).rejects.toThrow();expect((await rows(s,'ir_intents')).find(r=>r.operation===g.operation)?.stage).toBe('PREPARED');await withdraw(s,g);});
it('real SQL trigger fault after claim insertion atomically rolls back prepare',async()=>{const {s,f}=await setup();await runInDurableObject(s,(_i,state)=>state.storage.sql.exec("CREATE TRIGGER fail_intent BEFORE INSERT ON ir_intents BEGIN SELECT RAISE(ABORT,'qualification abort'); END").toArray());await expect(prepare(s,f)).rejects.toThrow();expect(await rows(s,'ir_claims')).toHaveLength(0);expect(await rows(s,'ir_operations')).toHaveLength(0);expect((await rows(s,'ir_meta'))[0].ledger_revision).toBe(0);});
it('real SQL fault in admission rolls back result/state mutation but preserves prior attempt',async()=>{const {s,f}=await setup();await prepare(s,f);await runInDurableObject(s,(_i,state)=>state.storage.sql.exec("CREATE TRIGGER fail_principal BEFORE INSERT ON ir_principals BEGIN SELECT RAISE(ABORT,'qualification abort'); END").toArray());await expect(admit(s,f)).rejects.toThrow();expect((await rows(s,'ir_intents'))[0].stage).toBe('ATTEMPTED');expect((await rows(s,'ir_meta'))[0].state_revision).toBe(0);expect(await rows(s,'ir_principals')).toHaveLength(0);await withdraw(s,f);});
it('withdrawal trigger abort rolls back nonce/tombstone and preserves original committed principal',async()=>{const {s,f}=await setup();await prepare(s,f);await admit(s,f);await runInDurableObject(s,(_i,state)=>state.storage.sql.exec("CREATE TRIGGER fail_retirement BEFORE INSERT ON ir_retired BEGIN SELECT RAISE(ABORT,'qualification abort'); END").toArray());await expect(withdraw(s,f)).rejects.toThrow();expect(await rows(s,'ir_claims')).toHaveLength(3);expect((await status(s,f)).status.outcome.tag).toBe('COMMITTED');expect((await rows(s,'ir_meta'))[0].state_revision).toBe(1);});
it.each(['prepare','admit','withdraw'] as const)('post-persistence lost ACK on %s preserves actual committed state',async method=>{const {s,f}=await setup();if(method!=='prepare')await prepare(s,f);if(method==='withdraw')await admit(s,f);const cause=new Error('synthetic lost original sync ACK');await using(s,f,async(r,state)=>{const sync=state.storage.sync.bind(state.storage);const spy=vi.spyOn(state.storage,'sync').mockImplementation(async()=>{await sync();throw cause;});try{await expect(method==='prepare'?r.prepare(f.prepare,signal()):method==='admit'?r.admit(f.admit,signal()):r.withdrawOriginal(f.withdraw,signal())).rejects.toBe(cause);}finally{spy.mockRestore();}});const stage=(await rows(s,'ir_intents'))[0].stage;expect(stage).toBe(method==='prepare'?'PREPARED':method==='admit'?'ATTEMPTED':'RETIRED');if(method==='prepare')await expect(prepare(s,f)).rejects.toThrow();if(method==='admit')await expect(admit(s,f)).rejects.toThrow();});
it('post-admission persistence failure is not rollback and original withdrawal still resolves it',async()=>{const {s,f}=await setup();await prepare(s,f);await using(s,f,async(r,state)=>{let calls=0;const sync=state.storage.sync.bind(state.storage);const spy=vi.spyOn(state.storage,'sync').mockImplementation(async()=>{await sync();if(++calls===2)throw Error('lost admitted ACK');});try{await expect(r.admit(f.admit,signal())).rejects.toThrow('lost admitted ACK');}finally{spy.mockRestore();}});expect(await rows(s,'ir_principals')).toHaveLength(1);await withdraw(s,f);});
it('new engine on same actual storage cannot reset spent attempt or terminal capacity',async()=>{const {s,f}=await setup(1,6);await prepare(s,f);await admit(s,f);await expect(admit(s,f)).rejects.toThrow();await withdraw(s,f);await expect(prepare(s,f)).rejects.toThrow();expect(await rows(s,'ir_claims')).toHaveLength(6);});
it('wrong registry/restore origin closes reads and writes without mutation',async()=>{const {s,f}=await setup();await expect(using(s,{...f,restore:H(100)},async r=>r.prepare(f.prepare,signal()))).rejects.toThrow();expect(await rows(s,'ir_claims')).toHaveLength(0);});
it('missing required owner or a Boolean/async owner is never authority',async()=>{const {s,f}=await setup();await using(s,f,async(_r,state)=>{expect(()=>new InstallationRegistry(state.storage,undefined as unknown as RegistryAuthority,f.identity,f.restore)).toThrow();for(const result of [true,false,Promise.resolve()]){const r=new InstallationRegistry(state.storage,{assertOriginal:()=>result},f.identity,f.restore);await expect(r.prepare(f.prepare,signal())).rejects.toThrow();}});expect(await rows(s,'ir_claims')).toHaveLength(0);});
it('independent owner refusal preserves identical cause and performs no SQL claim',async()=>{const {s,f}=await setup();const cause=new Error('independent actual authority unavailable');await expect(using(s,f,async r=>r.prepare(f.prepare,signal()),{assertOriginal(){throw cause;}})).rejects.toBe(cause);expect(await rows(s,'ir_claims')).toHaveLength(0);});
it('final owner is checked after crypto; a revoked authority cannot admit',async()=>{const {s,f}=await setup();await prepare(s,f);let count=0;const authority={assertOriginal(c:OriginalContext){if(c.action==='admit'&&++count===3)throw Error('retired after crypto');}};await expect(using(s,f,async r=>r.admit(f.admit,signal()),authority)).rejects.toThrow('retired after crypto');expect(await rows(s,'ir_principals')).toHaveLength(0);});
it('reentrant local close during authority validation blocks following SQL mutation',async()=>{const {s,f}=await setup();await runInDurableObject(s,async(_i,state)=>{let r!:InstallationRegistry;r=new InstallationRegistry(state.storage,{assertOriginal(){r.close();}},f.identity,f.restore);await expect(r.prepare(f.prepare,signal())).rejects.toThrow();});expect(await rows(s,'ir_claims')).toHaveLength(0);});
it('local positive close does not block independently authorized original withdrawal',async()=>{const {s,f}=await setup();await prepare(s,f);await using(s,f,async r=>{r.close();await expect(r.admit(f.admit,signal())).rejects.toThrow();expect(JSON.parse(await r.withdrawOriginal(f.withdraw,signal())).status.outcome.tag).toBe('COMMITTED');});});
it('abort after committed prepare keeps original consumed identities and cannot reissue',async()=>{const {s,f}=await setup();await using(s,f,async(r,state)=>{const c=new AbortController(),sync=state.storage.sync.bind(state.storage);const spy=vi.spyOn(state.storage,'sync').mockImplementation(async()=>{await sync();c.abort();});try{await expect(r.prepare(f.prepare,c.signal)).rejects.toThrow();}finally{spy.mockRestore();}});expect(await rows(s,'ir_claims')).toHaveLength(3);await expect(prepare(s,f)).rejects.toThrow();await withdraw(s,f);});
it('already cancelled request never reserves an intent',async()=>{const {s,f}=await setup();const c=new AbortController();c.abort();await expect(using(s,f,async r=>r.prepare(f.prepare,c.signal))).rejects.toThrow();expect(await rows(s,'ir_claims')).toHaveLength(0);});
it('takes primitive snapshots before awaits and rejects getters without invoking them',async()=>{const {s,f}=await setup();const values={...f.prepare};await using(s,f,async r=>{const pending=r.prepare(values,signal());values.intent='changed';await pending;});const g=await fixture(2);let calls=0;Object.defineProperty(g.prepare,'intent',{get(){calls++;return g.intent;}});await expect(prepare(s,g)).rejects.toThrow();expect(calls).toBe(0);});
it('reinitialization and insufficient configured terminal budget reject',async()=>{const {s,f}=await setup();await expect(using(s,f,async r=>r.initialize(4,24,signal()))).rejects.toThrow();await using(s,f,async(_r,state)=>{const other=new InstallationRegistry(state.storage,owner,f.identity,f.restore);await expect(other.initialize(1,5,signal())).rejects.toThrow();});});

it('principal DATA read requires complete original chain and closes after withdrawal',async()=>{const {s,f}=await setup();await prepare(s,f);await expect(using(s,f,async r=>r.readPrincipal(f.prepare,signal()))).rejects.toThrow();await admit(s,f);expect((await using(s,f,async r=>r.readPrincipal(f.prepare,signal()))).classification).toBe('INSTALLATION_PRINCIPAL_DATA_ONLY');await withdraw(s,f);await expect(using(s,f,async r=>r.readPrincipal(f.prepare,signal()))).rejects.toThrow();});
it('NOT_FOUND remains a closed diagnostic status, with explicit requested kind and no authority',async()=>{const {s,f}=await setup();const out=await status(s,f);expect(out.status.outcome).toEqual({tag:'NOT_FOUND_DATA'});await decodeRecord(canonical(out.status),'operation_status');expect(await rows(s,'ir_claims')).toHaveLength(0);});
it('captures original authority method before await rather than accepting a replacement',async()=>{const {s,f}=await setup();let called=0;const authority:RegistryAuthority={assertOriginal(){called++;throw Error('original refused');}};await using(s,f,async(_r,state)=>{const r=new InstallationRegistry(state.storage,authority,f.identity,f.restore);authority.assertOriginal=()=>{};await expect(r.prepare(f.prepare,signal())).rejects.toThrow('original refused');});expect(called).toBe(1);expect(await rows(s,'ir_claims')).toHaveLength(0);});
it('withdrawal cannot change the originally reserved withdrawal policy',async()=>{const {s,f}=await setup();await prepare(s,f);await expect(using(s,f,async r=>r.withdrawOriginal({...f.withdraw,withdrawal:canonical({...JSON.parse(f.withdrawal),withdrawal_policy_sha256:H(9999)})},signal()))).rejects.toThrow();expect(await rows(s,'ir_retired')).toHaveLength(0);});

it('dedicated production Worker stays closed before touching namespace or supplied authority',async()=>{const trap=new Proxy({},{get(){throw Error('untrusted input accessed');}});expect(()=>createProductionInstallationRegistry(trap)).toThrow('independent operator');expect(closedWorker.fetch().status).toBe(503);expect(closedWorker.fetch().headers.get('Cache-Control')).toBe('no-store');});

it('a successor needs original retirement and its own current state revision',async()=>{
 const {s,f}=await setup();await prepare(s,f);await admit(s,f);
 const early=await fixture(2,{principalID:'fixture-principal-1',principalEpoch:2,revision:1});
 await expect(prepare(s,early)).rejects.toThrow();
 expect(await rows(s,'ir_claims')).toHaveLength(3);
 await withdraw(s,f);
 await expect(prepare(s,early)).rejects.toThrow(); // Retirement did not renew old expected revision.
 const successor=await fixture(3,{principalID:'fixture-principal-1',principalEpoch:2,revision:2});
 await prepare(s,successor);await admit(s,successor);
 expect((await rows(s,'ir_principals')).map(r=>r.epoch)).toEqual([1,2]);
 expect((await status(s,successor)).status.outcome.tag).toBe('COMMITTED');
 await expect(using(s,f,r=>r.readPrincipal(f.prepare,signal()))).rejects.toThrow();
});

it('an exact old withdrawal never retires a separately admitted successor',async()=>{
 const {s,f}=await setup();await prepare(s,f);await admit(s,f);const original=await withdraw(s,f);
 const successor=await fixture(2,{principalID:'fixture-principal-1',principalEpoch:2,revision:2});
 await prepare(s,successor);await admit(s,successor);
 const before=await rows(s,'ir_meta');
 expect((await withdraw(s,f)).status.outcome).toEqual(original.status.outcome);
 expect(await rows(s,'ir_meta')).toEqual(before);
 expect((await status(s,successor)).status.outcome.tag).toBe('COMMITTED');
 expect((await using(s,successor,r=>r.readPrincipal(successor.prepare,signal()))).values.registry_committed_revision).toBe(3);
 expect(await rows(s,'ir_retired')).toHaveLength(1);
});

it('retired unknown admission stays spent while its explicit successor can settle',async()=>{
 const {s,f}=await setup();await prepare(s,f);
 await expect(using(s,f,r=>r.admit({...f.admit,signature_b64url:'invalid'},signal()))).rejects.toThrow();
 expect((await status(s,f)).status.outcome.tag).toBe('UNKNOWN');
 await withdraw(s,f);
 const successor=await fixture(2,{principalID:'fixture-principal-1',principalEpoch:2,revision:1});
 await prepare(s,successor);await admit(s,successor);
 await expect(admit(s,f)).rejects.toThrow();
 expect((await status(s,f)).status.outcome.tag).toBe('RETIRED');
 expect((await rows(s,'ir_principals')).map(r=>r.epoch)).toEqual([2]);
});

it('successors cannot skip epochs even with an independently accepted new revision',async()=>{
 const {s,f}=await setup();await prepare(s,f);await withdraw(s,f);
 const skipped=await fixture(2,{principalID:'fixture-principal-1',principalEpoch:3,revision:1});
 await expect(prepare(s,skipped)).rejects.toThrow();
 expect(await rows(s,'ir_intents')).toHaveLength(1);
 expect(await rows(s,'ir_claims')).toHaveLength(6);
});

it('global nonce claims reject another otherwise valid principal without partial reservation',async()=>{
 const {s,f}=await setup();await prepare(s,f);
 const other=await fixture(1,{principalID:'fixture-other'}); // Same original operation/challenge/nonce, different complete signed chain.
 await expect(prepare(s,other)).rejects.toThrow();
 expect(await rows(s,'ir_intents')).toHaveLength(1);
 expect(await rows(s,'ir_claims')).toHaveLength(3);
 expect((await rows(s,'ir_meta'))[0]).toMatchObject({state_revision:0,ledger_revision:1});
});
