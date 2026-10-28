import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {env,DurableObject,exports as workerExports} from 'cloudflare:workers';
import {runInDurableObject} from 'cloudflare:test';
import {SELF} from 'cloudflare:test';
import type {CoordinatorSourceState} from '../state';
import {SourceStateClient} from '../rpc';
import {SOURCE,STAGES,type Job,type Claim,type Epoch} from '../model';
import {createProductionCoordinator,SourceContainerExecutor,syntheticAdmission,type Admission} from '../executor';

declare module 'cloudflare:test' { interface ProvidedEnv { SOURCE_STATE:DurableObjectNamespace<CoordinatorSourceState> } }
declare global { namespace Cloudflare { interface Env { SOURCE_STATE:DurableObjectNamespace<CoordinatorSourceState> } } }
const H=(n:number)=>n.toString(16).padStart(64,'0');
const U=(n:number)=>`00000000-0000-4000-8000-${n.toString(16).padStart(12,'0')}`;
const job=(n=1):Job=>({job:U(n),parent:U(100+n),parentGeneration:1,pairingEpoch:H(1),principalEpoch:1,
  role:'widget_transport',context:H(2),keyScope:H(3),keyRef:H(4),deadline:1000});
const claim=(stage:Claim['stage'],revision=STAGES.indexOf(stage)+1,n=revision):Claim=>({stage,revision,
  operation:U(200+n),nonce:H(200+n),body:H(300+n),counter:stage==='verify_key'?1:stage==='verify_target'?2:null,
  counterRevision:stage==='verify_key'?0:stage==='verify_target'?1:null});
async function setup(j=job()) {
  const s=new SourceStateClient(env.SOURCE_STATE.get(env.SOURCE_STATE.newUniqueId()));
  const e=JSON.parse(await s.initializeSourceFixture(SOURCE,H(1))) as Epoch;
  await s.registerParentData(e,j);
  return {s,e,j};
}
async function count(s:SourceStateClient,table:string) {
  return runInDurableObject(s.stub as DurableObjectStub<CoordinatorSourceState>,(_instance,state)=>state.storage.sql.exec(`SELECT * FROM ${table}`).toArray());
}
async function opened(j=job()) {
  const f=await setup(j);await f.s.createJobData(f.e,j,U(500),H(500),10);return f;
}
async function spent() {
  const f=await opened();for(const stage of STAGES)await f.s.commitStageData(f.e,f.j,claim(stage));return f;
}
function executor(s:SourceStateClient,e:Epoch,j:Job) {
  const clock={domain:'synthetic-boot',continuous:1n,utc:100,continuousNs(){return this.continuous;},utcUpperMs(){return this.utc;}};
  const a=syntheticAdmission({label:SOURCE,job:j,epoch:e,clockDomain:clock.domain,originalCutoffNs:1000n,
    issuedAtMs:1,parentIssuedAtMs:1,parentExpiresAtMs:2000,operationMaxMs:999,parentMaxMs:1999,maxJobs:10});
  return {x:new SourceContainerExecutor(s,clock,e.containerGeneration),clock,a};
}
async function prepared() {
  const f=await setup();const local=executor(f.s,f.e,f.j);
  await local.x.begin(local.a,U(500),H(500));for(const stage of STAGES)await local.x.step(local.a,claim(stage));
  return {...f,...local};
}
let egress: ReturnType<typeof vi.fn>;
beforeEach(()=>{egress=vi.fn(()=>{throw Error('egress forbidden');});vi.stubGlobal('fetch',egress);});
afterEach(()=>{expect(egress).not.toHaveBeenCalled();vi.unstubAllGlobals();});

it('production factory rejects before inspecting arguments or any storage/Container binding',()=>{
  const argument=new Proxy({}, {get(){throw Error('argument touched');}});
  expect(()=>createProductionCoordinator(argument)).toThrow('unqualified');
});
it('uses real SQLite DO storage and rejects every public HTTP request',async()=>{
  const f=await opened();expect(await count(f.s,'cf_jobs')).toHaveLength(1);
  await runInDurableObject(f.s.stub as DurableObjectStub<CoordinatorSourceState>,(instance)=>{
    expect(instance).toBeInstanceOf(DurableObject);expect(()=>instance.startProductionContainer()).toThrow('unavailable');
  });
  expect((await SELF.fetch('https://source.invalid/anything')).status).toBe(503);
});
it('bootstrap is once-only and a mismatched restore epoch rejects before writes',async()=>{
  const f=await setup();await expect(f.s.initializeSourceFixture(SOURCE,H(1))).rejects.toThrow();
  await expect(f.s.createJobData({...f.e,restore:H(2)},f.j,U(500),H(500),10)).rejects.toThrow('fence');
  expect(await count(f.s,'cf_jobs')).toHaveLength(0);
});
it('duplicate nonce rolls back the job and its preceding operation write atomically',async()=>{
  const f=await opened(),j=job(2);await f.s.registerParentData(f.e,j);
  await expect(f.s.createJobData(f.e,j,U(501),H(500),10)).rejects.toThrow();
  expect(await count(f.s,'cf_jobs')).toHaveLength(1);expect(await count(f.s,'cf_operations')).toHaveLength(1);
});
it.each(['operation','nonce'] as const)('global %s namespace spans jobs, parents and roles',async field=>{
  const f=await opened(),j={...job(2),role:'status_activity_transport' as const};await f.s.registerParentData(f.e,j);
  await expect(f.s.createJobData(f.e,j,field==='operation'?U(500):U(501),field==='nonce'?H(500):H(501),10)).rejects.toThrow();
  expect(await count(f.s,'cf_jobs')).toHaveLength(1);
});
it('joint stage/CAS permits exactly one concurrent winner with no partial loser claim',async()=>{
  const f=await opened();const outcomes=await Promise.allSettled([f.s.commitStageData(f.e,f.j,claim('prepare_key')),
    f.s.commitStageData(f.e,f.j,{...claim('prepare_key'),operation:U(999),nonce:H(999)})]);
  expect(outcomes.filter(r=>r.status==='fulfilled')).toHaveLength(1);expect(await count(f.s,'cf_claims')).toHaveLength(1);
  expect(await count(f.s,'cf_operations')).toHaveLength(2);
});
it.each(['context','keyRef','pairingEpoch','role','principalEpoch','parentGeneration'] as const)('rejects substituted original %s',async field=>{
  const f=await opened();const altered={...f.j,[field]:field==='role'?'status_activity_transport':typeof f.j[field]==='number'?2:H(80)};
  await expect(f.s.commitStageData(f.e,altered as Job,claim('prepare_key'))).rejects.toThrow('fence');
  expect(await count(f.s,'cf_claims')).toHaveLength(0);
});
it('counter CAS rolls back claim+operation+nonce and remains global across parent/principal epochs',async()=>{
  const f=await opened();await f.s.commitStageData(f.e,f.j,claim('prepare_key'));await f.s.commitStageData(f.e,f.j,claim('verify_key'));
  const j={...job(2),principalEpoch:2};await f.s.registerParentData(f.e,j);await f.s.createJobData(f.e,j,U(600),H(600),10);
  await f.s.commitStageData(f.e,j,claim('prepare_key',1,601));
  await expect(f.s.commitStageData(f.e,j,claim('verify_key',2,602))).rejects.toThrow('counter CAS');
  expect(await count(f.s,'cf_claims')).toHaveLength(3);
  await f.s.commitStageData(f.e,j,{...claim('verify_key',2,602),counter:2,counterRevision:1});
  expect((await count(f.s,'cf_counters'))[0]).toMatchObject({counter:2,revision:2});
});
it('counter scope and uint32 cap cannot be reset by a new parent',async()=>{
  const f=await opened();await f.s.commitStageData(f.e,f.j,claim('prepare_key'));
  await f.s.commitStageData(f.e,f.j,{...claim('verify_key'),counter:4294967295});
  await f.s.commitStageData(f.e,f.j,claim('prepare_target'));
  await expect(f.s.commitStageData(f.e,f.j,{...claim('verify_target'),counter:4294967296})).rejects.toThrow('integer');
  const j={...job(2),keyScope:H(8)};await f.s.registerParentData(f.e,j);await f.s.createJobData(f.e,j,U(600),H(600),10);
  await f.s.commitStageData(f.e,j,claim('prepare_key',1,601));
  await expect(f.s.commitStageData(f.e,j,{...claim('verify_key',2,602),counterRevision:1})).rejects.toThrow('counter CAS');
});
it('parent retirement is durable and a replacement Container generation fences all prior jobs',async()=>{
  const f=await spent();await f.s.retireParentData(f.e,f.j.parent);await expect(f.s.validateSpentData(f.e,f.j)).rejects.toThrow('fence');
  const next=JSON.parse(await f.s.advanceContainerGeneration(f.e)) as Epoch;expect(next.containerGeneration).toBe(2);
  await expect(f.s.validateSpentData(f.e,f.j)).rejects.toThrow('generation fence');
  await expect(f.s.validateSpentData(next,f.j)).rejects.toThrow('fence');
});
it('a new executor cannot rehydrate a spent in-process submission handle from DO rows',async()=>{
  const f=await spent(),local=executor(f.s,f.e,f.j);
  await expect(local.x.observeFinal(local.a,()=> 'data')).rejects.toThrow('original in-process handle');
});
it('original handle succeeds once and exact frozen substitution is rejected',async()=>{
  const f=await prepared();const replacement=syntheticAdmission({...f.a});
  await expect(f.x.observeFinal(replacement,()=> 'wrong')).rejects.toThrow('original in-process handle');
  expect(await f.x.observeFinal(f.a,()=> 'data')).toBe('data');
  await expect(f.x.observeFinal(f.a,()=> 'again')).rejects.toThrow();expect(f.x.observations).toEqual([{job:f.j.job,state:'SOURCE_OBSERVATION_ONLY'}]);
});
it('lost RPC ACK after actual DO commit leaves submit spent and permanently fences executor',async()=>{
  const f=await setup();
  const transport=new Proxy(f.s,{get(target,key){if(key==='commitStageData')return async(...args:Parameters<typeof target.commitStageData>)=>{
    const result=await target.commitStageData(...args);if(args[2].stage==='submit')throw Error('lost ACK');return result;
  };return Reflect.get(target,key);}});
  const local=executor(transport,f.e,f.j);await local.x.begin(local.a,U(500),H(500));
  for(const stage of STAGES.slice(0,-1))await local.x.step(local.a,claim(stage));
  await expect(local.x.step(local.a,claim('submit'))).rejects.toThrow('lost ACK');
  expect((await count(f.s,'cf_jobs'))[0]).toMatchObject({phase:5,revision:6});
  await expect(local.x.step(local.a,claim('submit'))).rejects.toThrow('retired');
  await expect(local.x.observeFinal(local.a,()=> 'data')).rejects.toThrow();expect(local.x.observations).toEqual([]);
});
it('cancellation after real commit suppresses ACK publication without undoing SQL',async()=>{
  const f=await setup(),abort=new AbortController();
  const transport=new Proxy(f.s,{get(target,key){if(key==='commitStageData')return async(...args:Parameters<typeof target.commitStageData>)=>{
    const result=await target.commitStageData(...args);abort.abort();return result;
  };return Reflect.get(target,key);}});
  const local=executor(transport,f.e,f.j);await local.x.begin(local.a,U(500),H(500));
  await expect(local.x.step(local.a,claim('prepare_key'),abort.signal)).rejects.toThrow('cancelled');
  expect((await count(f.s,'cf_jobs'))[0]).toMatchObject({phase:1,revision:2});expect(await count(f.s,'cf_claims')).toHaveLength(1);
});
it.each(['continuous','utc','domain','cancel','retire'] as const)('final %s change during synchronous construction suppresses observation',async change=>{
  const f=await prepared(),abort=new AbortController();
  await expect(f.x.observeFinal(f.a,()=>{if(change==='continuous')f.clock.continuous=1000n;if(change==='utc')f.clock.utc=1000;
    if(change==='domain')f.clock.domain='other-boot';if(change==='cancel')abort.abort();if(change==='retire')f.x.retire();return 'data';},abort.signal)).rejects.toThrow();
  expect(f.x.observations).toEqual([{job:f.j.job,state:'SPENT'}]);expect((await count(f.s,'cf_jobs'))[0].phase).toBe(5);
});
it('generation advance between commit and final remote validation blocks final construction',async()=>{
  const f=await prepared();await f.s.advanceContainerGeneration(f.e);const build=vi.fn(()=> 'data');
  await expect(f.x.observeFinal(f.a,build)).rejects.toThrow('generation fence');expect(build).not.toHaveBeenCalled();
});
it('clock regression retires executor without consuming a new operation',async()=>{
  const f=await setup(),local=executor(f.s,f.e,f.j);await local.x.begin(local.a,U(500),H(500));local.clock.continuous=0n;
  await expect(local.x.step(local.a,claim('prepare_key'))).rejects.toThrow('regression');expect(await count(f.s,'cf_operations')).toHaveLength(1);
});
it('source policy count and original lifetime caps precede new writes',async()=>{
  const f=await opened(),j=job(2);await f.s.registerParentData(f.e,j);
  await expect(f.s.createJobData(f.e,j,U(600),H(600),1)).rejects.toThrow('budget');expect(await count(f.s,'cf_jobs')).toHaveLength(1);
  const local=executor(f.s,f.e,j),a=syntheticAdmission({...local.a,operationMaxMs:5});
  await expect(local.x.begin(a,U(601),H(601))).rejects.toThrow('policy');expect(await count(f.s,'cf_jobs')).toHaveLength(1);
});

it('real SQL abort after a counter update rolls back the entire stage transaction',async()=>{
  const f=await opened();await f.s.commitStageData(f.e,f.j,claim('prepare_key'));
  await runInDurableObject(f.s.stub as DurableObjectStub<CoordinatorSourceState>,(_i,state)=>{
    state.storage.sql.exec("CREATE TRIGGER qualification_abort AFTER UPDATE OF phase ON cf_jobs BEGIN SELECT RAISE(ABORT,'qualification after-counter fault'); END").toArray();
  });
  await expect(f.s.commitStageData(f.e,f.j,claim('verify_key'))).rejects.toThrow('rejected');
  expect(await count(f.s,'cf_counters')).toHaveLength(0);expect(await count(f.s,'cf_claims')).toHaveLength(1);
  expect(await count(f.s,'cf_operations')).toHaveLength(2);expect((await count(f.s,'cf_jobs'))[0]).toMatchObject({phase:1,revision:2});
});

function outboundFor(s:SourceStateClient):Fetcher {
  const exports=workerExports as unknown as {SourceStateOutbound(options:{props:{stateId:string}}):Fetcher};
  return exports.SourceStateOutbound({props:{stateId:(s.stub as DurableObjectStub<CoordinatorSourceState>).id.toString()}});
}
it('Container fixed-host client -> real loopback Worker -> own DO -> final local guard, without a provider hop',async()=>{
  const f=await setup(),outbound=outboundFor(f.s);
  const requests:Request[]=[];
  vi.stubGlobal('fetch',async(input:RequestInfo,init?:RequestInit)=>{
    const request=new Request(input,init);requests.push(request);
    expect(request.url).toBe('http://coordinator.state/source-transaction');expect(request.redirect).toBe('manual');
    return outbound.fetch(request);
  });
  const client=SourceStateClient.forContainer(),local=executor(client,f.e,f.j);
  await local.x.begin(local.a,U(500),H(500));for(const stage of STAGES)await local.x.step(local.a,claim(stage));
  let finalCount=-1;expect(await local.x.observeFinal(local.a,()=>{finalCount=requests.length;return 'data';})).toBe('data');
  expect(requests).toHaveLength(7);expect(requests.length).toBe(finalCount);expect((await count(f.s,'cf_jobs'))[0].phase).toBe(5);
});
it.each(['http://other.state/source-transaction','https://api.push.apple.com/3/device/example',
  'http://coordinator.state/other','http://coordinator.state/source-transaction?stateId=other'])('outbound handler denies %s before body/state access',async url=>{
  const f=await setup(),outbound=outboundFor(f.s);
  expect((await outbound.fetch(new Request(url,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}))).status).toBe(403);
  expect(await count(f.s,'cf_jobs')).toHaveLength(0);
});
it('streaming request cap rejects before SQL and the client rejects oversized state responses',async()=>{
  const f=await setup(),outbound=outboundFor(f.s);
  const response=await outbound.fetch(new Request('http://coordinator.state/source-transaction',{
    method:'POST',headers:{'Content-Type':'application/json'},body:'x'.repeat(16385),
  }));expect(response.status).toBe(413);expect(await count(f.s,'cf_jobs')).toHaveLength(0);
  vi.stubGlobal('fetch',async()=>new Response('x'.repeat(2049)));
  await expect(SourceStateClient.forContainer().validateSpentData(f.e,f.j)).rejects.toThrow('response cap');
});
it('unknown/oversized/malformed source RPC commands return negative DATA and do not mutate the journal',async()=>{
  const f=await setup();
  for(const wire of ['{',JSON.stringify({label:SOURCE,method:'provider',args:[]}), 'x'.repeat(16385)]) {
    expect(JSON.parse(await f.s.stub.sourceCommand(wire)).ok).toBe(false);
  }
  expect(await count(f.s,'cf_jobs')).toHaveLength(0);
});
it.each(['cancel','domain'] as const)('pre-write %s fence cannot be repaired by removing the signal or restoring a clock label',async reason=>{
  const f=await setup(),local=executor(f.s,f.e,f.j),abort=new AbortController();
  if(reason==='cancel')abort.abort();else local.clock.domain='wrong-boot';
  await expect(local.x.begin(local.a,U(500),H(500),abort.signal)).rejects.toThrow();
  local.clock.domain='synthetic-boot';
  await expect(local.x.begin(local.a,U(501),H(501))).rejects.toThrow('retired');
  expect(await count(f.s,'cf_jobs')).toHaveLength(0);
});
it('durable parent withdrawal before final validation suppresses construction',async()=>{
  const f=await prepared();await f.s.retireParentData(f.e,f.j.parent);const build=vi.fn(()=> 'data');
  await expect(f.x.observeFinal(f.a,build)).rejects.toThrow('fence');expect(build).not.toHaveBeenCalled();
});
