// Actual Node process -> local workerd -> actual DO SQLite. No Docker/Container VM.
import {unstable_dev} from 'wrangler';
import {spawnSync} from 'node:child_process';
import {writeFile,mkdir} from 'node:fs/promises';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {join,isAbsolute} from 'node:path';
import assert from 'node:assert/strict';
const scratch=process.argv[2];if(!scratch || !isAbsolute(scratch))throw Error('explicit external scratch required');
await mkdir(scratch,{recursive:true});
const root=fileURLToPath(new URL('../../../',import.meta.url));
const packaged=join(scratch,'node-package');
const build=spawnSync(process.execPath,[join(root,'coordinator/cloudflare/build-source.mjs'),packaged],{encoding:'utf8'});
if(build.status!==0)throw Error(build.stderr);
const bundle=join(packaged,'source-container.mjs');
const closed=spawnSync(process.execPath,[bundle],{encoding:'utf8'});
assert.equal(closed.status,78);assert.match(closed.stderr,/source qualification only/);
const {SourceStateClient,SourceContainerExecutor,syntheticAdmission}=await import(pathToFileURL(bundle).href);
const worker=await unstable_dev(fileURLToPath(new URL('bridge-worker.ts',import.meta.url)),{
  config:fileURLToPath(new URL('wrangler.jsonc',import.meta.url)),local:true,ip:'127.0.0.1',port:0,
  inspectorPort:0,logLevel:'error',persistTo:join(scratch,'workerd-state'),
  experimental:{disableExperimentalWarning:true,disableDevRegistry:true,watch:false,enableContainers:false},
});
const realFetch=globalThis.fetch;let calls=0;const observations=[];
globalThis.fetch=async(url,options)=>{
  assert.equal(url,'http://coordinator.state/source-transaction');assert.equal(options.redirect,'manual');calls++;
  return realFetch(`http://127.0.0.1:${worker.port}/source-transaction`,options);
};
const H=n=>n.toString(16).padStart(64,'0'),U=n=>`00000000-0000-4000-8000-${n.toString(16).padStart(12,'0')}`;
const stages=['prepare_key','verify_key','prepare_target','verify_target','submit'];
try {
  const client=SourceStateClient.forContainer();const epoch=JSON.parse(await client.initializeSourceFixture('SYNTHETIC_SOURCE_QUALIFICATION',H(1)));
  for(const [n,expire] of [[1,false],[2,true]]) {
    const job={job:U(n),parent:U(100+n),parentGeneration:1,pairingEpoch:H(1),principalEpoch:1,
      role:'widget_transport',context:H(2),keyScope:H(3),keyRef:H(4+n),deadline:1000};
    await client.registerParentData(epoch,job);
    const clock={domain:'unqualified-Mac-Node-process-source',continuousNs:()=>process.hrtime.bigint(),utcUpperMs:()=>100};
    const cutoff=process.hrtime.bigint()+3_000_000_000n;
    const a=syntheticAdmission({label:'SYNTHETIC_SOURCE_QUALIFICATION',job,epoch,clockDomain:clock.domain,
      originalCutoffNs:cutoff,issuedAtMs:1,parentIssuedAtMs:1,parentExpiresAtMs:2000,operationMaxMs:999,parentMaxMs:1999,maxJobs:10});
    const executor=new SourceContainerExecutor(client,clock,epoch.containerGeneration);
    await executor.begin(a,U(1000*n),H(1000*n));
    for(const [i,stage] of stages.entries())await executor.step(a,{stage,revision:i+1,operation:U(1000*n+i+1),nonce:H(1000*n+i+1),body:H(2000*n+i+1),
      counter:stage==='verify_key'?1:stage==='verify_target'?2:null,counterRevision:stage==='verify_key'?0:stage==='verify_target'?1:null});
    let atBuild=-1;
    const operation=executor.observeFinal(a,()=>{
      atBuild=calls;
      if(expire)while(process.hrtime.bigint()<cutoff) { /* CPU only: no await or downstream hop. */ }
      return 'SOURCE_DATA_ONLY';
    });
    if(expire)await assert.rejects(operation,/original expiry/);else assert.equal(await operation,'SOURCE_DATA_ONLY');
    assert.equal(calls,atBuild);assert.equal(executor.observations[0].state,expire?'SPENT':'SOURCE_OBSERVATION_ONLY');
    observations.push({case:expire?'actual_Node_CPU_clock_expiry':'actual_Node_local_DO_composition',result:'PASS',
      classification:'SOURCE_QUALIFICATION_ONLY',provider_calls:0,after_final_clock_hops:0});
  }
  const summary={classification:'SOURCE_QUALIFICATION_ONLY',production_factory_exit:closed.status,
    Node:process.version,platform:process.platform,actual_Linux_Container:false,UTC:'SYNTHETIC',calls,observations,
    native_admission:false,provider_calls:0};
  await writeFile(join(scratch,'node-loopback-summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify(summary));
} finally {globalThis.fetch=realFetch;await worker.stop();}
