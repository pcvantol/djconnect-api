// Actual local workerd qualification of the fixed CLOSED QA artifact only.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {buildFixedQa,deriveFixedQaSource,fixedGitIdentity,repo,hash} from './build_rendezvous_qa.mjs';

const built=await buildFixedQa();let runtime;
try{
 const gitForgery={GIT_DIR:'/nonexistent-qa-forged-git',GIT_WORK_TREE:'/nonexistent-qa-forged-tree',GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:'core.worktree',GIT_CONFIG_VALUE_0:'/nonexistent-qa-forged-config'};
 const saved=Object.fromEntries(Object.keys(gitForgery).map(key=>[key,process.env[key]]));
 try{Object.assign(process.env,gitForgery);assert.equal(await fixedGitIdentity(),built.receipt.source_sha);}
 finally{for(const [key,value]of Object.entries(saved))if(value===undefined)delete process.env[key];else process.env[key]=value;}
 let driftChecks=0;
 for(const [name,pin]of Object.entries(built.receipt.profile.transforms)){
  const bytes=await readFile(join(repo,name),'utf8');
  assert.throws(()=>deriveFixedQaSource(name,bytes+'\n',pin));driftChecks++;
  assert.throws(()=>deriveFixedQaSource(name,bytes,{...pin,counts:{}}));driftChecks++;
 }
 assert.throws(()=>deriveFixedQaSource('arbitrary.ts','',{}));driftChecks++;
 const wire=JSON.parse(deriveFixedQaSource('docs/rendezvous/wire-request-schemas-v1.json',await readFile(join(repo,'docs/rendezvous/wire-request-schemas-v1.json'),'utf8'),built.receipt.profile.transforms['docs/rendezvous/wire-request-schemas-v1.json']));
 const constants=[];
 const collect=value=>{if(value&&typeof value==='object'){if(Object.hasOwn(value,'const'))constants.push(value.const);for(const child of Object.values(value))collect(child);}};
 collect(wire);
 assert.equal(constants.filter(value=>value==='https://api-vibecast-qa.djconnect.dev').length,4);
 assert.equal(constants.filter(value=>value==='https://qa.vibecast.tv').length,1);
 assert.equal(constants.filter(value=>value==='https://api.djconnect.dev'||value==='https://vibecast.tv').length,0);
 const require=createRequire(import.meta.resolve('wrangler'));
 const {Miniflare,Log,LogLevel,convertV4MiniflareOptions}=require('miniflare');
 const inputs=JSON.parse(await readFile(join(repo,'rendezvous-build-inputs.json'),'utf8'));
 const classes=Object.values(inputs.local_test_bindings);
 const driver=`import qa from './worker.mjs';import * as product from './worker.mjs';
export {${classes.join(',')}} from './worker.mjs';
export default {async fetch(request,env){
 const probe=await request.json();
 if(probe.control)return fetch('https://denied.invalid/egress-control');
 if(probe.exports)return Response.json({exports:Object.keys(product).sort(),methods:Object.fromEntries(${JSON.stringify(classes)}.map(n=>[n,Object.getOwnPropertyNames(product[n].prototype).filter(k=>k!=='constructor').sort()]))});
 if(probe.rpc){try{const stub=env[probe.binding].get(env[probe.binding].idFromName('qa-forbidden-rpc'));if(probe.read)await stub[probe.rpc];else await stub[probe.rpc]();return Response.json({rejected:false});}catch{return Response.json({rejected:true});}}
 let reads=0;const closedEnv=new Proxy({}, {get(){reads++;throw new Error('must not read runtime admission/config/secret/DO');}});
 const headers=new Headers(probe.headers);const input=new Request(probe.url,{method:probe.method,headers,body:probe.method==='POST'?'opaque-not-an-admission':undefined});
 const response=await qa.fetch(input,closedEnv);
 return Response.json({status:response.status,headers:Object.fromEntries(response.headers),body:await response.json(),env_reads:reads,body_used:input.bodyUsed});
}};`;
 let outbound=0;
 runtime=new Miniflare(convertV4MiniflareOptions({host:'127.0.0.1',inspectorHost:'127.0.0.1',log:new Log(LogLevel.NONE),durableObjectsPersist:false,workers:[{
  name:'fixed-qa',modulesRoot:built.output,compatibilityDate:'2026-06-20',compatibilityFlags:['nodejs_compat'],
  modules:[{type:'ESModule',path:join(built.output,'driver.mjs'),contents:driver},{type:'ESModule',path:join(built.output,'worker.mjs'),contents:built.bundle}],
  durableObjects:Object.fromEntries(Object.entries(inputs.local_test_bindings).map(([name,className])=>[name,{className,useSQLite:true}])),
  outboundService:()=>{outbound++;return new Response(null,{status:503});},
 }]}));
 const worker=await runtime.getWorker();
 const raw=probe=>worker.fetch('http://local.test/',{method:'POST',body:JSON.stringify(probe)});
 assert.equal((await raw({control:true})).status,503);assert.equal(outbound,1);outbound=0;
 const call=async probe=>(await raw(probe)).json();
 const manifest=await call({exports:true});assert.deepEqual(manifest.exports,[...classes,'default'].sort());
 for(const name of classes)assert.deepEqual(manifest.methods[name],inputs.rpc_allowlists[name].toSorted());
 const observations=[];
 const routes=['/create','/inspect','/attestation/challenge','/attestation/register','/submit-challenge','/submit','/poll','/consume','/cancel','/attestation/delete','/attestation/recover'];
 const service=built.receipt.profile.service_origin,browser=built.receipt.profile.browser_origin;
 for(const route of routes)for(const origin of [browser,'https://vibecast.tv','https://qa.vibecast.tv.evil.invalid',null]){
  const headers={'X-Rendezvous-Enabled':'true','Authorization':'Bearer synthetic','Content-Type':'application/json',...(origin===null?{}:{Origin:origin})};
  const r=await call({url:service+'/v1/rendezvous'+route,method:'POST',headers});
  assert.equal(r.status,503);assert.deepEqual(r.body,{v:'djc-rendezvous/1',error:'service_unavailable'});assert.equal(r.env_reads,0);assert.equal(r.body_used,false);
  assert.equal(r.headers['access-control-allow-origin'],origin===browser?browser:undefined);assert.equal(r.headers['cache-control'],'no-store');
  assert.equal(r.headers['retry-after'],undefined);assert.equal(r.headers['content-encoding'],undefined);assert.equal(r.headers['access-control-allow-credentials'],undefined);
  observations.push({route,origin,status:r.status,env_reads:r.env_reads,body_used:r.body_used});
 }
 for(const origin of [browser,'https://vibecast.tv']){
  const r=await call({url:service+'/v1/rendezvous/create',method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'content-type'}});
  assert.equal(r.status,503);assert.equal(r.env_reads,0);assert.equal(r.headers['access-control-allow-methods'],undefined);observations.push({method:'OPTIONS',origin,status:r.status});
 }
 for(const url of ['https://api.djconnect.dev/v1/rendezvous/create','https://evil.invalid/v1/rendezvous/create',service+'/v1/install/bootstrap',service+'/health?activate=true']){
  const r=await call({url,method:'GET'});assert.equal(r.status,404);assert.equal(r.env_reads,0);observations.push({url,status:r.status});
 }
 const health=await call({url:service+'/health',method:'GET'});assert.equal(health.status,200);assert.equal(health.body.activation_allowed,false);assert.equal(health.body.release_sha,built.receipt.source_sha);assert.equal(health.env_reads,0);
 let forbiddenRpc=0;
 for(const binding of Object.keys(inputs.local_test_bindings)){
  for(const rpc of ['install','installInternal','evidence','advance','rotate','revoke','lookupSubmit','load','save','expire','debugState','state','engine','issue','getSql','verifyEnrollment']){assert.equal((await call({rpc,binding})).rejected,true);forbiddenRpc++;}
  for(const rpc of ['env','ctx','state','engine']){assert.equal((await call({rpc,binding,read:true})).rejected,true);forbiddenRpc++;}
 }
 assert.equal(forbiddenRpc,100);assert.equal(outbound,0);await built.verify();
 const evidence={scope:built.receipt.scope,result:'PASS',source_sha:built.receipt.source_sha,source_dirty:built.receipt.source_dirty,git_environment_forgery_refused:true,artifact_worker_sha256:built.receipt.worker_sha256,worker_bytes:built.receipt.worker_bytes,origin_drift_guards:driftChecks,transport_cases:observations,health,forbidden_rpc:forbiddenRpc,outbound_attempts:outbound,activation_allowed:false,native_positive:false,operator_admission:null};
 await writeFile(join(built.output,'qualification-evidence.json'),JSON.stringify(evidence,null,2)+'\n');
 const files=['worker.mjs','wrangler.json','wire-request-schemas-qa.json','qa-origin-fixture.json','build-evidence.json','qualification-evidence.json','LICENSE','THIRD_PARTY_NOTICES.md','RENDEZVOUS_THIRD_PARTY_LICENSES.md','package.json','package-lock.json'];
 const tar=spawnSync('tar',['-czf',join(built.output,'fixed-rendezvous-qa.tar.gz'),...files],{cwd:built.output,encoding:'utf8'});assert.equal(tar.status,0);
 const archive=await readFile(join(built.output,'fixed-rendezvous-qa.tar.gz'));
 await writeFile(join(built.output,'archive-integrity.json'),JSON.stringify({source_sha:built.receipt.source_sha,sha256:hash(archive),activation_allowed:false},null,2)+'\n');
 if(process.env.GITHUB_OUTPUT)await writeFile(process.env.GITHUB_OUTPUT,'output_dir='+built.output+'\n',{flag:'a'});
 console.log(JSON.stringify({output:built.output,archive_sha256:hash(archive),worker_sha256:built.receipt.worker_sha256,transport_cases:observations.length,forbidden_rpc:forbiddenRpc,origin_drift_guards:driftChecks,result:'PASS',activation_allowed:false,native_positive:false}));
}finally{await runtime?.dispose();}
