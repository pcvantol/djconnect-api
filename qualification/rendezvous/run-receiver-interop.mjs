// Actual delivered consumer + actual product module; no public/native positive.
import assert from 'node:assert/strict';
import {mkdtemp,chmod,cp,rm,writeFile,unlink,symlink,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {privateDirectory,need} from './local-native-files.mjs';
import {manifest,verifyInputs,digest,fixture} from './receiver-interop-inputs.mjs';
import {startLocalRuntime,repo} from './local-native-runtime.mjs';
import {readFile} from 'node:fs/promises';

async function inputGuards(original){
 let checks=0;
 const cases=[
  async p=>writeFile(join(p,'wire.mjs'),'changed'),
  async p=>unlink(join(p,'wire-schema.mjs')),
  async p=>writeFile(join(p,'unexpected.mjs'),'extra'),
  async p=>writeFile(join(p,'node_modules/jose/dist/webapi/index.js'),'changed'),
  async p=>writeFile(join(p,'node_modules/jose/extra.js'),'extra'),
  async p=>{await unlink(join(p,'wire.mjs'));await symlink('rendezvous.mjs',join(p,'wire.mjs'));},
  async p=>{await unlink(join(p,'wire.mjs'));await link(join(p,'rendezvous.mjs'),join(p,'wire.mjs'));},
  async p=>{await rm(join(p,'node_modules/jose'),{recursive:true});await symlink(join(original.path,'node_modules/jose'),join(p,'node_modules/jose'));},
  async p=>{await rm(join(p,'node_modules'),{recursive:true});await symlink(join(original.path,'node_modules'),join(p,'node_modules'));},
 ];
 for(const corrupt of cases){
  const path=await mkdtemp(join(tmpdir(),'djc-interop-negative-'));await chmod(path,0o700);
  try{await cp(original.path,path,{recursive:true});await corrupt(path);const copy=await privateDirectory(path,repo);await assert.rejects(verifyInputs(copy));checks++;}
  finally{await rm(path,{recursive:true,force:true});}
 }
 return checks;
}
async function main(){
 need(process.argv.length===3);process.umask(0o077);
 const dir=await privateDirectory(process.argv[2],repo),inputCounts=await verifyInputs(dir),guardChecks=await inputGuards(dir);
 let api,adapter;
 const originalFetch=globalThis.fetch;let deniedNodeFetch=0;
 // Do not let dependency diagnostics or thrown QR/wire objects publish authority.
 const consoleMethods=['log','error','warn','info','debug','trace'],originalConsole=Object.fromEntries(consoleMethods.map(name=>[name,console[name]]));
 for(const name of consoleMethods)console[name]=()=>{};
 try{
  api=await startLocalRuntime();
  globalThis.fetch=async()=>{deniedNodeFetch++;throw new Error('interop_node_external_fetch_denied');};
  await assert.rejects(fetch('https://egress-denied.example.invalid/qualification'));assert.equal(deniedNodeFetch,1);deniedNodeFetch=0;
  const {createRendezvousAdapter}=await import(pathToFileURL(join(dir.path,'rendezvous.mjs')).href);
  const calls=[];let privateCreate;
  const transport=async(url,options)=>{
   need(typeof url==='string'&&url.startsWith('https://api.djconnect.dev/v1/rendezvous/'));
   const target=new URL(url),route=target.pathname.slice('/v1/rendezvous'.length);
   need(target.origin==='https://api.djconnect.dev'&&target.href==='https://api.djconnect.dev/v1/rendezvous'+route);
   need(options.method==='POST'&&options.mode==='cors'&&options.credentials==='omit'&&options.redirect==='error'&&options.cache==='no-store'&&options.referrerPolicy==='no-referrer');
   need(Object.keys(options.headers).length===1&&options.headers['Content-Type']==='application/json'&&typeof options.body==='string');
   const response=await api.request(route,Buffer.from(options.body));calls.push({route,status:response.status});
   if(route==='/create')privateCreate={body:options.body,response:await response.clone().json()};
   return response; // Exact body bytes and actual server responses; no fake success.
  };
  adapter=createRendezvousAdapter({fetch:transport,visible:()=>true});
  const challenge=await adapter.create();assert.equal(adapter.validateChallenge(challenge),true);
  assert.ok(challenge.matrix.length>0&&challenge.matrix.every(row=>row.length===challenge.matrix.length&&row.every(cell=>typeof cell==='boolean')));
  adapter.expose(challenge);assert.equal(await adapter.cancel(challenge),true);assert.equal(adapter.canRestart(),true);
  const count=calls.length;await assert.rejects(adapter.cancel(challenge));assert.equal(calls.length,count);
  const request=JSON.parse(privateCreate.body),tx=privateCreate.response;
  const wrong=await api.request('/poll',Buffer.from(JSON.stringify({v:'djc-rendezvous/1',transaction_id:tx.transaction_id,generation:request.generation,claim_secret:Buffer.alloc(32,7).toString('base64url')})));assert.equal(wrong.status,401);
  const qr=tx.qr_payload,scan={v:'djc-rendezvous/1',transaction_id:qr.transaction_id,generation:qr.generation,qr_capability:qr.qr_capability};
  const cancelled=await api.request('/inspect',Buffer.from(JSON.stringify(scan)));assert.equal(cancelled.status,409);
  assert.deepEqual(calls,[{route:'/create',status:201},{route:'/cancel',status:200}]);
  assert.deepEqual(api.egressObservation(),{allowed:0,denied:0});assert.equal(deniedNodeFetch,0);
  await verifyInputs(dir);await api.verifySources();
  const ownFiles=['receiver-interop-inputs.mjs','prepare-receiver-interop.mjs','run-receiver-interop.mjs'];
  const ownHashes=Object.fromEntries(await Promise.all(ownFiles.map(async name=>[name,digest(await readFile(new URL(name,import.meta.url)))])));
  const proof={scope:manifest.scope,result:'PASS',api_sha:api.snapshot.head,receiver_sha:manifest.receiver_sha,manifest_sha256:digest(await readFile(join(fixture,'interop-inputs-v1.json'))),qualification_sources:ownHashes,input_counts:inputCounts,negative_input_guards:guardChecks,interop_checks:7,calls,node_external_fetch_attempts:0,worker_outbound_attempts:0,acceptance:'NO_NATIVE_BROWSER_EDGE_OR_HA_POSITIVE'};
  Object.assign(console,originalConsole);originalConsole.log(JSON.stringify(proof));
 }finally{
  globalThis.fetch=originalFetch;Object.assign(console,originalConsole);
  adapter?.stop();if(api)await api.stop();
 }
}
main().catch(()=>{console.error('RECEIVER_INTEROP_REJECTED; no payload diagnostics or automatic retry');process.exitCode=1;});
