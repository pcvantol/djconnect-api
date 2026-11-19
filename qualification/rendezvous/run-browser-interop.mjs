// Real engines and actual source/state; route interception is NOT HTTP/CORS/TLS proof.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {readFile,mkdtemp,chmod,cp,rm,unlink,symlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {need,privateDirectory} from './local-native-files.mjs';
import {verifyInputs,manifest,digest} from './receiver-interop-inputs.mjs';
import {verifyTools,toolsFixture,toolsManifest,moduleURL} from './browser-interop-tools.mjs';
import {startLocalRuntime,repo} from './local-native-runtime.mjs';

const ORIGIN='https://vibecast.tv',SERVICE='https://api.djconnect.dev',PAGE=ORIGIN+'/__api_qualification/';
const methods=['log','error','warn','info','debug','trace'];
async function fileHash(path){const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);return hash.digest('hex');}
function within(promise,ms){let timer;return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('browser_case_timeout')),ms);})]).finally(()=>clearTimeout(timer));}
function decodedQR(matrix,decode){
 need(Array.isArray(matrix)&&matrix.length>=21&&matrix.length<=177&&matrix.every(row=>Array.isArray(row)&&row.length===matrix.length&&row.every(cell=>typeof cell==='boolean')));
 const scale=4,n=(matrix.length+8)*scale,rgba=new Uint8ClampedArray(n*n*4).fill(255);
 for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(matrix[Math.floor(y/scale)-4]?.[Math.floor(x/scale)-4]){const i=(y*n+x)*4;rgba[i]=rgba[i+1]=rgba[i+2]=0;}
 const result=decode(rgba,n,n);need(result&&typeof result.data==='string'&&result.data.length<=1024);return JSON.parse(result.data);
}
async function toolGuards(original){
 let count=0;
 const cases=[
  async p=>{await unlink(join(p,'node_modules/.bin/playwright'));await symlink('../../unexpected.js',join(p,'node_modules/.bin/playwright'));},
  async p=>unlink(join(p,'node_modules/.bin/playwright-core')),
  async p=>writeFile(join(p,'node_modules/playwright-core/browsers.json'),'changed'),
  async p=>{await rm(join(p,'node_modules'),{recursive:true});await symlink(join(original.path,'node_modules'),join(p,'node_modules'));},
 ];
 for(const corrupt of cases){
  const path=await mkdtemp(join(tmpdir(),'djc-browser-tool-negative-'));await chmod(path,0o700);
  try{await cp(original.path,path,{recursive:true,verbatimSymlinks:true});const copy=await privateDirectory(path,repo);await verifyTools(copy);await corrupt(path);await assert.rejects(verifyTools(copy));count++;}
  finally{await rm(path,{recursive:true,force:true});}
 }
 return count;
}
async function browserCase(browser,kind,bundle,api,decode){
 const context=await browser.newContext({serviceWorkers:'block',acceptDownloads:false});
 let unexpected=0,callbackErrors=0,pageErrors=0,created,pendingResolve;
 const calls=[],pending=new Promise(resolve=>{pendingResolve=resolve;});
 try{
  const page=await context.newPage();page.setDefaultTimeout(10000);page.on('pageerror',()=>{pageErrors++;});
  await context.route('**/*',async route=>{
   try{
    const request=route.request(),url=request.url();
    if(url===PAGE&&request.method()==='GET')return await route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><html><head><link rel="icon" href="data:,"></head><body><script src="/fixture.js"></script></body></html>'});
    if(url===ORIGIN+'/fixture.js'&&request.method()==='GET')return await route.fulfill({status:200,contentType:'text/javascript',body:bundle});
    const path=url.startsWith(SERVICE+'/v1/rendezvous/')?url.slice((SERVICE+'/v1/rendezvous').length):'';
    if(!['/create','/poll','/cancel'].includes(path)||url!==SERVICE+'/v1/rendezvous'+path||request.method()!=='POST'){
     unexpected++;return await route.abort('blockedbyclient'); // No fake OPTIONS/preflight or unknown response.
    }
    const headers=await request.allHeaders();need(headers.origin===ORIGIN&&headers['content-type']==='application/json'&&!headers.cookie&&!headers.authorization&&!headers.referer);
    const body=request.postDataBuffer();need(body instanceof Uint8Array&&body.length<=16384);
    const response=await api.request(path,body),bytes=Buffer.from(await response.arrayBuffer());need(bytes.length<=16384);
    const entry={method:'POST',route:path,status:response.status};calls.push(entry);
    if(path==='/create'){need(!created&&response.status===201);created=JSON.parse(bytes.toString('utf8'));}
    if(path==='/poll'){const value=JSON.parse(bytes.toString('utf8'));need(response.status===200&&value.state==='pending'&&value.expires_at===created.expires_at);}
    await route.fulfill({status:response.status,headers:Object.fromEntries(response.headers),body:bytes});
    if(path==='/poll'&&calls.filter(c=>c.route==='/poll').length===2)pendingResolve();
   }catch{callbackErrors++;await route.abort('blockedbyclient').catch(()=>{});}
  });
  await page.goto(PAGE,{waitUntil:'load',timeout:10000});
  const intercepted=await page.evaluate(async()=>{try{await fetch('https://egress-denied.example.invalid/qualification');return false;}catch{return true;}});
  need(intercepted&&unexpected===1&&callbackErrors===0);unexpected=0;
  const matrix=await page.evaluate(async()=>{
   if(!isSecureContext||document.visibilityState!=='visible')throw new Error('fixture_context_rejected');
   const adapter=DJCReceiverFixture.createRendezvousAdapter(),challenge=await adapter.create();
   adapter.expose(challenge);window.__apiQualification={adapter,challenge};
   if(!adapter.validateChallenge(challenge))throw new Error('fixture_challenge_rejected');return challenge.matrix;
  });
  assert.deepEqual(decodedQR(matrix,decode),created.qr_payload);
  if(kind==='pending'){
   await page.evaluate(()=>{const q=window.__apiQualification;q.wait=q.adapter.wait({challenge:q.challenge}).then(()=>{q.waitResult='unexpected_handoff';},()=>{q.waitResult='stopped';});});
   await within(pending,10000); // A second real poll also proves progress after the first pending response.
  }
  const cancelled=await page.evaluate(async()=>{
   const q=window.__apiQualification,ok=await q.adapter.cancel(q.challenge);if(q.wait)await q.wait;
   let duplicateRejected=false;try{await q.adapter.cancel(q.challenge);}catch{duplicateRejected=true;}
   return {ok,duplicateRejected,invalid:!q.adapter.validateChallenge(q.challenge),restart:q.adapter.canRestart(),wait:q.waitResult??'not_started',storage:[localStorage.length,sessionStorage.length]};
  });
  assert.deepEqual(cancelled,{ok:true,duplicateRejected:true,invalid:true,restart:true,wait:kind==='pending'?'stopped':'not_started',storage:[0,0]});
  assert.deepEqual(calls,kind==='pending'?[{method:'POST',route:'/create',status:201},{method:'POST',route:'/poll',status:200},{method:'POST',route:'/poll',status:200},{method:'POST',route:'/cancel',status:200}]:[{method:'POST',route:'/create',status:201},{method:'POST',route:'/cancel',status:200}]);
  need(unexpected===0&&callbackErrors===0&&pageErrors===0);
  return {case:kind,result:'PASS',calls,independent_qr_decode:true,observed_local_session_storage:[0,0],browser_guard_control_intercepted:true,unexpected_browser_http_requests:0,observed_options:0};
 }finally{await context.close();}
}
async function main(){
 need(process.argv.length===4);process.umask(0o077);
 const inputs=await privateDirectory(process.argv[2],repo),tools=await privateDirectory(process.argv[3],repo);
 need(inputs.path!==tools.path);const counts=await verifyInputs(inputs),toolFiles=await verifyTools(tools),negativeToolGuards=await toolGuards(tools);
 const debugEnv=Object.fromEntries(['DEBUG','PWDEBUG'].map(name=>[name,process.env[name]]));delete process.env.DEBUG;delete process.env.PWDEBUG;
 const originalConsole=Object.fromEntries(methods.map(name=>[name,console[name]])),originalFetch=globalThis.fetch;
 let api,browser,proof,nodeAttempts=0;
 for(const name of methods)console[name]=()=>{};
 try{
  api=await startLocalRuntime();
  globalThis.fetch=async()=>{nodeAttempts++;throw new Error('browser_qualification_node_fetch_denied');};
  await assert.rejects(fetch('https://egress-denied.example.invalid/qualification'));need(nodeAttempts===1);nodeAttempts=0;
  const require=createRequire(join(repo,'package.json')),{build}=require('esbuild');
  const rootLock=JSON.parse(await readFile(join(repo,'package-lock.json'))),esbuildVersion=require('esbuild/package.json').version;need(esbuildVersion===rootLock.packages['node_modules/esbuild'].version);
  const built=await build({absWorkingDir:inputs.path,entryPoints:['rendezvous.mjs'],bundle:true,write:false,metafile:true,format:'iife',globalName:'DJCReceiverFixture',platform:'browser',logLevel:'silent'});
  const allowed=new Set([...Object.values(manifest.receiver_sources).map(v=>v.leaf),...Object.keys(manifest.installed_hashes)]);
  for(const path of Object.keys(built.metafile.inputs)){const actual=relative(inputs.path,resolve(inputs.path,path));need(allowed.has(actual));}
  need(built.outputFiles.length===1);const bundle=built.outputFiles[0].text;
  const {chromium,webkit}=await import(moduleURL(tools,'playwright')),{default:decode}=await import(moduleURL(tools,'jsqr'));
  const results=[];
  for(const [engine,type]of Object.entries({chromium,webkit})){
   const executable=type.executablePath(),executableHash=await fileHash(executable);
   browser=await type.launch({headless:true,executablePath:executable,timeout:20000});
   const version=browser.version();need(version===toolsManifest.engines[engine].version);
   try{for(const kind of ['basic','pending'])results.push({engine,version,revision:toolsManifest.engines[engine].revision,launch_file_sha256:executableHash,launch_file_scope:engine==='webkit'?'SHELL_LAUNCHER_NOT_FULL_ENGINE':'LAUNCH_EXECUTABLE_NOT_FULL_INSTALLATION',...await within(browserCase(browser,kind,bundle,api,decode),20000)});}
   finally{await browser.close();browser=undefined;}
  }
  need(results.length===4&&nodeAttempts===0);assert.deepEqual(api.egressObservation(),{allowed:0,denied:0});
  await verifyInputs(inputs);await verifyTools(tools);await api.verifySources();
  const ownHashes=Object.fromEntries(await Promise.all(['run-browser-interop.mjs','browser-interop-tools.mjs','prepare-browser-interop.mjs','receiver-interop-inputs.mjs'].map(async name=>[name,digest(await readFile(new URL(name,import.meta.url)))])));
  proof={scope:'ACTUAL_CHROMIUM_WEBKIT_RECEIVER_TO_API_ROUTE_FIXTURE_NO_CORS_TLS_NATIVE_HA_OR_TV_POSITIVE',result:'PASS',api_sha:api.snapshot.head,receiver_sha:manifest.receiver_sha,input_counts:{...counts,browser_tool_files:toolFiles},negative_tool_guards:negativeToolGuards,browser_tool_manifest_sha256:digest(await readFile(join(toolsFixture,'tool-inputs-v1.json'))),qualification_sources:ownHashes,esbuild_version:esbuildVersion,browser_bundle_sha256:digest(bundle),browser_metafile_sha256:digest(JSON.stringify(built.metafile)),cases:results,node_global_fetch_attempts:0,worker_outbound_attempts:0,real_http_preflight_qualified:false,product_ui_qualified:false};
 }finally{
  globalThis.fetch=originalFetch;if(browser)await browser.close().catch(()=>{});if(api)await api.stop();
  Object.assign(console,originalConsole);for(const [name,value]of Object.entries(debugEnv)){if(value===undefined)delete process.env[name];else process.env[name]=value;}
 }
 console.log(JSON.stringify(proof));
}
main().catch(()=>{process.stderr.write('BROWSER_INTEROP_REJECTED; no payload diagnostics, traces or automatic retry\n');process.exitCode=1;});
