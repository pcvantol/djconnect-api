// LOCAL TRANSPORT/CACHE OBSERVATION ONLY. Synthetic poll fixtures, not transaction success.
import {mkdir,writeFile,readFile,realpath,chmod} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import https from 'node:https';
import {setTimeout as delay} from 'node:timers/promises';
import {build} from 'esbuild';
import {Miniflare,Log,LogLevel,convertV4MiniflareOptions} from 'miniflare';
const repo=resolve(fileURLToPath(new URL('../../',import.meta.url))),[depsArg,outArg]=process.argv.slice(2);
if(!depsArg||!outArg)throw new Error('usage: pinned-playwright-root fresh-output');
const deps=await realpath(depsArg),output=resolve(outArg);if(output===repo||output.startsWith(repo+'/')||deps.startsWith(repo+'/'))throw new Error('isolated_only');
await mkdir(output,{mode:0o700});const put=(n,s)=>writeFile(join(output,n),s,{mode:0o600,flag:'wx'});
const require=createRequire(join(deps,'package.json'));if(require('playwright/package.json').version!=='1.64.1')throw new Error('pin');
const {chromium,webkit}=require('playwright'),hash=b=>createHash('sha256').update(b).digest('hex');
const source={};for(const n of ['qualification/rendezvous/run_capacity_browsers.mjs','qualification/rendezvous/capacity-cors-harness.ts','qualification/rendezvous/http-ingress.ts','src/crypto.ts','docs/rendezvous/wire-request-schemas-v1.json'])source[n]=hash(await readFile(join(repo,n)));
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(output,'tls-private.key'),'-out',join(output,'tls-local.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost'],{stdio:'ignore'});
await chmod(join(output,'tls-private.key'),0o600);await chmod(join(output,'tls-local.crt'),0o600);
const tls={key:await readFile(join(output,'tls-private.key')),cert:await readFile(join(output,'tls-local.crt'))};
// No profile, hosts/DNS/truststore/system browser changes. TLS exception is per fresh test context.
const bundled=await build({entryPoints:[join(repo,'qualification/rendezvous/capacity-cors-harness.ts')],bundle:true,write:false,format:'esm',platform:'browser',alias:{'djc-wire-schema':join(repo,'docs/rendezvous/wire-request-schemas-v1.json'),'djc-existing-crypto':join(repo,'src/crypto.ts')}});
const workers=[];const engines={};const listening=s=>new Promise(r=>s.listen(0,'127.0.0.1',r)),close=s=>new Promise(r=>s.close(r));
async function measure(name,type){
 const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:bundled.outputFiles[0].text,compatibilityDate:'2026-06-20',compatibilityFlags:['nodejs_compat'],cf:false,telemetry:{enabled:false},log:new Log(LogLevel.ERROR)}));workers.push(mf);
 const events=[];let origin,cohort,phase,t0;const html='<!doctype html><meta charset="utf-8"><title>Local CORS cache qualification</title>';
 const pageServer=https.createServer(tls,(_q,s)=>{s.writeHead(200,{'content-type':'text/html','cache-control':'no-store'});s.end(html);});await listening(pageServer);origin='https://127.0.0.1:'+pageServer.address().port;
 const apiServer=https.createServer(tls,async(q,s)=>{try{
  const path=new URL(q.url,'https://localhost').pathname,match=/^\/tv\/(\d+)\/v1\/rendezvous\/(create|poll|consume|cancel)$/.exec(path);
  if(!match||q.headers.origin!==origin){s.writeHead(403);s.end();return;}
  let bytes=0,chunks=[];for await(const c of q){bytes+=c.length;if(bytes>1024)throw new Error('size');chunks.push(c);}
  const headers=new Headers();for(const [k,v]of Object.entries(q.headers))if(v!==undefined&&!['host','connection','origin','content-length'].includes(k))headers.set(k,Array.isArray(v)?v.join(','):v);headers.set('origin','https://vibecast.tv');
  const at=Date.now(),response=await mf.dispatchFetch('https://api.djconnect.dev/v1/rendezvous/'+match[2],{method:q.method,headers,...(q.method==='POST'?{body:Buffer.concat(chunks)}:{})});
  const h=Object.fromEntries(response.headers);if(h['access-control-allow-origin']==='https://vibecast.tv')h['access-control-allow-origin']=origin;
  const event={at_ms:at-t0,tv:Number(match[1]),method:q.method,route:'/'+match[2],status:response.status,phase,preflight_method:q.headers['access-control-request-method']??null,preflight_headers:q.headers['access-control-request-headers']??null};events.push(event);
  s.writeHead(response.status,h);s.end(Buffer.from(await response.arrayBuffer()));
 }catch{s.writeHead(503);s.end();}});await listening(apiServer);const target='https://127.0.0.1:'+apiServer.address().port;
 const createProbe=JSON.parse(await readFile(join(repo,'docs/rendezvous/wire-schema-cases-v1.json'),'utf8')).cases.find(c=>c.name==='create-structural-positive').value;
 const browser=await type.launch({headless:true,...(name==='chromium'?{channel:'chromium'}:{})});const cases=[];
 try{for(const screens of [1,2,4]){
  cohort=screens;phase='fresh-context';t0=Date.now();const start=events.length;let contexts=[],pages=[];
  async function fresh(){await Promise.all(contexts.map(c=>c.close()));contexts=await Promise.all(Array.from({length:screens},()=>browser.newContext({ignoreHTTPSErrors:true,serviceWorkers:'block'})));pages=await Promise.all(contexts.map(c=>c.newPage()));await Promise.all(pages.map(p=>p.goto(origin)));}
  await fresh();const errors=[];await Promise.all(pages.map((p,tv)=>p.evaluate(async({url,body})=>{const r=await fetch(url,{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.status;},{url:target+'/tv/'+tv+'/v1/rendezvous/create',body:createProbe})));let due=Date.now();for(let round=0;round<33;round++){
   const wait=due-Date.now();if(wait>0)await delay(wait);
   if(round===10){phase='same-context-reload';await Promise.all(pages.map(p=>p.reload()));}
   if(round===20){phase='new-context';await fresh();}
   const results=await Promise.all(pages.map((p,tv)=>p.evaluate(async({url})=>{try{const r=await fetch(url,{method:'POST',mode:'cors',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify({v:'djc-rendezvous/1',transaction_id:'dd11aa22-3344-4556-8abc-0123456789ab',generation:3,claim_secret:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'})});return {status:r.status};}catch{return {error:'transport_failed'};}},{url:target+'/tv/'+tv+'/v1/rendezvous/poll'})));
   results.forEach((v,tv)=>{if(v.status!==200)errors.push({round,tv,...v});});due=Date.now()+2000;
   if(round%10===0)console.log(name+' '+screens+' screens, poll round '+round);
  }
  // Actual browser CORS preflight on new terminal routes, independent from stateful outcome replay.
  phase='terminal-route-probe';for(const route of ['consume','cancel'])await Promise.all(pages.map((p,tv)=>p.evaluate(async({url})=>{const r=await fetch(url,{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify({v:'djc-rendezvous/1',transaction_id:'dd11aa22-3344-4556-8abc-0123456789ab',generation:3,claim_secret:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'})});return r.status;},{url:target+'/tv/'+tv+'/v1/rendezvous/'+route})));
  await Promise.all(contexts.map(c=>c.close()));const trace=events.slice(start);cases.push({screens,wall_started_utc:new Date(t0).toISOString(),wall_duration_ms:Date.now()-t0,errors,events:trace});console.log(name+' '+screens+' screens complete, '+trace.length+' received requests');
 }
 engines[name]={version:browser.version(),cases};
 }finally{await browser.close();await close(apiServer);await close(pageServer);await mf.dispose();}
}
try{await Promise.all([measure('chromium',chromium),measure('webkit',webkit)]);const result={scope:'LOCAL_REAL_BROWSER_CORS_ONLY_REPLAY_SEPARATE_NO_PUBLIC_NATIVE_OR_CAPACITY_PASS',playwright:'1.64.1',platform:process.platform,arch:process.arch,node:process.version,compatibility_date:'2026-06-20',cadence_ms:2000,rounds:33,topology:'two loopback HTTPS ports, fixed Origin/requestURL/ACAO translation to exact canonical ingress, fresh isolated contexts',tls:'temporary self-signed cert; per-context ignoreHTTPSErrors; no truststore change or TLS qualification',admission:'CORS probe uses exact ingress with trusted always-admit fixture and synthetic pending responses; actual stateful gate replay is separate',source_sha256:source,engines};result.transport_status=Object.values(engines).every(e=>e.cases.every(c=>c.errors.length===0))?'PASS':'FAILED';if(result.transport_status!=='PASS')process.exitCode=1;await put('browser-traces-sanitized.json',JSON.stringify(result,null,2)+'\n');console.log('Both engines complete; no stateful capacity PASS inferred.');}finally{for(const mf of workers)await mf.dispose().catch(()=>{});}
