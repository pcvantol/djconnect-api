// Local qualification of the real Worker root. Never a deployment entrypoint.
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,chmod,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import * as esbuild from 'esbuild';

const repo=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
const guard='const PRODUCT_RENDEZVOUS_ENABLED = false as boolean;';
const hash=b=>createHash('sha256').update(b).digest('hex');
const names=['RequestAdmission','AllocationBudget','AllocationIndex','EnrollmentCoordinator','BudgetedTransactionCoordinator'];
export function deriveRootDispatcher(source){
 assert.equal(source.split(guard).length,2,'source activation guard changed');
 return source.replace(guard,'const PRODUCT_RENDEZVOUS_ENABLED = true as boolean;');
}

/** Fixed local-only derivative; no caller-selected policy, verifier or identity. */
export async function startRootIntegrationRuntime(browserOrigin){
 assert.match(browserOrigin,/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/);
 const inputs=JSON.parse(await readFile(join(repo,'rendezvous-build-inputs.json')));
 const lock=JSON.parse(await readFile(join(repo,'package-lock.json')));
 assert.equal(esbuild.version,lock.packages['node_modules/esbuild'].version);
 const dispatch=await readFile(join(repo,'src/rendezvous/dispatch.ts'),'utf8');
 const derivedDispatch=deriveRootDispatcher(dispatch);
 const scratch=await mkdtemp(join(tmpdir(),'djc-root-integration-'));await chmod(scratch,0o700);
 let runtime;
 try{
  const pins={};let replacements=0;
  const result=await esbuild.build({absWorkingDir:repo,entryPoints:['src/index.ts'],bundle:true,format:'esm',platform:'browser',target:'es2022',external:['cloudflare:workers','node:*','stream','buffer'],write:false,metafile:true,
   alias:Object.fromEntries(Object.entries(inputs.aliases).map(([name,path])=>[name,resolve(repo,path)])),
   plugins:[{name:'fixed-local-source-derivative',setup(build){
    // Same fixed ESM-to-CJS Node built-in wrappers emitted by Wrangler.
    build.onResolve({filter:/^(stream|buffer)$/},args=>args.kind==='require-call'?{path:args.path,namespace:'node-built-in-modules'}:undefined);
    build.onLoad({filter:/^(stream|buffer)$/,namespace:'node-built-in-modules'},({path})=>({contents:`import libDefault from ${JSON.stringify(path)}; module.exports = libDefault;`,loader:'js'}));
    build.onLoad({filter:/\/src\/rendezvous\/dispatch\.ts$/},async({path})=>{
    assert.equal(await readFile(path,'utf8'),dispatch);replacements++;
    return {contents:derivedDispatch,loader:'ts'};
   });}}]});
  assert.equal(replacements,1);assert.equal(result.outputFiles.length,1);
  const entry=Object.values(result.metafile.outputs).find(value=>value.entryPoint);
  assert.deepEqual(entry.exports.toSorted(),inputs.root_exports.toSorted());
  for(const [path,meta] of Object.entries(result.metafile.inputs)){
   if(path==='node-built-in-modules:stream'||path==='node-built-in-modules:buffer'){
    assert.deepEqual(meta.imports,[{path:path.split(':')[1],kind:'import-statement',external:true}]);continue;
   }
   assert(!/(?:-harness|\.check\.|fixtures|root-integration-runtime|private-profile-40381)/i.test(path));
   const absolute=resolve(repo,path);assert(absolute.startsWith(repo+'/'));
   const bytes=await readFile(absolute);pins[path]=hash(bytes);
   // Metadata is used for a closed graph, not a claim of byte-equal TS emission.
   assert(meta.bytes>=0);
  }
  for(const path of ['src/index.ts','src/rendezvous/dispatch.ts','src/rendezvous/composition.ts','qualification/rendezvous/enrollment-evidence-candidate.mjs','qualification/rendezvous/app-attest-core-candidate.mjs','qualification/rendezvous/assertion-key-state.ts'])assert(Object.hasOwn(pins,path),path);
  for(const path of ['package.json','package-lock.json','wrangler.jsonc','rendezvous-build-inputs.json','qualification/rendezvous/root-integration-runtime.mjs','qualification/rendezvous/root-integration.check.mjs'])pins[path]=hash(await readFile(join(repo,path)));
  const verify=async()=>{for(const [path,pin]of Object.entries(pins))assert.equal(hash(await readFile(join(repo,path))),pin,'source drift');};
  await verify();
  const bundle=result.outputFiles[0].text;
  for(const forbidden of ['SoftwareEnrollment','SOFTWARE_STUB_COMPOSITION','private-40381-registration-recover'])assert(!bundle.includes(forbidden));
  const cap=randomBytes(32).toString('base64url');
  const until=Date.now()+900000;
  const bindings={LOCAL_CAP:cap,LOCAL_BROWSER_ORIGIN:browserOrigin,
   RENDEZVOUS_EDGE_POLICY:'djc-direct-edge-identity/1-candidate',RENDEZVOUS_IP_HASH_KEY:randomBytes(32).toString('base64'),RECEIPT_ACTIVE_KEY:randomBytes(32).toString('base64'),
   COMPOSED_POLICY_ENABLED:'djc-http-composition-qualification/1',REQUEST_POLICY_ENABLED:'djc-request-admission-qualification/2',ALLOCATION_POLICY_ENABLED:'djc-allocation-qualification/1',INDEX_POLICY_ENABLED:'djc-index-qualification/1',ASSERTION_POLICY_ENABLED:'ios-dev-qualification/1',ASSERTION_POLICY_EXPIRES_AT:String(until),ENROLLMENT_POLICY_REVISION:'root-loopback-source-qualification/1'};
  // Canonical URL/metadata/Origin translation is an explicit local fixture.
  // Requests actually traverse HTTP; this is not Cloudflare ingress evidence.
  const driver=`import root from './root.mjs';
export {${names.join(',')}} from './root.mjs';
const observations=[];
export default {async fetch(request,env,ctx){
 const url=new URL(request.url),prefix='/'+env.LOCAL_CAP;
 if(url.pathname===prefix+'/__metrics'&&request.method==='GET'&&!url.search)return Response.json(observations);
 if(observations.length>=128)return new Response(null,{status:503});
 if(Date.now()>=Number(env.ASSERTION_POLICY_EXPIRES_AT)||!url.pathname.startsWith(prefix+'/v1/rendezvous/')||url.search)return new Response(null,{status:503});
 const headers=new Headers(request.headers),origin=headers.get('Origin');
 for(const key of [...headers.keys()])if(key.toLowerCase().startsWith('cf-')||key.toLowerCase()==='host')headers.delete(key);
 headers.set('CF-Connecting-IP','192.0.2.20');
 if(origin===env.LOCAL_BROWSER_ORIGIN)headers.set('Origin','https://vibecast.tv');
 const input=new Request('https://api.djconnect.dev'+url.pathname.slice(prefix.length),{method:request.method,headers,body:request.body,cf:{colo:'AMS'}});
 const response=await root.fetch(input,env,ctx),out=new Headers(response.headers);
 observations.push({method:request.method,route:url.pathname.slice(prefix.length+'/v1/rendezvous'.length),status:response.status});
 if(origin===env.LOCAL_BROWSER_ORIGIN&&out.get('Access-Control-Allow-Origin')==='https://vibecast.tv')out.set('Access-Control-Allow-Origin',origin);
 return new Response(response.body,{status:response.status,headers:out});
}};`;
  const require=createRequire(import.meta.resolve('wrangler'));
  const {Miniflare,Log,LogLevel,convertV4MiniflareOptions}=require('miniflare');
  let outbound=0;
  runtime=new Miniflare(convertV4MiniflareOptions({host:'127.0.0.1',inspectorHost:'127.0.0.1',durableObjectsPersist:false,unsafeInspectDurableObjects:true,log:new Log(LogLevel.NONE),workers:[{
   name:'root-integration',modulesRoot:scratch,compatibilityDate:'2026-06-20',compatibilityFlags:['nodejs_compat'],bindings,
   modules:[{type:'ESModule',path:join(scratch,'driver.mjs'),contents:driver},{type:'ESModule',path:join(scratch,'root.mjs'),contents:bundle}],
   durableObjects:Object.fromEntries(Object.entries(inputs.local_test_bindings).map(([name,className])=>[name,{className,useSQLite:true}])),
   outboundService:()=>{outbound++;return new Response(null,{status:503});},
  }]}));
  const url=await runtime.ready;assert.equal(url.hostname,'127.0.0.1');
  let disabled=false;try{await runtime.getInspectorURL();}catch{disabled=true;}assert(disabled);
  assert.equal((await fetch(url)).status,503);
  return {base:new URL('/'+cap+'/v1/rendezvous/',url).href,verify,
   async observations(){return (await fetch(new URL('/'+cap+'/__metrics',url))).json();},
   receipt:()=>({scope:'REAL_ROOT_DERIVED_LOOPBACK_HTTP_NOT_NATIVE_EDGE_OR_PUBLIC_TLS',guard_source_sha256:hash(dispatch),derived_guard_source_sha256:hash(derivedDispatch),source_hashes:pins,graph_sha256:hash(JSON.stringify(result.metafile)),bundle_sha256:hash(bundle),original_window_ms:120000,outbound,activation_allowed:false,native_positive:false}),
   async close(){await runtime.dispose();await rm(scratch,{recursive:true,force:true});},
  };
 }catch(error){await runtime?.dispose();await rm(scratch,{recursive:true,force:true});throw error;}
}
