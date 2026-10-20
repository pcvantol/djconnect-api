// API-owned local server experiment. No product endpoint, native target or activation.
import {createHash,randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,writeFile,chmod,rm} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {need,ROUTES} from './local-native-files.mjs';
import {statusOnlyOutbound,allowedStatusRequest} from './local-native-egress.mjs';
import {stage40381,check40381Graph,registrationRecoverController} from './private-profile-40381.mjs';

export const repo=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
const sha=v=>createHash('sha256').update(v).digest('hex');
const toolFiles=['qualification/rendezvous/local-native-files.mjs','qualification/rendezvous/local-native-egress.mjs','qualification/rendezvous/local-native-runtime.mjs','qualification/rendezvous/run-local-native.mjs','qualification/rendezvous/private-profile-40381.mjs','qualification/rendezvous/run-local-native-40381.mjs'];
export function gitRead(args){
 const env=Object.fromEntries(Object.entries(process.env).filter(([name])=>!name.startsWith('GIT_')));
 Object.assign(env,{GIT_NO_LAZY_FETCH:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0',GIT_NO_REPLACE_OBJECTS:'1'});
 return spawnSync('git',args,{cwd:repo,env,encoding:'utf8',timeout:10000});
}
export async function checkSourcePins(pins,base){
 for(const [p,h] of Object.entries(pins)){need(!p.includes('..')&&!p.startsWith('/'));need(sha(await readFile(join(base,p)))===h);}
}
export async function sourceSnapshot(){
 const status=gitRead(['status','--porcelain','--untracked-files=normal']);need(status.status===0&&status.stdout==='');
 const checked=spawnSync('python3',['scripts/validate_rendezvous_deployment_plan.py'],{cwd:repo,encoding:'utf8',timeout:30000});
 need(checked.status===0&&JSON.parse(checked.stdout).activation_allowed===false);
 const plan=JSON.parse(await readFile(join(repo,'docs/rendezvous/deployment-preparation-v1.json')));
 const root=JSON.parse(await readFile(join(repo,'docs/rendezvous/enrollment-policy-build-observations-v1.json')));
 const pins={...plan.source_hashes,...plan.reference_hashes,...root.source_hashes};
 const installed=Object.keys(root.source_hashes).filter(p=>p.startsWith('node_modules/'));need(installed.length===32);
 await checkSourcePins(pins,repo);
 for(const p of toolFiles)pins[p]=sha(await readFile(join(repo,p)));
 const head=gitRead(['rev-parse','HEAD']);need(head.status===0&&/^[0-9a-f]{40}\n$/.test(head.stdout));
 return {head:head.stdout.trim(),pins};
}
export async function startLocalRuntime(){
 return startRuntime(false);
}
export async function startLocal40381Runtime(){
 return startRuntime(true);
}
async function startRuntime(private40381){
 const snapshot=await sourceSnapshot(),scratch=await mkdtemp(join(tmpdir(),'djc-native-local-'));await chmod(scratch,0o700);
 let runtime;
 try{
  const inputs=JSON.parse(await readFile(join(repo,'rendezvous-build-inputs.json')));
  const stage=private40381?await stage40381(snapshot,repo,scratch):undefined;
  const source=stage?.root??repo;
  const bridge=randomBytes(32).toString('base64url');
  const driver=`import {createProductRendezvousHandler} from ${JSON.stringify(join(source,'src/rendezvous/composition.ts'))};
export {RequestAdmission,AllocationBudget,AllocationIndex,EnrollmentCoordinator,BudgetedTransactionCoordinator} from ${JSON.stringify(join(source,'src/index.ts'))};
export default {async fetch(request,env){
 if(request.headers.get('X-Local-Bridge')!==env.LOCAL_BRIDGE)return new Response(null,{status:503});
 const path=new URL(request.url).pathname;
 if(!${JSON.stringify(ROUTES)}.includes(path)||request.method!=='POST')return new Response(null,{status:400});
 const headers=new Headers({'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.20'});
 if(['/create','/poll','/consume','/cancel'].includes(path))headers.set('Origin','https://vibecast.tv');
 const incoming=new Request('https://api.djconnect.dev/v1/rendezvous'+path,{method:'POST',headers,body:request.body,cf:{colo:'AMS'}});
 return createProductRendezvousHandler(env)(incoming);
}};`;
  await writeFile(join(scratch,'driver.ts'),driver,{mode:0o600});
  const aliases=Object.fromEntries(Object.entries(inputs.aliases).map(([k,v])=>[k,resolve(source,v)]));
  if(stage)Object.assign(aliases,{cbor:join(repo,'node_modules/cbor/lib/cbor.js'),asn1js:join(repo,'node_modules/asn1js/build/index.es.js'),pkijs:join(repo,'node_modules/pkijs/build/index.es.js')});
  const config={name:'djc-private-native-local',main:join(scratch,'driver.ts'),compatibility_date:'2026-06-20',compatibility_flags:['nodejs_compat'],workers_dev:false,send_metrics:false,alias:aliases};
  await writeFile(join(scratch,'wrangler.json'),JSON.stringify(config),{mode:0o600});
  const built=spawnSync(process.execPath,[join(repo,'node_modules/wrangler/bin/wrangler.js'),'deploy','--dry-run','--config',join(scratch,'wrangler.json'),'--outdir',join(scratch,'build'),'--metafile',join(scratch,'meta.json')],{cwd:repo,encoding:'utf8',timeout:120000,env:{...process.env,WRANGLER_SEND_METRICS:'false'}});
  need(built.status===0); // Build output is deliberately never logged (paths/contents may be private).
  const bundle=await readFile(join(scratch,'build/driver.js'),'utf8');
  need(!bundle.includes('SoftwareEnrollment')&&!bundle.includes('SOFTWARE_STUB_COMPOSITION'));
  const metadata=JSON.parse(await readFile(join(scratch,'meta.json')));
  const entry=Object.values(metadata.outputs).find(o=>o.entryPoint);need(entry&&entry.exports.length===6&&entry.exports.includes('default'));
  if(stage){await stage.verify();check40381Graph(metadata,stage,snapshot,repo,scratch);}
  for(const p of Object.keys(metadata.inputs)){
   need(!/(?:-harness|\.check\.|fixtures|pre-qr-replacement-reference)/i.test(p));
   if(p.startsWith('node-built-in-modules:'))continue;
   const absolute=resolve(scratch,p);
   need(absolute===join(scratch,'driver.ts')||Object.hasOwn(snapshot.pins,absolute.slice(repo.length+1))&&absolute.startsWith(repo+'/')||stage&&absolute.startsWith(stage.root+'/')&&Object.hasOwn(stage.pins,absolute.slice(stage.root.length+1)));
  }
  const require=createRequire(import.meta.resolve('wrangler'));
  const {Miniflare,Log,LogLevel,convertV4MiniflareOptions}=require('miniflare');
  const until=Date.now()+900000;
  const bindings={LOCAL_BRIDGE:bridge,RENDEZVOUS_EDGE_POLICY:'djc-direct-edge-identity/1-candidate',RENDEZVOUS_IP_HASH_KEY:randomBytes(32).toString('base64'),RECEIPT_ACTIVE_KEY:randomBytes(32).toString('base64'),COMPOSED_POLICY_ENABLED:'djc-http-composition-qualification/1',REQUEST_POLICY_ENABLED:'djc-request-admission-qualification/2',ALLOCATION_POLICY_ENABLED:'djc-allocation-qualification/1',INDEX_POLICY_ENABLED:'djc-index-qualification/1',ASSERTION_POLICY_ENABLED:'ios-dev-qualification/1',ASSERTION_POLICY_EXPIRES_AT:String(until),ENROLLMENT_POLICY_REVISION:stage?'private-40381-registration-recover/1':'local-native-file-experiment/1'};
  const egress={allowed:0,denied:0};
  const outbound=async request=>{egress[allowedStatusRequest(request)?'allowed':'denied']++;return statusOnlyOutbound(request);};
  runtime=new Miniflare(convertV4MiniflareOptions({host:'127.0.0.1',inspectorHost:'127.0.0.1',durableObjectsPersist:false,unsafeInspectDurableObjects:true,log:new Log(LogLevel.NONE),workers:[{name:'local-native',compatibilityDate:'2026-06-20',compatibilityFlags:['nodejs_compat'],modulesRoot:join(scratch,'build'),modules:[{type:'ESModule',path:join(scratch,'build/driver.mjs'),contents:bundle}],bindings,durableObjects:Object.fromEntries(Object.entries(inputs.local_test_bindings).map(([k,className])=>[k,{className,useSQLite:true}])),outboundService:outbound},
   // Separate QA-only positive interception control; no DOs, secrets or arbitrary URL.
   {name:'guard-control',modulesRoot:scratch,modules:[{type:'ESModule',path:join(scratch,'guard.mjs'),contents:"export default {fetch(){return fetch('https://egress-denied.example.invalid/qualification');}}"}],outboundService:outbound}]}));
  const url=await runtime.ready;need(url.hostname==='127.0.0.1');
  let inspectorDisabled=false;try{await runtime.getInspectorURL();}catch{inspectorDisabled=true;}need(inspectorDisabled);
  const control=await runtime.getWorker('guard-control');need((await control.fetch('https://local.invalid/')).status===503&&egress.denied===1&&egress.allowed===0);
  egress.denied=0;
  const worker=await runtime.getWorker('local-native');
  need((await worker.fetch('https://local.invalid/attestation/challenge',{method:'POST',body:'{}'})).status===503);
  need((await fetch(new URL('/attestation/challenge',url),{method:'POST',body:'{}',redirect:'manual'})).status===503);
  const send=(route,body)=>worker.fetch('https://local.invalid'+route,{method:'POST',headers:{'X-Local-Bridge':bridge},body});
  const request=stage?registrationRecoverController(send):send;
  return {
   snapshot,bundle_sha256:sha(bundle),
   ...(stage?{private_profile:{...stage.receipt,metafile_sha256:sha(JSON.stringify(metadata))}}:{}),
   egressObservation(){return {...egress};},
   async verifySources(){need(JSON.stringify(await sourceSnapshot())===JSON.stringify(snapshot));if(stage)await stage.verify();need(Date.now()<until);},
   async request(route,body){need(ROUTES.includes(route)&&body instanceof Uint8Array);if(stage){need(Date.now()<until);await stage.verify();}return request(route,body);},
   // Host-only observations, never RPC or wire parameters. Used by negative CI tests.
   async enrollmentObservation(keyId){
    const address=sha(JSON.stringify(['development','ios-dev-qualification/1',keyId]));
    const storage=await runtime.unsafeGetDurableObjectStorage('local-native','EnrollmentCoordinator',{name:'djc-rendezvous-key/1/'+address});
    return {keys:await storage.exec('SELECT COUNT(*) AS n FROM key_state'),operations:await storage.exec('SELECT expires_at,value FROM enrollment_operation')};
   },
   async stop(){await runtime.dispose();await rm(scratch,{recursive:true,force:true});},
  };
 }catch(error){if(runtime)await runtime.dispose();await rm(scratch,{recursive:true,force:true});throw error;}
}
