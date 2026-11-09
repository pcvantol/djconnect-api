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
 need(checked.status===0);const preparation=JSON.parse(checked.stdout);need(preparation.activation_allowed===false);
 const plan=JSON.parse(await readFile(join(repo,'docs/rendezvous/deployment-preparation-v1.json')));
 const rootPath='docs/rendezvous/closed-enrollment-service-product-observations-v2.json';
 const rootRaw=await readFile(join(repo,rootPath));
 need(plan.reference_hashes[rootPath]===sha(rootRaw));
 const root=JSON.parse(rootRaw);
 // Retain both historical proofs and exact separately validated deltas.
 // No current checkout/JSON may replace an original proof or authorize native.
 const delta=preparation.qualification_workflow_delta;
 need(delta&&Object.keys(delta).join(',')==='.github/workflows/ci-cd.yml');
 const closedPath='docs/rendezvous/host-wake-closed-root-source-delta-v1.json';
 const closedRaw=await readFile(join(repo,closedPath)),provenance=preparation.source_provenance;
 need(plan.reference_hashes[closedPath]===sha(closedRaw)&&sha(closedRaw)===provenance.closed_receiving_root_delta_sha256);
 const closed=JSON.parse(closedRaw);
 need(closed.scope==='EXACT_CLOSED_RECEIVING_ROOT_SOURCE_DELTA_NOT_ACTIVATION'&&closed.public_activation_allowed===false);
 need(closed.baseline_source_map_sha256===provenance.qualified_source_map_sha256&&closed.effective_source_map_sha256===provenance.closed_receiving_root_source_map_sha256);
 const retentionPath='docs/rendezvous/active-ci-retention-source-delta-v1.json',retentionRaw=await readFile(join(repo,retentionPath));
 need(plan.reference_hashes[retentionPath]===sha(retentionRaw)&&sha(retentionRaw)===provenance.active_ci_retention_delta_sha256);
 const retention=JSON.parse(retentionRaw);
 need(retention.scope==='EXACT_ACTIVE_CI_RETENTION_SOURCE_ONLY_NOT_RUNTIME'&&retention.public_activation_allowed===false);
 need(retention.baseline_source_map_sha256===closed.effective_source_map_sha256&&retention.effective_source_map_sha256===provenance.active_ci_retention_source_map_sha256);
 const categoryPath='docs/rendezvous/native-first-category-source-delta-v1.json',categoryRaw=await readFile(join(repo,categoryPath));
 need(plan.reference_hashes[categoryPath]===sha(categoryRaw)&&sha(categoryRaw)===provenance.native_first_category_delta_sha256);
 const category=JSON.parse(categoryRaw);need(category.scope==='EXACT_PRIVATE_FIRST_CATEGORY_SOURCE_NOT_ACTIVATION'&&category.public_activation_allowed===false);
 need(category.baseline_source_map_sha256===retention.effective_source_map_sha256&&category.effective_source_map_sha256===provenance.native_first_category_source_map_sha256);
 const mountPath='docs/rendezvous/private-receiving-mount-source-delta-v1.json',mountRaw=await readFile(join(repo,mountPath));
 need(plan.reference_hashes[mountPath]===sha(mountRaw)&&sha(mountRaw)===provenance.private_receiving_mount_delta_sha256);
 const mount=JSON.parse(mountRaw);need(mount.scope==='EXACT_PRIVATE_RECEIVING_MOUNT_NOT_EFFECT_AUTHORIZATION'&&mount.private_http_mount_selected===true&&mount.production_effect_authorized===false);
 need(mount.baseline_source_map_sha256===category.effective_source_map_sha256&&mount.effective_source_map_sha256===provenance.private_receiving_mount_source_map_sha256);
 const dependencyPath='docs/rendezvous/pkijs-wrangler-dependency-refresh-source-delta-v1.json',dependencyRaw=await readFile(join(repo,dependencyPath));
 need(plan.reference_hashes[dependencyPath]===sha(dependencyRaw)&&sha(dependencyRaw)===provenance.dependency_refresh_delta_sha256);
 const dependency=JSON.parse(dependencyRaw);need(dependency.scope==='EXACT_PKIJS_WRANGLER_DEPENDENCY_REFRESH_NOT_ACTIVATION'&&dependency.public_activation_allowed===false&&dependency.production_effect_authorized===false);
 need(dependency.baseline_source_map_sha256===mount.effective_source_map_sha256&&dependency.effective_source_map_sha256===provenance.dependency_refresh_source_map_sha256);
 const watchPath='docs/rendezvous/watch-topic-source-delta-v1.json',watchRaw=await readFile(join(repo,watchPath));
 need(plan.reference_hashes[watchPath]===sha(watchRaw)&&sha(watchRaw)===provenance.watch_topic_delta_sha256);
 const watch=JSON.parse(watchRaw);need(watch.scope==='EXACT_WATCH_TOPIC_ALIGNMENT_NOT_ACTIVATION'&&watch.public_activation_allowed===false&&watch.production_effect_authorized===false);
 need(watch.baseline_source_map_sha256===dependency.effective_source_map_sha256&&watch.effective_source_map_sha256===provenance.watch_topic_source_map_sha256);
 const receiptPath='docs/rendezvous/watch-registration-receipt-source-delta-v1.json',receiptRaw=await readFile(join(repo,receiptPath));
 need(plan.reference_hashes[receiptPath]===sha(receiptRaw)&&sha(receiptRaw)===provenance.watch_registration_receipt_delta_sha256);
 const receipt=JSON.parse(receiptRaw);need(receipt.scope==='EXACT_WATCH_REGISTRATION_RECEIPT_NOT_ACTIVATION'&&receipt.public_activation_allowed===false&&receipt.production_effect_authorized===false);
 need(receipt.baseline_source_map_sha256===watch.effective_source_map_sha256&&receipt.effective_source_map_sha256===provenance.watch_registration_receipt_source_map_sha256);
 const releaseRetentionPath='docs/rendezvous/release-ci-retention-source-delta-v1.json',releaseRetentionRaw=await readFile(join(repo,releaseRetentionPath));
 need(plan.reference_hashes[releaseRetentionPath]===sha(releaseRetentionRaw)&&sha(releaseRetentionRaw)===provenance.release_ci_retention_delta_sha256);
 const releaseRetention=JSON.parse(releaseRetentionRaw);need(releaseRetention.scope==='EXACT_RELEASE_CI_RETENTION_SOURCE_ONLY_NOT_RUNTIME'&&releaseRetention.public_activation_allowed===false);
 need(releaseRetention.baseline_source_map_sha256===receipt.effective_source_map_sha256&&releaseRetention.effective_source_map_sha256===provenance.release_ci_retention_source_map_sha256);
 const bindingsPath='docs/rendezvous/closed-production-bindings-source-delta-v1.json';
 const bindingsRaw=await readFile(join(repo,bindingsPath));
 need(plan.reference_hashes[bindingsPath]===sha(bindingsRaw)&&sha(bindingsRaw)===provenance.closed_production_bindings_delta_sha256);
 const bindings=JSON.parse(bindingsRaw);
 need(bindings.scope==='EXACT_CLOSED_PRODUCTION_BINDINGS_SOURCE_ONLY'&&bindings.public_activation_allowed===false&&bindings.production_effect_authorized===false);
 need(bindings.baseline_source_map_sha256===releaseRetention.effective_source_map_sha256&&bindings.effective_source_map_sha256===provenance.closed_production_bindings_source_map_sha256);
 const toolchainPath='docs/rendezvous/toolchain-development-dependency-refresh-v1.json';
 const toolchainRaw=await readFile(join(repo,toolchainPath));
 need(plan.reference_hashes[toolchainPath]===sha(toolchainRaw)&&sha(toolchainRaw)===provenance.toolchain_refresh_delta_sha256);
 const toolchain=JSON.parse(toolchainRaw);
 need(toolchain.scope==='EXACT_TOOLCHAIN_AND_DEVELOPMENT_DEPENDENCY_REFRESH_NOT_ACTIVATION'&&toolchain.public_activation_allowed===false);
 need(toolchain.baseline_source_map_sha256===bindings.effective_source_map_sha256&&toolchain.effective_source_map_sha256===provenance.toolchain_refresh_source_map_sha256);
 const toolchainFiles=["package-lock.json","package.json","scripts/qualify_rendezvous_product_build.mjs"];
 need(Object.keys(toolchain.changes).length===toolchainFiles.length&&toolchainFiles.every(name=>Object.hasOwn(toolchain.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 const maintenancePath='docs/rendezvous/api-maintenance-source-delta-v1.json';
 const maintenanceRaw=await readFile(join(repo,maintenancePath));
 need(plan.reference_hashes[maintenancePath]===sha(maintenanceRaw)&&sha(maintenanceRaw)===provenance.api_maintenance_delta_sha256);
 const maintenance=JSON.parse(maintenanceRaw);
 need(maintenance.scope==='EXACT_API_MAINTENANCE_SOURCE_ONLY_NOT_ACTIVATION'&&maintenance.public_activation_allowed===false);
 need(maintenance.baseline_source_map_sha256===toolchain.effective_source_map_sha256&&maintenance.effective_source_map_sha256===provenance.api_maintenance_source_map_sha256);
 const maintenanceFiles=["src/auth.ts","src/handlers/install.ts","src/messages.ts","src/repositories/installTokens.ts","src/repositories/registrations.ts"];
 need(Object.keys(maintenance.changes).length===maintenanceFiles.length&&maintenanceFiles.every(name=>Object.hasOwn(maintenance.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 const stablePath='docs/rendezvous/stable-api-release-source-delta-v1.json';
 const stableRaw=await readFile(join(repo,stablePath));
 need(plan.reference_hashes[stablePath]===sha(stableRaw)&&sha(stableRaw)===provenance.stable_release_delta_sha256);
 const stable=JSON.parse(stableRaw);
 need(stable.scope==='EXACT_STABLE_API_RELEASE_METADATA_NOT_ACTIVATION'&&stable.public_activation_allowed===false);
 need(stable.baseline_source_map_sha256===maintenance.effective_source_map_sha256&&stable.effective_source_map_sha256===provenance.stable_release_source_map_sha256);
 const stableFiles=["src/auth.ts","src/handlers/install.ts","src/messages.ts","src/repositories/installTokens.ts","src/repositories/registrations.ts"];
 need(Object.keys(stable.changes).length===stableFiles.length&&stableFiles.every(name=>Object.hasOwn(stable.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 for(const [name,pin] of Object.entries(root.source_hashes))if(!name.startsWith('node_modules/')){
  let expected=pin;
  if(Object.hasOwn(delta,name)){need(delta[name].before===expected);expected=delta[name].after;}
  if(Object.hasOwn(closed.changes,name)){need(closed.changes[name].before===expected);expected=closed.changes[name].after;}
  if(Object.hasOwn(retention.changes,name)){need(retention.changes[name].before===expected);expected=retention.changes[name].after;}
  if(Object.hasOwn(category.changes,name)){need(category.changes[name].before===expected);expected=category.changes[name].after;}
  if(Object.hasOwn(mount.changes,name)){need(mount.changes[name].before===expected);expected=mount.changes[name].after;}
  if(Object.hasOwn(dependency.source_changes,name)){need(dependency.source_changes[name].before===expected);expected=dependency.source_changes[name].after;}
  if(Object.hasOwn(watch.source_changes,name)){need(watch.source_changes[name].before===expected);expected=watch.source_changes[name].after;}
  if(Object.hasOwn(receipt.source_changes,name)){need(receipt.source_changes[name].before===expected);expected=receipt.source_changes[name].after;}
  if(Object.hasOwn(releaseRetention.changes,name)){need(releaseRetention.changes[name].before===expected);expected=releaseRetention.changes[name].after;}
  if(Object.hasOwn(bindings.changes,name)){need(bindings.changes[name].before===expected);expected=bindings.changes[name].after;}
  if(Object.hasOwn(toolchain.changes,name)){need(toolchain.changes[name].before===expected);expected=toolchain.changes[name].after;}
 need(Object.keys(maintenance.changes).length===maintenanceFiles.length&&maintenanceFiles.every(name=>Object.hasOwn(maintenance.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 need(Object.keys(stable.changes).length===stableFiles.length&&stableFiles.every(name=>Object.hasOwn(stable.changes,name)&&Object.hasOwn(root.source_hashes,name)));
  need(plan.source_hashes[name]===expected);
 }
 const pins={...root.source_hashes,...plan.source_hashes,...plan.reference_hashes};
 const installed=Object.keys(root.source_hashes).filter(p=>p.startsWith('node_modules/'));need(installed.length===50);
 for(const [name,change] of Object.entries(dependency.installed_changes)){need(name==='node_modules/pkijs/build/index.js'&&pins[name]===change.before);pins[name]=change.after;}
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
  if(stage)Object.assign(aliases,{cbor:join(repo,'node_modules/cbor/lib/cbor.js'),asn1js:createRequire(import.meta.url).resolve('asn1js'),pkijs:createRequire(import.meta.url).resolve('pkijs')});
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
  runtime=new Miniflare({...convertV4MiniflareOptions({host:'127.0.0.1',inspectorHost:'127.0.0.1',durableObjectsPersist:false,unsafeInspectDurableObjects:true,log:new Log(LogLevel.NONE),workers:[{name:'local-native',compatibilityDate:'2026-06-20',compatibilityFlags:['nodejs_compat'],modulesRoot:join(scratch,'build'),modules:[{type:'ESModule',path:join(scratch,'build/driver.mjs'),contents:bundle}],bindings,durableObjects:Object.fromEntries(Object.entries(inputs.local_test_bindings).map(([k,className])=>[k,{className,useSQLite:true}])),outboundService:outbound},
   // Separate QA-only positive interception control; no DOs, secrets or arbitrary URL.
   {name:'guard-control',modulesRoot:scratch,modules:[{type:'ESModule',path:join(scratch,'guard.mjs'),contents:"export default {fetch(){return fetch('https://egress-denied.example.invalid/qualification');}}"}],outboundService:outbound}]}),enableDevRegistry:false});
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
