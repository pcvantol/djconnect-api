// Fixed offline QA artifact builder. No upload, provider API, native or selectors.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdtemp,chmod,copyFile,realpath,mkdir,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,dirname,join,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import * as esbuild from 'esbuild';

export const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..');
export const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
// This is a fixed historical source variant, never a runtime/profile selector.
export const fixedQaIdentity=Object.freeze({application_identifier:'ZEML4LPXH4.dev.djconnect.ios.vibecastqa',build:'40408',app_policy:'ios-vibecast-qa-development/1',environment:'development'});
const replacements={"https://api.djconnect.dev":"https://api-vibecast-qa.djconnect.dev","https://vibecast.tv":"https://qa.vibecast.tv","ZEML4LPXH4.dev.djconnect.ios":"ZEML4LPXH4.dev.djconnect.ios.vibecastqa","ios-dev-qualification/1":"ios-vibecast-qa-development/1","const BUILDS = new Set(['40227', '40228', '40230']);":"const BUILDS = new Set(['40408']);"};
const expected={"src/rendezvous/composition.ts":{"https://api.djconnect.dev":1,"ios-dev-qualification/1":1},"qualification/rendezvous/http-ingress.ts":{"https://api.djconnect.dev":1,"https://vibecast.tv":1},"qualification/rendezvous/assertion-key-state.ts":{"https://api.djconnect.dev":1,"ios-dev-qualification/1":1},"qualification/rendezvous/transaction-state.ts":{"https://api.djconnect.dev":1,"ios-dev-qualification/1":1},"docs/rendezvous/wire-request-schemas-v1.json":{"https://api.djconnect.dev":4,"https://vibecast.tv":1},"qualification/rendezvous/key-routing.ts":{"ios-dev-qualification/1":1},"qualification/rendezvous/receipt-key-store.ts":{"ios-dev-qualification/1":1},"qualification/rendezvous/app-attest-core-candidate.mjs":{"ZEML4LPXH4.dev.djconnect.ios":1,"const BUILDS = new Set(['40227', '40228', '40230']);":1},"qualification/rendezvous/receipt-cms-candidate.mjs":{"ZEML4LPXH4.dev.djconnect.ios":1},"qualification/rendezvous/enrollment-evidence-candidate.mjs":{"ios-dev-qualification/1":1},"qualification/rendezvous/enrollment-key-state.ts":{"ios-dev-qualification/1":1},"qualification/rendezvous/enrollment-evidence-candidate.d.mts":{"ios-dev-qualification/1":2}};
function gitRead(args){
 const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('GIT_')));
 const result=spawnSync('git',['--no-replace-objects',...args],{cwd:repo,env,encoding:'utf8'});
 assert.equal(result.status,0,'fixed repository Git read failed');return result.stdout;
}
export async function fixedGitIdentity(){
 assert.equal(await realpath(gitRead(['rev-parse','--show-toplevel']).trim()),await realpath(repo),'wrong Git worktree');
 const sourceSha=gitRead(['rev-parse','HEAD']).trim();assert.match(sourceSha,/^[a-f0-9]{40}$/);
 assert.equal(gitRead(['status','--porcelain','--untracked-files=all']).trim(),'','QA artifact requires a clean committed worktree');
 return sourceSha;
}
export function verifyCommittedInput(sourceSha,name,pin){
 assert(resolve(repo,name).startsWith(repo+'/'),'input outside fixed worktree');
 assert.equal(hash(gitRead(['show',sourceSha+':'+name])),pin,'graph/build input differs from exact committed source');
}
export function deriveFixedQaSource(path,source,pin){
 assert(Object.hasOwn(expected,path),'unselected transform');
 assert.deepEqual(pin.counts,expected[path]);assert.equal(hash(source),pin.source_sha256,'pinned source drift');
 let derived=source;
 for(const [from,count] of Object.entries(expected[path])){
  assert.equal(source.split(from).length-1,count,'origin count drift');
  derived=derived.replaceAll(from,replacements[from]);
 }
 assert.equal(hash(derived),pin.derived_sha256,'derived source drift');
 return derived;
}
export async function buildFixedQa(){
 assert.equal(process.argv.length,2,'no build arguments or selectors');
 const load=async path=>JSON.parse(await readFile(join(repo,path),'utf8'));
 const profile=await load('qualification/rendezvous/qa-build-profile.json');
 assert.equal(profile.schema_version,1);assert.equal(profile.service,'djconnect-api-vibecast-qa');
 assert.equal(profile.service_origin,replacements['https://api.djconnect.dev']);assert.equal(profile.browser_origin,replacements['https://vibecast.tv']);
 assert.deepEqual(profile.qa_verifier_identity,fixedQaIdentity);
 assert.equal(profile.historical_apple_artifact.disposition,'HISTORICAL_SIGNED_READBACK_ONLY_EXPIRED_WINDOW_NO_ADMISSION');
 assert.equal(profile.activation_allowed,false);assert.equal(profile.current_apple_profile,null);assert.equal(profile.operational_admission,null);
 assert.deepEqual(Object.keys(profile.transforms).sort(),Object.keys(expected).sort());
 const entry=await readFile(join(repo,'src/rendezvous/qa-entry.ts'),'utf8');
 assert.equal(entry.split('const QA_ACTIVATION_REVIEWED = false as boolean;').length,2,'closed QA guard changed');
 const lock=await load('package-lock.json');assert.equal(esbuild.version,lock.packages['node_modules/esbuild'].version);
 const inputs=await load('rendezvous-build-inputs.json');
 const sourceSha=await fixedGitIdentity();
 const output=await mkdtemp(join(tmpdir(),'djc-fixed-qa-'));await chmod(output,0o700);
 const transforms={},seen=new Set();
 const result=await esbuild.build({absWorkingDir:repo,entryPoints:['src/rendezvous/qa-entry.ts'],bundle:true,format:'esm',platform:'browser',target:'es2022',external:['cloudflare:workers','node:*','stream','buffer'],write:false,metafile:true,
  define:{__DJC_QA_SOURCE_SHA__:JSON.stringify(sourceSha)},
  alias:Object.fromEntries(Object.entries(inputs.aliases).map(([k,v])=>[k,resolve(repo,v)])),
  plugins:[{name:'fixed-qa-graph',setup(build){
   build.onResolve({filter:/^(stream|buffer)$/},args=>args.kind==='require-call'?{path:args.path,namespace:'node-built-in-modules'}:undefined);
   build.onLoad({filter:/^(stream|buffer)$/,namespace:'node-built-in-modules'},({path})=>({contents:`import libDefault from ${JSON.stringify(path)}; module.exports = libDefault;`,loader:'js'}));
   build.onLoad({filter:/\.(?:ts|mjs|json)$/},async({path})=>{
    const name=relative(repo,path);if(!Object.hasOwn(expected,name))return;
    assert(!seen.has(name));seen.add(name);const source=await readFile(path,'utf8');
    const contents=deriveFixedQaSource(name,source,profile.transforms[name]);
    transforms[name]={source_sha256:hash(source),derived_sha256:hash(contents),counts:expected[name]};
    return {contents,loader:name.endsWith('.json')?'json':name.endsWith('.mjs')?'js':'ts'};
   });
  }}]});
 assert.deepEqual([...seen].sort(),Object.keys(expected).filter(name=>!name.endsWith('.d.mts')).sort());assert.equal(result.outputFiles.length,1);
 const exports=Object.values(result.metafile.outputs).find(x=>x.entryPoint).exports.sort();
 assert.deepEqual(exports,[...Object.values(inputs.local_test_bindings),'default'].sort());
 const pins={},installed={};
 for(const name of Object.keys(result.metafile.inputs)){
  if(name.startsWith('node-built-in-modules:')){assert(['node-built-in-modules:stream','node-built-in-modules:buffer'].includes(name));continue;}
  const path=resolve(repo,name);assert(path.startsWith(repo+'/'));assert(!/(?:-harness|\.check\.|fixtures|private-profile-40381)/i.test(name));
  (name.startsWith('node_modules/')?installed:pins)[name]=hash(await readFile(path));
 }
 for(const name of ['package.json','package-lock.json','rendezvous-build-inputs.json','qualification/rendezvous/qa-build-profile.json','qualification/rendezvous/qa-worker-config.json','scripts/build_rendezvous_qa.mjs','scripts/qualify_rendezvous_qa_build.mjs','scripts/test_rendezvous_qa_git_provenance.mjs','scripts/qualify_rendezvous_qa_profile.mjs','qualification/rendezvous/qa-profile.check.mjs','qualification/rendezvous/qa-profile-cms-fixtures.json'])pins[name]=hash(await readFile(join(repo,name)));
 // Typecheck the actual derived graph, including the erased declaration module.
 // Stage only committed source bytes; declarations never enter the Worker bundle.
 const typed=join(output,'derived-types');await mkdir(typed);await symlink(join(repo,'node_modules'),join(typed,'node_modules'),'dir');
 const typeNames=gitRead(['ls-files','src','qualification/rendezvous','tsconfig.json','worker-configuration.d.ts','docs/rendezvous/wire-request-schemas-v1.json']).trim().split('\n').filter(name=>/\.(?:ts|mts|mjs|json)$/.test(name));
 for(const name of typeNames){
  const source=await readFile(join(repo,name),'utf8');pins[name]=hash(source);verifyCommittedInput(sourceSha,name,pins[name]);
  const contents=Object.hasOwn(expected,name)?deriveFixedQaSource(name,source,profile.transforms[name]):source;
  const target=join(typed,name);await mkdir(dirname(target),{recursive:true});await writeFile(target,contents);
  if(name.endsWith('.d.mts')&&Object.hasOwn(expected,name))transforms[name]={source_sha256:hash(source),derived_sha256:hash(contents),counts:expected[name]};
 }
 assert.deepEqual(Object.keys(transforms).sort(),Object.keys(expected).sort());
 await writeFile(join(typed,'qa-policy-type-probe.ts'),`import type {SavedEnrollmentState,EnrollmentEvidence} from './qualification/rendezvous/enrollment-evidence-candidate.mjs';
const policy: SavedEnrollmentState['policy']['id'] = 'ios-vibecast-qa-development/1';
const evidence: EnrollmentEvidence['policy'] = policy;
// @ts-expect-error Ordinary production policy is not the derived QA policy.
const wrongState: SavedEnrollmentState['policy']['id'] = 'ios-dev-qualification/1';
// @ts-expect-error Both erased declaration policy fields must be transformed.
const wrongEvidence: EnrollmentEvidence['policy'] = 'ios-dev-qualification/1';
void evidence;void wrongState;void wrongEvidence;`);
 await writeFile(join(typed,'tsconfig.qa.json'),JSON.stringify({extends:'./tsconfig.json',include:['worker-configuration.d.ts','src/**/*.ts','qa-policy-type-probe.ts'],exclude:[]}));
 const types=spawnSync(process.execPath,[join(repo,'node_modules/typescript/bin/tsc'),'--noEmit','--project',join(typed,'tsconfig.qa.json')],{cwd:typed,encoding:'utf8'});
 await writeFile(join(output,'private-derived-types.log'),types.stdout+types.stderr,{mode:0o600});assert.equal(types.status,0,'derived QA graph strict types failed');
 const bundle=result.outputFiles[0].text;
 for(const forbidden of ['https://api.djconnect.dev','https://vibecast.tv','SoftwareEnrollment','SOFTWARE_STUB_COMPOSITION','private-40381-registration-recover','APNS_PRIVATE_KEY','DJCONNECT_RELAY_SECRET'])assert(!bundle.includes(forbidden),forbidden);
 assert(!bundle.includes("ios-dev-qualification/1"));
 assert(bundle.includes(fixedQaIdentity.app_policy)&&bundle.includes(fixedQaIdentity.application_identifier));
 assert(bundle.includes(profile.service_origin)&&bundle.includes(profile.browser_origin)&&bundle.includes(sourceSha));
 const config=await load('qualification/rendezvous/qa-worker-config.json');
 assert.equal(config.name,profile.service);assert.equal(config.main,'worker.mjs');assert.equal(config.no_bundle,true);
 assert.deepEqual(config.routes,[]);assert.equal(config.workers_dev,false);assert.equal(config.preview_urls,false);
 assert.deepEqual(config.durable_objects.bindings.map(x=>[x.name,x.class_name]),Object.entries(inputs.local_test_bindings));
 assert.deepEqual(Object.keys(config).sort(),['name','main','no_bundle','compatibility_date','compatibility_flags','workers_dev','preview_urls','routes','send_metrics','observability','durable_objects','migrations'].sort());
 for(const name of ['LICENSE','THIRD_PARTY_NOTICES.md','docs/rendezvous/THIRD_PARTY_LICENSES_V1.md','package.json','package-lock.json']){
  const to=name.includes('/')?'RENDEZVOUS_THIRD_PARTY_LICENSES.md':name;await copyFile(join(repo,name),join(output,to));pins[name]=hash(await readFile(join(repo,name)));
 }
 await writeFile(join(output,'worker.mjs'),bundle);await writeFile(join(output,'wrangler.json'),JSON.stringify(config,null,2)+'\n');
 const schemaPath='docs/rendezvous/wire-request-schemas-v1.json';
 const qaSchema=deriveFixedQaSource(schemaPath,await readFile(join(repo,schemaPath),'utf8'),profile.transforms[schemaPath]);
 await writeFile(join(output,'wire-request-schemas-qa.json'),qaSchema);
 await writeFile(join(output,'qa-origin-fixture.json'),JSON.stringify({kind:'FIXED_QA_ONLY_NOT_PRODUCT_OR_OPERATIONAL_ADMISSION',source_sha:sourceSha,service:profile.service,service_origin:profile.service_origin,browser_origin:profile.browser_origin,wire_schema_sha256:hash(qaSchema),worker_sha256:hash(bundle),activation_allowed:false,current_apple_profile:null,operational_admission:null},null,2)+'\n');
 // Qualify the exact isolated package with Wrangler's fixed dry-run command.
 // Never expose a deploy flag, account selector, route, secret or upload path.
 const dry=spawnSync(process.execPath,[join(repo,'node_modules/wrangler/bin/wrangler.js'),'deploy','--dry-run','--config',join(output,'wrangler.json'),'--outdir',join(output,'dry-run')],{cwd:output,encoding:'utf8',env:{...process.env,WRANGLER_SEND_METRICS:'false'}});
 await writeFile(join(output,'private-dry-run.log'),dry.stdout+dry.stderr,{mode:0o600});assert.equal(dry.status,0,'fixed Wrangler dry-run failed');
 assert.equal(hash(await readFile(join(output,'dry-run/worker.mjs'))),hash(bundle),'dry-run Worker differs');
 const verify=async()=>{
  assert.equal(await fixedGitIdentity(),sourceSha,'Git identity changed');
  for(const [name,pin]of Object.entries({...pins,...installed}))assert.equal(hash(await readFile(join(repo,name))),pin,'source/dependency drift');
  for(const [name,pin]of Object.entries(pins))verifyCommittedInput(sourceSha,name,pin);
 };
 await verify();
 const receipt={scope:profile.scope,source_sha:sourceSha,source_dirty:false,committed_graph_bytes_verified:true,git_environment_overrides_ignored:true,profile,activation_allowed:false,native_positive:false,operational_admission:null,derived_strict_types:'PASS_WITH_BOTH_OLD_POLICY_NEGATIVE_TYPE_CONTROLS',qa_verifier_identity:fixedQaIdentity,wrangler_dry_run:'PASS_EXACT_WORKER_BYTES',worker_sha256:hash(bundle),worker_bytes:Buffer.byteLength(bundle),config_sha256:hash(JSON.stringify(config,null,2)+'\n'),source_hashes:pins,installed_hashes:installed,transforms,graph:result.metafile};
 await writeFile(join(output,'build-evidence.json'),JSON.stringify(receipt,null,2)+'\n');
 return {output,bundle,receipt,config,verify};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))console.log(JSON.stringify({output:(await buildFixedQa()).output}));
