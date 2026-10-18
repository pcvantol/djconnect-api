// Local-only orchestration qualification. No install, Cloudflare write or new device data.
import {mkdir,readFile,writeFile,symlink,realpath,stat} from 'node:fs/promises';
import {dirname,resolve,join,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {X509Certificate,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
let phase='prepare';
async function main(){
  const repo=resolve(fileURLToPath(new URL('../../',import.meta.url)));
  const [dependencyArg,outputArg,privateArg]=process.argv.slice(2);if(!dependencyArg||!outputArg)throw new Error('usage');
  const isolated=p=>{if(p===repo||p.startsWith(repo+sep))throw new Error('isolated_required');};
  const deps=await realpath(resolve(dependencyArg)),output=join(await realpath(dirname(resolve(outputArg))),resolve(outputArg).split(sep).at(-1));isolated(deps);isolated(output);
  const rd=createRequire(join(deps,'package.json')),versions={cbor:'10.0.12',pkijs:'3.4.1',asn1js:'3.1.0'};
  for(const [name,version] of Object.entries(versions))if(rd(name+'/package.json').version!==version)throw new Error('pin');
  await mkdir(output,{mode:0o700});if((await stat(output)).mode&0o077)throw new Error('private_directory');
  const put=(name,data)=>writeFile(join(output,name),data,{mode:0o600,flag:'wx'}),hash=b=>createHash('sha256').update(b).digest('hex');
  await symlink(join(repo,'node_modules'),join(output,'node_modules'),'dir');
  const roots={};for(const [name,file,pin] of [
    ['attestation','apple-attestation-root.pem','1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932'],
    ['receipt','apple-receipt-root.cer','63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179'],
  ]){const root=new X509Certificate(await readFile(new URL('./'+file,import.meta.url))).raw;if(hash(root)!==pin)throw new Error('root');roots[name]=root;}
  await put('trust.mjs',Object.entries(roots).map(([name,b])=>`export const ${name}Root=Uint8Array.from(atob('${b.toString('base64')}'),c=>c.charCodeAt(0));`).join('\n'));
  const fixture={genuine:[]};
  if(privateArg){
    const dir=await realpath(resolve(privateArg));isolated(dir);if((await stat(dir)).mode&0o077)throw new Error('private_fixture_directory');
    const first=join(dir,'device-evidence'),state=JSON.parse(await readFile(join(first,'state.json'),'utf8')),cbor=rd('cbor'),pki=rd('pkijs'),asn=rd('asn1js');
    for(const name of ['active','replacement']){
      const attestation=await readFile(join(first,name+'-attestation.cbor')),object=cbor.decodeFirstSync(attestation,{preferMap:true,preventDuplicateKeys:true}),statement=object.get('attStmt'),chain=statement.get('x5c'),receipt=statement.get('receipt');
      const outer=new pki.ContentInfo({schema:asn.fromBER(receipt,{parseEmbedded:false}).result}),sd=new pki.SignedData({schema:outer.content});
      fixture.genuine.push({name,credential:state[name],attestation:attestation.toString('base64'),input:(await readFile(join(first,name+'-attestation-input.bin'))).toString('base64'),leaf:chain[0].toString('base64'),receipt:receipt.toString('base64'),pathExpiresAt:Math.min(...[...chain,roots.attestation].map(b=>new X509Certificate(b).validToDate.getTime())),cmsExpiresAt:Math.min(...sd.certificates.map(c=>c.notAfter.value.getTime()))});
    }
  }
  await put('fixtures.mjs','export default '+JSON.stringify(fixture)+';\n');
  const sources={};for(const name of ['enrollment-evidence-candidate.mjs','enrollment-evidence-candidate.d.mts','enrollment-evidence.check.mjs','app-attest-core-candidate.mjs','receipt-cms-candidate.mjs','worker-path-candidate.mjs','receipt-status-candidate.mjs','receipt-status-client.mjs','run_enrollment_workerd.mjs']){const data=await readFile(new URL('./'+name,import.meta.url));sources[name]=hash(data);await put(name,data);}
  await put('worker.mjs',"export default {fetch(){return new Response('qualification only',{status:503,headers:{'cache-control':'no-store'}})}};\n");
  await put('wrangler.jsonc',JSON.stringify({name:'djc-local-enrollment-evidence-qualification',main:'worker.mjs',workers_dev:false,compatibility_date:'2026-06-20',compatibility_flags:['nodejs_compat'],send_metrics:false,observability:{enabled:false}}));
  const aliases={'djc-enrollment-trust':join(output,'trust.mjs'),'djc-enrollment-fixtures':join(output,'fixtures.mjs'),cbor:rd.resolve('cbor'),pkijs:join(deps,'node_modules/pkijs/build/index.es.js'),asn1js:join(deps,'node_modules/asn1js/build/index.es.js')};
  await put('vitest.config.mts',`import {defineConfig} from 'vitest/config';import {cloudflareTest} from '@cloudflare/vitest-pool-workers';export default defineConfig({resolve:{alias:${JSON.stringify(aliases)}},plugins:[cloudflareTest({wrangler:{configPath:'./wrangler.jsonc'}})],test:{include:['enrollment-evidence.check.mjs'],testTimeout:20000}});\n`);
  await put('contract-types.check.ts',`import {createEnrollmentEvidenceVerifier,type SavedEnrollmentState,type EnrollmentVerifier} from './enrollment-evidence-candidate.mjs';declare const state:SavedEnrollmentState;const verifier:EnrollmentVerifier=createEnrollmentEvidenceVerifier(()=>state);async function privateUse(){const result=await verifier.verify({keyId:state.challenge.keyId,challengeId:state.challenge.id,attestation:new Uint8Array([1])});if(result.ok){const deadline:number=result.evidence.validUntil;const receipt:Uint8Array=result.evidence.initialReceipt;return {deadline,receipt};}}\n`);
  await put('tsconfig.json',JSON.stringify({compilerOptions:{target:'ES2022',module:'ESNext',moduleResolution:'Bundler',strict:true,skipLibCheck:true,lib:['ES2022'],types:[]},include:['contract-types.check.ts','enrollment-evidence-candidate.d.mts']}));
  const rr=createRequire(join(repo,'package.json')),env={...process.env,WRANGLER_LOG_PATH:join(output,'wrangler.log'),CLOUDFLARE_SEND_METRICS:'false'};
  phase='types';const types=spawnSync(process.execPath,[join(dirname(rr.resolve('typescript/package.json')),'bin/tsc'),'--noEmit','--project','tsconfig.json'],{cwd:output,encoding:'utf8',maxBuffer:2*1024*1024,env});await put('types-private.log',(types.stdout??'')+'\n'+(types.stderr??''));if(types.status!==0)throw new Error('types_failed');
  phase='tests';const child=spawnSync(process.execPath,[join(dirname(rr.resolve('vitest/package.json')),'vitest.mjs'),'run','--config','vitest.config.mts','--reporter=json','--outputFile=results-private.json'],{cwd:output,encoding:'utf8',maxBuffer:8*1024*1024,env});await put('process-private.log',(child.stdout??'')+'\n'+(child.stderr??''));await put('process-state-private.json',JSON.stringify({status:child.status,signal:child.signal,errorCode:child.error?.code}));if(child.status!==0)throw new Error('test_failed');
  const results=JSON.parse(await readFile(join(output,'results-private.json'),'utf8'));if(!results.success||results.numFailedTests||results.numPendingTests)throw new Error('results');
  async function metadata(resolver,name,entry){let d=dirname(entry??resolver.resolve(name));while(true){try{const p=join(d,'package.json'),v=JSON.parse(await readFile(p,'utf8'));if(v.name===name)return {path:p,version:v.version};}catch{}const parent=dirname(d);if(parent===d)throw new Error('metadata');d=parent;}}
  phase='metadata';const pool=await metadata(rr,'@cloudflare/vitest-pool-workers',fileURLToPath(import.meta.resolve('@cloudflare/vitest-pool-workers'))),miniflare=await metadata(createRequire(pool.path),'miniflare'),workerd=await metadata(createRequire(miniflare.path),'workerd');
  const summary={scope:'LOCAL_ENROLLMENT_EVIDENCE_COMPOSITION_NO_ATOMIC_REGISTRATION_OR_RUNTIME_GO',tests_passed:results.numPassedTests,type_contract_check:'PASS_DECLARATION_CONSUMER_NOT_JS_IMPLEMENTATION_TYPECHECK',genuine_archived_inputs:fixture.genuine.length,source_sha256:sources,trust_sha256:Object.fromEntries(Object.entries(roots).map(([k,v])=>[k,hash(v)])),node:process.version,libraries:versions,pool:pool.version,miniflare:miniflare.version,workerd:workerd.version,compatibility_date:'2026-06-20',cases:results.testResults.flatMap(f=>f.assertionResults.map(t=>({name:t.fullName,status:t.status}))),not_run:['fresh genuine composed enrollment positive','actual signed-iOS nonce32 enrollment integration','atomic challenge consumption/encrypted registration commit','hardened private RPC/global admission','live provider egress/cache/policy propagation','actual signed-iOS actions/HA/TV chain','production deployment',...(privateArg?[]:['private genuine archived inputs'])]};
  await put('summary-sanitized.json',JSON.stringify(summary,null,2)+'\n');console.log('PASS: '+summary.tests_passed+' local evidence cases and declaration consumer; no enrollment/runtime GO.');
}
main().catch(()=>{console.error('Enrollment qualification failed at '+phase+'; diagnostics remain private.');process.exitCode=1;});
