// Public synthetic local DO qualification. No installation, private capture, deploy or cloud API calls.
import {mkdir,readFile,writeFile,symlink,realpath} from 'node:fs/promises';
import {dirname,resolve,join,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
let phase='prepare';
async function main(){
 const repo=resolve(fileURLToPath(new URL('../../',import.meta.url))),arg=process.argv[2];if(!arg)throw new Error('usage');
 const output=join(await realpath(dirname(resolve(arg))),resolve(arg).split(sep).at(-1));if(output===repo||output.startsWith(repo+sep))throw new Error('isolated_required');
 await mkdir(output,{mode:0o700});const put=(name,value)=>writeFile(join(output,name),value,{mode:0o600,flag:'wx'});await symlink(join(repo,'node_modules'),join(output,'node_modules'),'dir');
 const hash=value=>createHash('sha256').update(value).digest('hex'),sources={};
 for(const name of ['receipt-key-store.ts','receipt-store-harness.ts','receipt-key-store.check.ts','run_store_workerd.mjs']){const data=await readFile(new URL('./'+name,import.meta.url));sources[name]=hash(data);await put(name,data);}
 const helper=await readFile(join(repo,'src/crypto.ts'));sources['src/crypto.ts']=hash(helper);await put('existing-crypto.ts',helper);
 await put('wrangler.jsonc',JSON.stringify({name:'djc-local-receipt-store-qualification',main:'receipt-store-harness.ts',workers_dev:false,compatibility_date:'2026-06-20',compatibility_flags:['nodejs_compat'],send_metrics:false,observability:{enabled:false},durable_objects:{bindings:[{name:'RECEIPT_KEY_STORE',class_name:'ReceiptKeyStore'}]},migrations:[{tag:'local-qa-only-v1',new_sqlite_classes:['ReceiptKeyStore']}]}));
 await put('vitest.config.mts',`import {defineConfig} from 'vitest/config';import {cloudflareTest} from '@cloudflare/vitest-pool-workers';export default defineConfig({resolve:{alias:{'djc-existing-crypto':${JSON.stringify(join(output,'existing-crypto.ts'))}}},plugins:[cloudflareTest({wrangler:{configPath:'./wrangler.jsonc'}})],test:{include:['receipt-key-store.check.ts'],testTimeout:20000}});\n`);
 await put('tsconfig.json',JSON.stringify({compilerOptions:{target:'ES2022',module:'ESNext',moduleResolution:'Bundler',strict:true,skipLibCheck:true,lib:['ES2022'],types:[],paths:{'djc-existing-crypto':['./existing-crypto.ts']}},include:['receipt-key-store.ts','receipt-store-harness.ts','existing-crypto.ts',join(repo,'worker-configuration.d.ts')]}));
 const rr=createRequire(join(repo,'package.json')),logEnv={...process.env,WRANGLER_LOG_PATH:join(output,'wrangler.log'),CLOUDFLARE_SEND_METRICS:'false'};
 phase='types';const typed=spawnSync(process.execPath,[join(dirname(rr.resolve('typescript/package.json')),'bin/tsc'),'--noEmit','--project','tsconfig.json'],{cwd:output,encoding:'utf8',maxBuffer:2*1024*1024,env:logEnv});await put('types-private.log',(typed.stdout??'')+'\n'+(typed.stderr??''));if(typed.status!==0)throw new Error('types_failed');
 phase='tests';const child=spawnSync(process.execPath,[join(dirname(rr.resolve('vitest/package.json')),'vitest.mjs'),'run','--config','vitest.config.mts','--reporter=json','--outputFile=results-private.json'],{cwd:output,encoding:'utf8',maxBuffer:8*1024*1024,env:logEnv});await put('process-private.log',(child.stdout??'')+'\n'+(child.stderr??''));await put('process-state-private.json',JSON.stringify({status:child.status,signal:child.signal,errorCode:child.error?.code}));if(child.status!==0)throw new Error('test_failed');
 const result=JSON.parse(await readFile(join(output,'results-private.json'),'utf8'));if(!result.success||result.numFailedTests||result.numPendingTests)throw new Error('results');
 async function metadata(resolver,name,entry){let d=dirname(entry??resolver.resolve(name));while(true){try{const path=join(d,'package.json'),value=JSON.parse(await readFile(path,'utf8'));if(value.name===name)return{path,version:value.version};}catch{}const parent=dirname(d);if(parent===d)throw new Error('metadata');d=parent;}}
 phase='metadata';const pool=await metadata(rr,'@cloudflare/vitest-pool-workers',fileURLToPath(import.meta.resolve('@cloudflare/vitest-pool-workers'))),mf=await metadata(createRequire(pool.path),'miniflare'),wd=await metadata(createRequire(mf.path),'workerd');
 phase='summary';const summary={scope:'LOCAL_SQLITE_DO_ENCRYPTED_STORAGE_ONLY_NOT_ATTESTATION_STATUS_OR_PUBLIC_ADMISSION',tests_passed:result.numPassedTests,typecheck:'PASS',cases:result.testResults.flatMap(f=>f.assertionResults.map(t=>({name:t.fullName,status:t.status}))),source_sha256:sources,node:process.version,typescript:rr('typescript/package.json').version,pool:pool.version,miniflare:mf.version,workerd:wd.version,compatibility_date:'2026-06-20',not_run:['complete verifier/wire admission','revocation status policy','provider deployment/physical deletion/backups/cleanup monitoring','production/HA/iPhone/TV chain']};await put('summary-sanitized.json',JSON.stringify(summary,null,2)+'\n');console.log('PASS: '+summary.tests_passed+' local SQLite DO cases and isolated types; no public admission GO.');
}
main().catch(()=>{console.error('Storage qualification failed at '+phase+'; diagnostics remain local.');process.exitCode=1;});
