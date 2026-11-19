// Isolated public synthetic structural qualification. Installs/deploys nothing.
import {mkdir,readFile,writeFile,symlink,realpath} from 'node:fs/promises';
import {dirname,resolve,join,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {loadPinnedJose,encryptVector,parseVectorInput} from './generate_destination_vector.mjs';
let phase='prepare';
async function main(){
 const repo=resolve(fileURLToPath(new URL('../../',import.meta.url))),[dependencyArg,outputArg]=process.argv.slice(2);if(!dependencyArg||!outputArg)throw new Error('usage');
 const output=join(await realpath(dirname(resolve(outputArg))),resolve(outputArg).split(sep).at(-1));if(output===repo||output.startsWith(repo+sep))throw new Error('isolated_required');
 await mkdir(output,{mode:0o700});const put=(name,value)=>writeFile(join(output,name),value,{mode:0o600,flag:'wx'});await symlink(join(repo,'node_modules'),join(output,'node_modules'),'dir');
 const hash=value=>createHash('sha256').update(value).digest('hex'),sources={};
 for(const name of ['jwe-framing.ts','jwe-framing.check.mjs','jwe-framing-harness.ts','run_framing_workerd.mjs','generate_destination_vector.mjs','jwe-dependency-provenance-v1.json']){const bytes=await readFile(new URL('./'+name,import.meta.url));sources[name]=hash(bytes);await put(name,bytes);}
 phase='synthetic-oracle';const jose=await loadPinnedJose(dependencyArg),pair=generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
 const {kty,e,n}=pair.publicKey.export({format:'jwk'}),jwk={kty,e,n},thumbprint=await jose.calculateJwkThumbprint(jwk,'sha256');
 assert.equal(thumbprint,createHash('sha256').update(JSON.stringify({e,kty,n})).digest('base64url'));
 const plaintext={v:'djc-rendezvous/1',transaction_id:'dd11aa22-3344-4556-8abc-0123456789ab',generation:3,browser_key_thumbprint:thumbprint,expires_at:1,bootstrap_origin:'https://vibecast.tv',display_entry_url:'https://ha.example.org/djconnect/vibecast/display',issuer_epoch:Buffer.alloc(32).toString('base64url')};
 // Stale synthetic expiry is deliberate: framing alone cannot enforce plaintext expiry.
 const envelope=await encryptVector(parseVectorInput(Buffer.from(JSON.stringify({jwk,thumbprint,plaintext}))),jose);
 assert.deepEqual(Buffer.from((await jose.compactDecrypt(envelope,pair.privateKey)).plaintext),Buffer.from(JSON.stringify(plaintext)));
 const altered=envelope.split('.'),tag=Buffer.from(altered[4],'base64url');tag[0]^=1;altered[4]=tag.toString('base64url');await assert.rejects(()=>jose.compactDecrypt(altered.join('.'),pair.privateKey));
 await put('public-envelope.json',JSON.stringify({jwk,thumbprint,envelope,digest:createHash('sha256').update(envelope,'ascii').digest('base64url'),plaintextBytes:Buffer.byteLength(JSON.stringify(plaintext))}));
 await put('wrangler.jsonc',JSON.stringify({name:'djc-local-jwe-framing-qualification',main:'jwe-framing-harness.ts',workers_dev:false,compatibility_date:'2026-06-20',compatibility_flags:['nodejs_compat'],send_metrics:false,observability:{enabled:false}}));
 await put('deny-egress.mjs',"globalThis.fetch=async()=>{throw new Error('qualification_egress_disabled');};\n");
 await put('vitest.config.mts',"import {defineConfig} from 'vitest/config';import {cloudflareTest} from '@cloudflare/vitest-pool-workers';export default defineConfig({plugins:[cloudflareTest({wrangler:{configPath:'./wrangler.jsonc'}})],test:{setupFiles:['./deny-egress.mjs'],include:['jwe-framing.check.mjs'],testTimeout:20000}});\n");
 await put('tsconfig.json',JSON.stringify({compilerOptions:{target:'ES2022',module:'ESNext',moduleResolution:'Bundler',strict:true,skipLibCheck:true,lib:['ES2022'],types:[]},include:['jwe-framing.ts','jwe-framing-harness.ts',join(repo,'worker-configuration.d.ts')]}));
 const rr=createRequire(join(repo,'package.json')),logEnv={...process.env,WRANGLER_LOG_PATH:join(output,'wrangler.log'),CLOUDFLARE_SEND_METRICS:'false'};
 phase='types';const typed=spawnSync(process.execPath,[join(dirname(rr.resolve('typescript/package.json')),'bin/tsc'),'--noEmit','--project','tsconfig.json'],{cwd:output,encoding:'utf8',maxBuffer:2*1024*1024,env:logEnv});await put('types-private.log',(typed.stdout??'')+'\n'+(typed.stderr??''));if(typed.status!==0)throw new Error('types_failed');
 phase='tests';const child=spawnSync(process.execPath,[join(dirname(rr.resolve('vitest/package.json')),'vitest.mjs'),'run','--config','vitest.config.mts','--reporter=json','--outputFile=results-private.json'],{cwd:output,encoding:'utf8',maxBuffer:8*1024*1024,env:logEnv});await put('process-private.log',(child.stdout??'')+'\n'+(child.stderr??''));if(child.status!==0)throw new Error('test_failed');
 const result=JSON.parse(await readFile(join(output,'results-private.json'),'utf8'));if(!result.success||result.numFailedTests||result.numPendingTests)throw new Error('results');
 async function metadata(resolver,name,entry){let d=dirname(entry??resolver.resolve(name));while(true){try{const p=join(d,'package.json'),v=JSON.parse(await readFile(p,'utf8'));if(v.name===name)return {path:p,version:v.version};}catch{}const parent=dirname(d);if(parent===d)throw new Error('metadata');d=parent;}}
 phase='metadata';const pool=await metadata(rr,'@cloudflare/vitest-pool-workers',fileURLToPath(import.meta.resolve('@cloudflare/vitest-pool-workers'))),mf=await metadata(createRequire(pool.path),'miniflare'),wd=await metadata(createRequire(mf.path),'workerd');
 const summary={scope:'LOCAL_JWE_FRAMING_PUBLIC_JWK_ONLY_NOT_AEAD_SENDER_PLAINTEXT_OR_RUNTIME_GO',tests_passed:result.numPassedTests,typecheck:'PASS',jose:'6.2.12',node:process.version,typescript:rr('typescript/package.json').version,pool:pool.version,miniflare:mf.version,workerd:wd.version,compatibility_date:'2026-06-20',source_sha256:sources,oracle:'pinned generator; JOSE decrypt matches public synthetic plaintext; altered tag rejected by JOSE, deliberately framing-accepted',private_material:'ephemeral software RSA private key process-memory only; never exported or persisted',cases:result.testResults.flatMap(f=>f.assertionResults.map(t=>({name:t.fullName,status:t.status}))),not_run:['public HTTP JSON/Origin/payload/admission validation','transaction DO and real coordinator composition','fresh native enrollment/action binding','destination plaintext/expiry/HA reachability','provider deployment and HA/iPhone/TV chain']};await put('summary-sanitized.json',JSON.stringify(summary,null,2)+'\n');console.log('PASS: '+summary.tests_passed+' actual local workerd structural cases and isolated TypeScript; no AEAD or service GO.');
}
main().catch(()=>{console.error('Framing qualification failed at '+phase+'; diagnostics remain local.');process.exitCode=1;});
