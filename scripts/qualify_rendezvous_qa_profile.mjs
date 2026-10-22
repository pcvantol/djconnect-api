// Isolated software qualification of the exact QA derivative. No native/provider admission.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,mkdtemp,symlink} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {spawnSync} from 'node:child_process';
import {repo,hash,deriveFixedQaSource,fixedQaIdentity} from './build_rendezvous_qa.mjs';
const [deps,outputArg,jose]=process.argv.slice(2);assert(deps&&outputArg&&jose&&process.argv.length===5);
const output=resolve(outputArg);await mkdir(output,{recursive:false,mode:0o700});
const root=await mkdtemp(join(output,'derived-source-'));await symlink(join(repo,'node_modules'),join(root,'node_modules'),'dir');
const profile=JSON.parse(await readFile(join(repo,'qualification/rendezvous/qa-build-profile.json'),'utf8'));
assert.deepEqual(profile.qa_verifier_identity,fixedQaIdentity);assert.equal(profile.activation_allowed,false);assert.equal(profile.current_apple_profile,null);assert.equal(profile.operational_admission,null);
const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.startsWith('GIT_')));
const listed=spawnSync('git',['--no-replace-objects','ls-files','qualification/rendezvous','docs/rendezvous/wire-request-schemas-v1.json','docs/rendezvous/wire-schema-cases-v1.json','docs/rendezvous/capacity-browser-traces-v1.json','src/crypto.ts','worker-configuration.d.ts'],{cwd:repo,env,encoding:'utf8'});assert.equal(listed.status,0);
const maps={};
const fixtureReplacements={'ios-dev-qualification/1':fixedQaIdentity.app_policy,'ZEML4LPXH4.dev.djconnect.ios':fixedQaIdentity.application_identifier,'https://api.djconnect.dev':profile.service_origin,'https://vibecast.tv':profile.browser_origin,"'40230'":"'40408'"};
// Unchanged runtime files are copied exactly. ONLY explicit tests/harnesses/runners
// and their public fixtures receive QA inputs; those are never product imports.
const fixturePath=name=>/\.check\.|-harness\.|\/run_|\/generate_destination_vector\.mjs$|\/pre-qr-replacement-reference\.ts$|\/wire-schema-cases-v1\.json$|\/capacity-browser-traces-v1\.json$/.test(name);
for(const name of listed.stdout.trim().split('\n')){
 let source=await readFile(join(repo,name));let contents=source;
 if(Object.hasOwn(profile.transforms,name))contents=Buffer.from(deriveFixedQaSource(name,source.toString(),profile.transforms[name]));
 else if(fixturePath(name)&&!name.endsWith('/qa-profile.check.mjs')){let text=source.toString();for(const [from,to]of Object.entries(fixtureReplacements))text=text.replaceAll(from,to);contents=Buffer.from(text);}
 const path=join(root,name);await mkdir(dirname(path),{recursive:true});await writeFile(path,contents);
 maps[name]={source_sha256:hash(source),derived_sha256:hash(contents),kind:Object.hasOwn(profile.transforms,name)?'PINNED_QA_RUNTIME_OR_DECLARATION':fixturePath(name)?'PUBLIC_SOFTWARE_TEST_INPUT':'UNCHANGED'};
}
// Production modules are distinct unchanged controls, never a QA trust/root override.
for(const name of ['app-attest-core-candidate.mjs','receipt-cms-candidate.mjs'])await writeFile(join(root,'qualification/rendezvous',name.replace('.mjs','.production.mjs')),await readFile(join(repo,'qualification/rendezvous',name)));
const runner=join(root,'qualification/rendezvous/run_shared_key_workerd.mjs');let text=await readFile(runner,'utf8');
const stageNeedle="for(const name of ['retry-hint.ts'";assert.equal(text.split(stageNeedle).length,2);
text=text.replace(stageNeedle,"for(const name of ['qa-profile.check.mjs','qa-profile-cms-fixtures.json','app-attest-core-candidate.production.mjs','receipt-cms-candidate.production.mjs','retry-hint.ts'");
const includeNeedle="include:['shared-key.check.mjs'";assert.equal(text.split(includeNeedle).length,2);text=text.replace(includeNeedle,"include:['qa-profile.check.mjs','shared-key.check.mjs'");await writeFile(runner,text);
const run=spawnSync(process.execPath,[runner,resolve(deps),join(output,'workerd'),resolve(jose)],{cwd:root,env:{...process.env,WRANGLER_LOG_PATH:join(output,'wrangler.log')},encoding:'utf8',maxBuffer:32*1024*1024});await writeFile(join(output,'runner.log'),run.stdout+run.stderr,{mode:0o600});
await writeFile(join(output,'derivation-map.json'),JSON.stringify({scope:'ACTUAL_QA_DERIVED_SOFTWARE_GRAPH_NOT_NATIVE',identity:fixedQaIdentity,source_maps:maps,runner_test_inclusion_sha256:hash(text)},null,2)+'\n');
assert.equal(run.status,0,'derived QA shared workerd qualification failed; inspect runner.log');
const summary=JSON.parse(await readFile(join(output,'workerd/summary-sanitized.json'),'utf8'));assert.equal(summary.typecheck,'PASS');
const evidence={scope:'ACTUAL_FIXED_QA_DERIVATIVE_SOFTWARE_ONLY_NOT_NATIVE',result:'PASS',identity:fixedQaIdentity,tests_passed:summary.tests_passed,strict_types:summary.typecheck,qa_profile_cases:summary.cases.filter(t=>t.name.startsWith('QA profile ')),derivation_map_sha256:hash(await readFile(join(output,'derivation-map.json'))),activation_allowed:false,native_positive:false};
assert(evidence.qa_profile_cases.length>=20);assert(evidence.qa_profile_cases.every(t=>t.status==='passed'));await writeFile(join(output,'qa-profile-evidence.json'),JSON.stringify(evidence,null,2)+'\n');console.log(JSON.stringify({output,...evidence}));
