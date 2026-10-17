// Isolated optional qualification; never installs, deploys, or calls Cloudflare.
import { mkdir, readFile, writeFile, symlink, realpath, stat } from 'node:fs/promises';
import { dirname, resolve, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { X509Certificate, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
async function main() {
  const repo = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const [dependencyArg, outputArg, privateArg] = process.argv.slice(2);
  if (!dependencyArg || !outputArg) throw new Error('usage');
  const deps = await realpath(resolve(dependencyArg));
  const output = join(await realpath(dirname(resolve(outputArg))), resolve(outputArg).split(sep).at(-1));
  const isolated = path => { if(path===repo || path.startsWith(repo+sep)) throw new Error('isolated_required'); };
  isolated(deps); isolated(output);
  const requireDeps = createRequire(join(deps,'package.json'));
  const versions = { pkijs:'3.4.1', asn1js:'3.1.0' };
  for(const [name,version] of Object.entries(versions)) if(requireDeps(name+'/package.json').version!==version) throw new Error('pin');
  await mkdir(output,{mode:0o700});
  if((await stat(output)).mode&0o077) throw new Error('private_directory');
  const put = (name,value) => writeFile(join(output,name),value,{mode:0o600,flag:'wx'});
  await symlink(join(repo,'node_modules'),join(output,'node_modules'),'dir');
  const root = new X509Certificate(await readFile(new URL('./apple-receipt-root.cer',import.meta.url)));
  const hash = value => createHash('sha256').update(value).digest('hex');
  if(hash(root.raw)!=='63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179') throw new Error('root');
  const fixture = {root:root.raw.toString('base64'),genuine:[]};
  const b64 = async (...parts) => (await readFile(join(...parts))).toString('base64');
  if(privateArg) {
    const dir=await realpath(resolve(privateArg));isolated(dir);if((await stat(dir)).mode&0o077)throw new Error('private_directory');
    const common={};for(const name of ['signer','intermediate','root'])common[name]=new X509Certificate(await readFile(join(dir,name+'.pem'))).raw;
    const times=JSON.parse(await readFile(join(dir,'binding-observations-public.json'),'utf8'));
    for(const role of ['signer','intermediate']){
      const time=times.find(v=>v.role===role);
      fixture.genuine.push({name:role,kind:'ocsp',response:await b64(dir,role+'-response.der'),cert:common[role].toString('base64'),issuer:common[role==='signer'?'intermediate':'root'].toString('base64'),thisUpdate:Date.parse(time.this_update),nextUpdate:Date.parse(time.next_update)});
    }
    fixture.genuine.push({name:'intermediate-crl',kind:'crl',response:(await readFile(new URL('./apple-root-g3-crl-sample.der',import.meta.url))).toString('base64'),cert:common.intermediate.toString('base64'),issuer:common.root.toString('base64'),thisUpdate:Date.parse('2026-08-25T00:08:08Z'),nextUpdate:Date.parse('2027-01-07T00:08:07Z')});
  }
  fixture.synthetic=JSON.parse(await readFile(new URL('./synthetic-status-v1.json',import.meta.url),'utf8')).cases;
  for(const f of fixture.genuine)f.referenceTime=f.kind==='ocsp'?f.thisUpdate+60000:Date.parse('2026-10-17T20:41:16Z');
  await put('fixtures.mjs','export default '+JSON.stringify(fixture)+';\n');
  const sources={};
  for(const name of ['receipt-status-candidate.mjs','receipt-status.check.mjs','receipt-status-client.mjs','receipt-status-client.check.mjs','run_status_workerd.mjs','build_synthetic_status.py']) {
    const source=await readFile(new URL('./'+name,import.meta.url)); sources[name]=hash(source); await put(name,source);
  }
  await put('worker.mjs',"export default {fetch(){return new Response('qualification only',{status:503})}};\n");
  await put('wrangler.jsonc',JSON.stringify({name:'djc-private-status-qualification',main:'worker.mjs',workers_dev:false,compatibility_date:'2026-06-20',compatibility_flags:['nodejs_compat'],send_metrics:false,observability:{enabled:false}}));
  const aliases={pkijs:join(deps,'node_modules/pkijs/build/index.es.js'),asn1js:join(deps,'node_modules/asn1js/build/index.es.js'),'djc-status-fixtures':join(output,'fixtures.mjs')};
  await put('vitest.config.mts',`import {defineConfig} from 'vitest/config';import {cloudflareTest} from '@cloudflare/vitest-pool-workers';export default defineConfig({resolve:{alias:${JSON.stringify(aliases)}},plugins:[cloudflareTest({wrangler:{configPath:'./wrangler.jsonc'}})],test:{include:['receipt-status.check.mjs','receipt-status-client.check.mjs'],testTimeout:20000}});\n`);
  const rr=createRequire(join(repo,'package.json'));
  const child=spawnSync(process.execPath,[join(dirname(rr.resolve('vitest/package.json')),'vitest.mjs'),'run','--config','vitest.config.mts','--reporter=json','--outputFile=results-private.json'],{cwd:output,encoding:'utf8',maxBuffer:8*1024*1024,env:{...process.env,WRANGLER_LOG_PATH:join(output,'wrangler.log'),CLOUDFLARE_SEND_METRICS:'false'}});
  await put('process-private.log',(child.stdout??'')+'\n'+(child.stderr??''));
  if(child.status!==0) throw new Error('failed');
  const result=JSON.parse(await readFile(join(output,'results-private.json'),'utf8'));
  if(!result.success||result.numFailedTests||result.numPendingTests) throw new Error('results');
  async function metadata(resolver, name, entry) {
    let directory = dirname(entry ?? resolver.resolve(name));
    while (true) {
      try { const path = join(directory, 'package.json'); const value = JSON.parse(await readFile(path,'utf8'));
        if (value.name === name) return { path, version: value.version };
      } catch { /* Walk to owning package. */ }
      const parent=dirname(directory); if(parent===directory) throw new Error('metadata'); directory=parent;
    }
  }
  const pool=await metadata(rr,'@cloudflare/vitest-pool-workers',fileURLToPath(import.meta.resolve('@cloudflare/vitest-pool-workers')));
  const miniflare=await metadata(createRequire(pool.path),'miniflare');
  const workerd=await metadata(createRequire(miniflare.path),'workerd');
  const publicInputs={};for(const name of ['apple-root-g3-crl-sample.der','apple-receipt-root.cer','synthetic-status-v1.json'])publicInputs[name]=hash(await readFile(new URL('./'+name,import.meta.url)));
  const summary={public_inputs_sha256:publicInputs,pool:pool.version,miniflare:miniflare.version,workerd:workerd.version,scope:'LOCAL_WORKERD_COMMON_CERT_STATUS_ONLY_NO_ENROLLMENT_GO',tests_passed:result.numPassedTests,genuine_status_inputs:fixture.genuine.length,synthetic_cases:fixture.synthetic.length,cases:result.testResults.flatMap(f=>f.assertionResults.map(t=>({name:t.fullName,status:t.status}))),node:process.version,libraries:versions,source_sha256:sources,compatibility_date:'2026-06-20',not_run:['production egress/operational cache/propagation','complete verifier/fresh enrollment','exact action wire/DO state/replay atomicity','production/HA/TV chain',...(privateArg?[]:['genuine private Apple fixtures'])]};
  await put('summary-sanitized.json',JSON.stringify(summary,null,2)+'\n');
  console.log('PASS: '+summary.tests_passed+' isolated workerd status cases; no enrollment GO.');
}
main().catch(()=>{console.error('Status qualification failed; diagnostics remain private.');process.exitCode=1;});
