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
  const versions = { cbor:'10.0.12', pkijs:'3.4.1', asn1js:'3.1.0' };
  for(const [name,version] of Object.entries(versions)) if(requireDeps(name+'/package.json').version!==version) throw new Error('pin');
  await mkdir(output,{mode:0o700});
  if((await stat(output)).mode&0o077) throw new Error('private_directory');
  const put = (name,value) => writeFile(join(output,name),value,{mode:0o600,flag:'wx'});
  await symlink(join(repo,'node_modules'),join(output,'node_modules'),'dir');
  const root = new X509Certificate(await readFile(new URL('./apple-attestation-root.pem',import.meta.url)));
  const hash = value => createHash('sha256').update(value).digest('hex');
  if(hash(root.raw)!=='1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932') throw new Error('root');
  const fixture = {root:root.raw.toString('base64'),genuine:[]};
  const b64 = async (...parts) => (await readFile(join(...parts))).toString('base64');
  if(privateArg) {
    const directory=await realpath(resolve(privateArg)); isolated(directory);
    if((await stat(directory)).mode&0o077) throw new Error('fixture_privacy');
    const first=join(directory,'device-evidence'), second=join(directory,'reuse-evidence'), boundary=join(directory,'input-evidence');
    const state=JSON.parse(await readFile(join(first,'state.json'),'utf8'));
    const cbor=requireDeps('cbor');
    for(const name of ['active','replacement']) {
      const attestation=await b64(first,name+'-attestation.cbor');
      const object=cbor.decodeFirstSync(Buffer.from(attestation,'base64'),{preferMap:true,preventDuplicateKeys:true});
      const cert=new X509Certificate(object.get('attStmt').get('x5c')[0]);
      const jwk=cert.publicKey.export({format:'jwk'});
      const point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]).toString('base64');
      const value={name,attestation,input:await b64(first,name+'-attestation-input.bin'),credential:state[name],point,assertions:[]};
      for(let counter=1;counter<=4;counter++) {
        const dir=counter<=2?first:second;
        value.assertions.push({counter,proof:await b64(dir,`${name}-assert-${counter}.cbor`),input:await b64(dir,`${name}-assert-${counter}-input.bin`)});
      }
      if(name==='active') value.assertions.push({counter:6,proof:await b64(boundary,'active-assert-5.cbor'),input:await b64(boundary,'active-assert-5-input.bin')});
      fixture.genuine.push(value);
    }
    fixture.boundary={proof:await b64(boundary,'unexpected-hash-31.cbor')};
  }
  await put('fixtures.mjs','export default '+JSON.stringify(fixture)+';\n');
  const sources={};
  for(const name of ['app-attest-core-candidate.mjs','app-attest-core.check.mjs','worker-path-candidate.mjs','run_core_workerd.mjs']) {
    const source=await readFile(new URL('./'+name,import.meta.url)); sources[name]=hash(source); await put(name,source);
  }
  await put('worker.mjs',"export default {fetch(){return new Response('qualification only',{status:503})}};\n");
  await put('wrangler.jsonc',JSON.stringify({name:'djc-private-core-qualification',main:'worker.mjs',workers_dev:false,compatibility_date:'2026-06-20',compatibility_flags:['nodejs_compat'],send_metrics:false,observability:{enabled:false}}));
  const aliases={pkijs:join(deps,'node_modules/pkijs/build/index.es.js'),asn1js:join(deps,'node_modules/asn1js/build/index.es.js'),cbor:requireDeps.resolve('cbor'),'djc-core-fixtures':join(output,'fixtures.mjs')};
  await put('vitest.config.mts',`import {defineConfig} from 'vitest/config';import {cloudflareTest} from '@cloudflare/vitest-pool-workers';export default defineConfig({resolve:{alias:${JSON.stringify(aliases)}},plugins:[cloudflareTest({wrangler:{configPath:'./wrangler.jsonc'}})],test:{include:['app-attest-core.check.mjs'],testTimeout:20000}});\n`);
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
  const summary={pool:pool.version,miniflare:miniflare.version,workerd:workerd.version,scope:'LOCAL_WORKERD_APP_ATTEST_CORE_ONLY_RECEIPT_UNVERIFIED_NO_RUNTIME_GO',tests_passed:result.numPassedTests,genuine_attestations:fixture.genuine.length,genuine_assertions:fixture.genuine.reduce((n,v)=>n+v.assertions.length,0),cases:result.testResults.flatMap(f=>f.assertionResults.map(t=>({name:t.fullName,status:t.status}))),node:process.version,libraries:versions,source_sha256:sources,compatibility_date:'2026-06-20',not_run:['receipt CMS/fresh enrollment','revocation availability','exact action wire/DO state/replay atomicity','production/HA/TV chain',...(privateArg?[]:['genuine private Apple fixtures'])]};
  await put('summary-sanitized.json',JSON.stringify(summary,null,2)+'\n');
  console.log('PASS: '+summary.tests_passed+' isolated workerd core cases; receipt UNVERIFIED, no runtime GO.');
}
main().catch(()=>{console.error('Core qualification failed; diagnostics remain private.');process.exitCode=1;});
