// Offline Worker/DO source packaging. No cloud API, Container, image or deployment.
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,join,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';
import {unstable_readConfig} from 'wrangler';
const root=fileURLToPath(new URL('../../',import.meta.url));const dir=fileURLToPath(new URL('./',import.meta.url));
const out=process.argv[2];if(!out||!isAbsolute(out)||resolve(out).startsWith(resolve(root)))throw Error('external scratch path required');
const digest=b=>createHash('sha256').update(b).digest('hex');
const manifest=JSON.parse(await readFile(join(dir,'source-manifest.json'),'utf8'));
for(const [name,expected] of Object.entries(manifest.inputs_sha256))if(digest(await readFile(join(root,name)))!==expected)throw Error('source input drift: '+name);
if(digest(await readFile(join(root,'node_modules/wrangler/config-schema.json')))!==manifest.wrangler_schema_sha256)throw Error('Wrangler schema drift');
if(JSON.parse(await readFile(join(root,'node_modules/wrangler/package.json'),'utf8')).version!==manifest.wrangler_version)throw Error('Wrangler version drift');
await mkdir(out,{recursive:true});
const result=await build({entryPoints:[join(dir,'worker.ts')],outfile:join(out,'worker.mjs'),bundle:true,metafile:true,
  platform:'browser',format:'esm',target:'es2024',external:['cloudflare:workers']});
const config={name:'djc-worker-do-registry-source-only',main:'worker.mjs',compatibility_date:'2026-08-22',
  compatibility_flags:['nodejs_compat'],workers_dev:false,send_metrics:false,
  durable_objects:{bindings:[{name:'REGISTRY_DATA',class_name:'PrincipalRegistryData'}]},
  exports:{PrincipalRegistryData:{type:'durable-object',storage:'sqlite'}}};
const path=join(out,'wrangler.source.json');await writeFile(path,JSON.stringify(config,null,2)+'\n');
const parsed=unstable_readConfig({config:path});if(parsed.durable_objects.bindings.length!==1||parsed.containers?.length)throw Error('unexpected source configuration');
const inputs=Object.keys(result.metafile.inputs);if(inputs.some(p=>p.includes('coordinator/cloudflare')||p.includes('coordinator/src')))throw Error('unexpected coordinator dependency');
const proof={classification:'WORKER_DO_REGISTRY_SOURCE_DATA_ONLY',source_manifest_sha256:digest(await readFile(join(dir,'source-manifest.json'))),
  worker_sha256:digest(await readFile(join(out,'worker.mjs'))),configuration_sha256:digest(await readFile(path)),bundler_inputs:inputs,
  root_Worker_changed:false,production_registry_available:false,container:false,provisioned:false,deployed:false};
await writeFile(join(out,'source-package.json'),JSON.stringify(proof,null,2)+'\n');console.log(JSON.stringify(proof));
