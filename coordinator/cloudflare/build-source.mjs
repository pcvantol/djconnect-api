// Offline source packaging only. Never invokes Docker, Wrangler deploy or a cloud API.
import {build} from 'esbuild';
import {readFile,mkdir,writeFile,copyFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve,join,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {unstable_readConfig} from 'wrangler';
const root=fileURLToPath(new URL('../../',import.meta.url));
const dir=fileURLToPath(new URL('./',import.meta.url));
const out=process.argv[2];
if(!out || !isAbsolute(out) || resolve(out).startsWith(resolve(root)))throw Error('explicit scratch directory outside source tree required');
const inputs=JSON.parse(await readFile(join(dir,'inputs.json'),'utf8'));
const sha=b=>createHash('sha256').update(b).digest('hex');
const manifest=JSON.parse(await readFile(join(dir,'source-manifest.json'),'utf8'));
if(manifest.classification!==inputs.classification)throw Error('source classification mismatch');
for(const [path,digest] of Object.entries(manifest.inputs_sha256)) {
  if(sha(await readFile(join(root,path)))!==digest)throw Error(`source manifest drift: ${path}`);
}
for(const [path,digest] of [['package-lock.json',inputs.package_lock_sha256],['node_modules/wrangler/config-schema.json',inputs.wrangler_schema_sha256]]) {
  if(sha(await readFile(join(root,path)))!==digest)throw Error(`source input drift: ${path}`);
}
const installed=JSON.parse(await readFile(join(root,'node_modules/wrangler/package.json'),'utf8'));
if(installed.version!==inputs.wrangler_version)throw Error('Wrangler version drift');
await mkdir(out,{recursive:true});
await build({entryPoints:[join(dir,'qualification/worker.ts')],outfile:join(out,'source-worker.mjs'),
  bundle:true,platform:'browser',format:'esm',target:'es2024',external:['cloudflare:workers']});
await build({entryPoints:[join(dir,'container-entry.ts')],outfile:join(out,'source-container.mjs'),
  bundle:true,platform:'node',format:'esm',target:'node26'});
await copyFile(join(dir,'Dockerfile'),join(out,'Dockerfile'));
// Real installed Wrangler schema/parser, but this source config is NOT a release manifest.
const config={name:'djc-coordinator-source-only',main:'source-worker.mjs',compatibility_date:'2026-08-22',
  compatibility_flags:['nodejs_compat'],workers_dev:false,
  durable_objects:{bindings:[{name:'SOURCE_STATE',class_name:'CoordinatorSourceState'}]},
  containers:[{name:'source-coordinator',class_name:'CoordinatorSourceState',scheduling_policy:'durable_object',
    images:{source:{dockerfile:'Dockerfile'}}}],
  exports:{CoordinatorSourceState:{type:'durable-object',storage:'sqlite',container:'source-coordinator'}}};
const configPath=join(out,'wrangler.source.json');await writeFile(configPath,JSON.stringify(config,null,2)+'\n');
const parsed=unstable_readConfig({config:configPath});
if(parsed.containers.length!==1 || parsed.containers[0].scheduling_policy!=='durable_object')throw Error('Container config parse mismatch');
const files={};for(const file of ['source-worker.mjs','source-container.mjs','Dockerfile','wrangler.source.json'])files[file]=sha(await readFile(join(out,file)));
await writeFile(join(out,'source-package.json'),JSON.stringify({classification:inputs.classification,
  files,base_manifest:inputs.linux_amd64_base_manifest_digest,application_image_digest:null,
  docker_built:false,cloudflare_container_started:false,production_deployable:false},null,2)+'\n');
console.log(JSON.stringify({classification:inputs.classification,files,application_image_digest:null,production_deployable:false}));
