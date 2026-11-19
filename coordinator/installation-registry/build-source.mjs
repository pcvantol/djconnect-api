// Exact standalone transaction library plus separate closed Worker target. Never deploys.
import {readFile,mkdir,writeFile,realpath} from 'node:fs/promises';
import {resolve,dirname,basename,join,isAbsolute,relative,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';
import {unstable_readConfig} from 'wrangler';
const root=fileURLToPath(new URL('../../',import.meta.url)),dir=fileURLToPath(new URL('./',import.meta.url));
const out=process.argv[2];if(!out||!isAbsolute(out))throw Error('new absolute external scratch required');
const target=join(await realpath(dirname(resolve(out))),basename(resolve(out))),rootReal=await realpath(root);
const rel=relative(rootReal,target);if(rel===''||(!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep)))throw Error('output inside source repository');
const sha=b=>createHash('sha256').update(b).digest('hex');
const manifestBytes=await readFile(join(dir,'source-manifest.json')),manifest=JSON.parse(manifestBytes);
for(const [path,digest]of Object.entries(manifest.inputs_sha256))if(sha(await readFile(join(root,path)))!==digest)throw Error('source input drift: '+path);
if(JSON.parse(await readFile(join(root,'node_modules/esbuild/package.json'))).version!==manifest.esbuild_version)throw Error('esbuild drift');
if(JSON.parse(await readFile(join(root,'node_modules/wrangler/package.json'))).version!==manifest.wrangler_version)throw Error('Wrangler drift');
if(sha(await readFile(join(root,'node_modules/wrangler/config-schema.json')))!==manifest.wrangler_schema_sha256)throw Error('Wrangler schema drift');
const installed={};
for(const p of ['node_modules/esbuild/package.json','node_modules/esbuild/lib/main.js',`node_modules/@esbuild/${process.platform}-${process.arch}/bin/esbuild`,'node_modules/wrangler/package.json','node_modules/wrangler/config-schema.json'])installed[p]=sha(await readFile(join(root,p)));
await mkdir(target);
const library=await build({entryPoints:[join(dir,'registry.ts')],outfile:join(target,'registry.mjs'),bundle:true,metafile:true,platform:'browser',format:'esm',target:'es2024'});
const expected=['coordinator/installation-registry/registry.ts','coordinator/installation-principal/codec-data.ts','coordinator/installation-principal/schema-data.json','coordinator/principal-possession/possession-data.ts','src/surface-push/wire.ts'].sort();
if(JSON.stringify(Object.keys(library.metafile.inputs).sort())!==JSON.stringify(expected))throw Error('transaction library source graph drift');
await build({entryPoints:[join(dir,'qualification/fixtures.ts')],outfile:join(target,'fixture.mjs'),bundle:true,platform:'browser',format:'esm',target:'es2024'});
const worker=await build({entryPoints:[join(dir,'worker.ts')],outfile:join(target,'worker.mjs'),bundle:true,metafile:true,platform:'browser',format:'esm',target:'es2024',external:['cloudflare:workers']});
if(JSON.stringify(Object.keys(worker.metafile.inputs))!==JSON.stringify(['coordinator/installation-registry/worker.ts']))throw Error('closed Worker graph drift');
// This is a reviewable template, not a selected live namespace or deployed artifact.
const config={name:'djc-installation-registry-closed',main:'worker.mjs',compatibility_date:'2026-08-22',compatibility_flags:['nodejs_compat'],workers_dev:false,preview_urls:false,send_metrics:false,routes:[],
 durable_objects:{bindings:[{name:'INSTALLATION_REGISTRY',class_name:'InstallationRegistryObject'}]},migrations:[{tag:'installation-registry-v1',new_sqlite_classes:['InstallationRegistryObject']}]};
const configPath=join(target,'wrangler.closed.json');await writeFile(configPath,JSON.stringify(config,null,2)+'\n');
const parsed=unstable_readConfig({config:configPath});if(parsed.durable_objects.bindings.length!==1||parsed.migrations.length!==1||parsed.containers?.length)throw Error('unexpected closed Worker config');
await writeFile(join(target,'metafiles.json'),JSON.stringify({library:library.metafile,worker:worker.metafile},null,2)+'\n');
const proof={classification:'CLOSED_INSTALLATION_REGISTRY_SOURCE_ONLY',source_manifest_sha256:sha(manifestBytes),module_sha256:sha(await readFile(join(target,'registry.mjs'))),public_fixture_module_sha256:sha(await readFile(join(target,'fixture.mjs'))),worker_sha256:sha(await readFile(join(target,'worker.mjs'))),configuration_sha256:sha(await readFile(configPath)),library_inputs:expected,worker_inputs:Object.keys(worker.metafile.inputs),installed_inputs_sha256:installed,
 toolchain:{node:process.version,platform:process.platform,arch:process.arch,esbuild:manifest.esbuild_version,wrangler:manifest.wrangler_version},transaction_library_in_production_Worker:false,namespace_selected:false,production_factory:false,provisioned:false,deployed:false};
await writeFile(join(target,'source-package.json'),JSON.stringify(proof,null,2)+'\n');console.log(JSON.stringify(proof));
