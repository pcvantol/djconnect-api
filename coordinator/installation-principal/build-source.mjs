// New external scratch only; no Worker configuration, cloud API or deployment.
import {readFile,mkdir,writeFile,realpath} from 'node:fs/promises';
import {resolve,dirname,basename,join,isAbsolute,relative,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';
const root=fileURLToPath(new URL('../../',import.meta.url)),dir=fileURLToPath(new URL('./',import.meta.url));
const out=process.argv[2];if(!out||!isAbsolute(out))throw Error('new absolute external scratch path required');
const requested=resolve(out),rootReal=await realpath(root),parent=await realpath(dirname(requested)),target=join(parent,basename(requested));
const rel=relative(rootReal,target);if(rel===''||(!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep)))throw Error('output inside source repository');
const sha=b=>createHash('sha256').update(b).digest('hex');
const manifestBytes=await readFile(join(dir,'source-manifest.json')),manifest=JSON.parse(manifestBytes);
for(const [name,digest] of Object.entries(manifest.inputs_sha256))if(sha(await readFile(join(root,name)))!==digest)throw Error('source input drift: '+name);
const esbuildPackage=await readFile(join(root,'node_modules/esbuild/package.json'));
if(JSON.parse(esbuildPackage).version!==manifest.esbuild_version)throw Error('esbuild version drift');
const binary=join(root,`node_modules/@esbuild/${process.platform}-${process.arch}/bin/esbuild`);
const installed={};
for(const path of [join(root,'node_modules/esbuild/package.json'),join(root,'node_modules/esbuild/lib/main.js'),binary])installed[relative(root,path)]=sha(await readFile(path));
await mkdir(target); // EEXIST preserves earlier evidence, including symlink targets.
const result=await build({entryPoints:[join(dir,'codec-data.ts')],outfile:join(target,'codec-data.mjs'),
  bundle:true,metafile:true,platform:'browser',format:'esm',target:'es2024'});
const inputs=Object.keys(result.metafile.inputs).sort();
if(JSON.stringify(inputs)!==JSON.stringify(['coordinator/installation-principal/codec-data.ts','coordinator/installation-principal/schema-data.json','src/surface-push/wire.ts']))throw Error('unexpected source graph');
await writeFile(join(target,'metafile.json'),JSON.stringify(result.metafile,null,2)+'\n');
for(const [output,input] of [['design-r2.json','design-r2.json'],['schema-data.json','schema-data.json'],['expired-synthetic-records.json','qualification/expired-synthetic-records.json']])await writeFile(join(target,output),await readFile(join(dir,input)));
const proof={classification:'INSTALLATION_PRINCIPAL_CLOSED_DATA_LIBRARY_ONLY',source_manifest_sha256:sha(manifestBytes),
  module_sha256:sha(await readFile(join(target,'codec-data.mjs'))),design_sha256:sha(await readFile(join(target,'design-r2.json'))),
  schema_sha256:sha(await readFile(join(target,'schema-data.json'))),public_fixture_sha256:sha(await readFile(join(target,'expired-synthetic-records.json'))),bundler_inputs:inputs,installed_inputs_sha256:installed,
  toolchain:{node:process.version,platform:process.platform,arch:process.arch,esbuild:manifest.esbuild_version},
  Worker_configuration_generated:false,production_factory:false,registry_admission:false,deployed:false};
await writeFile(join(target,'source-package.json'),JSON.stringify(proof,null,2)+'\n');console.log(JSON.stringify(proof));
