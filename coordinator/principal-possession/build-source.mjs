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
const result=await build({entryPoints:[join(dir,'possession-data.ts')],outfile:join(target,'possession-data.mjs'),
  bundle:true,metafile:true,platform:'browser',format:'esm',target:'es2024'});
const inputs=Object.keys(result.metafile.inputs).sort();
if(JSON.stringify(inputs)!==JSON.stringify(['coordinator/principal-possession/possession-data.ts','src/surface-push/wire.ts']))throw Error('unexpected source graph');
await writeFile(join(target,'metafile.json'),JSON.stringify(result.metafile,null,2)+'\n');
await writeFile(join(target,'byte-contract-r1.json'),await readFile(join(dir,'byte-contract-r1.json')));
await writeFile(join(target,'public-vectors.json'),await readFile(join(dir,'public-vectors.json')));
const proof={classification:'CORE_INSTALL_POSSESSION_CRYPTO_DATA_LIBRARY_ONLY',source_manifest_sha256:sha(manifestBytes),
  module_sha256:sha(await readFile(join(target,'possession-data.mjs'))),byte_contract_sha256:sha(await readFile(join(target,'byte-contract-r1.json'))),
  public_vectors_sha256:sha(await readFile(join(target,'public-vectors.json'))),bundler_inputs:inputs,installed_inputs_sha256:installed,
  toolchain:{node:process.version,platform:process.platform,arch:process.arch,esbuild:manifest.esbuild_version},
  Worker_configuration_generated:false,production_factory:false,registry_admission:false,deployed:false};
await writeFile(join(target,'source-package.json'),JSON.stringify(proof,null,2)+'\n');console.log(JSON.stringify(proof));
