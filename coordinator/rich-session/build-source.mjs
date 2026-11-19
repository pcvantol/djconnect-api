import {readFile,mkdir,writeFile,realpath,copyFile} from 'node:fs/promises';
import {resolve,dirname,basename,join,isAbsolute,relative,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';
const root=fileURLToPath(new URL('../../',import.meta.url)),dir=fileURLToPath(new URL('./',import.meta.url));
const out=process.argv[2];if(!out||!isAbsolute(out))throw Error('new external absolute scratch required');
const target=join(await realpath(dirname(resolve(out))),basename(resolve(out))),rel=relative(await realpath(root),target);
if(rel===''||(!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep)))throw Error('output inside repository');
const sha=b=>createHash('sha256').update(b).digest('hex');
const manifestBytes=await readFile(join(dir,'source-manifest.json')),manifest=JSON.parse(manifestBytes);
for(const [path,digest]of Object.entries(manifest.inputs_sha256))if(sha(await readFile(join(root,path)))!==digest)throw Error('source input drift: '+path);
if(JSON.parse(await readFile(join(root,'node_modules/esbuild/package.json'))).version!==manifest.esbuild_version)throw Error('esbuild drift');
const installed={};for(const p of ['node_modules/esbuild/package.json','node_modules/esbuild/lib/main.js',`node_modules/@esbuild/${process.platform}-${process.arch}/bin/esbuild`])installed[p]=sha(await readFile(join(root,p)));
await mkdir(target); // Existing evidence/symlinks are never overwritten.
const output=join(target,'profile-data.mjs'),result=await build({entryPoints:[join(dir,'profile-data.ts')],outfile:output,bundle:true,metafile:true,platform:'browser',format:'esm',target:'es2024'});
if(JSON.stringify(Object.keys(result.metafile.inputs))!==JSON.stringify(['coordinator/rich-session/profile-data.ts']))throw Error('unexpected source graph');
await mkdir(join(target,'apple-fixtures'));
const receipt=JSON.parse(await readFile(join(dir,'qualification/apple-fixtures/encoder-fixture-receipt.json')));
for(const [name,info]of Object.entries(receipt.fixture_inventory)){const path=join(dir,'qualification/apple-fixtures',name),bytes=await readFile(path);if(bytes.length!==info.bytes||sha(bytes)!==info.sha256)throw Error('original Apple fixture drift');await copyFile(path,join(target,'apple-fixtures',name));}
await copyFile(join(dir,'qualification/apple-fixtures/encoder-fixture-receipt.json'),join(target,'apple-fixtures/encoder-fixture-receipt.json'));
await copyFile(join(dir,'qualification/utc-rational-cases.json'),join(target,'utc-rational-cases.json'));
await copyFile(join(dir,'contract-v1.md'),join(target,'contract-v1.md'));
await writeFile(join(target,'metafile.json'),JSON.stringify(result.metafile,null,2)+'\n');
const proof={classification:'RICH_SESSION_CLOSED_DATA_PROFILE_ONLY',source_manifest_sha256:sha(manifestBytes),module_sha256:sha(await readFile(output)),contract_sha256:sha(await readFile(join(target,'contract-v1.md'))),original_Apple_receipt_sha256:sha(await readFile(join(target,'apple-fixtures/encoder-fixture-receipt.json'))),original_fixture_files:Object.keys(receipt.fixture_inventory).length,original_encoder_cases:receipt.case_count,installed_inputs_sha256:installed,bundler_inputs:Object.keys(result.metafile.inputs),toolchain:{node:process.version,platform:process.platform,arch:process.arch,esbuild:manifest.esbuild_version},Worker_configuration_generated:false,live_profile_map:false,owner_admission:false,provider_effect:false,deployed:false};
await writeFile(join(target,'source-package.json'),JSON.stringify(proof,null,2)+'\n');console.log(JSON.stringify(proof));
