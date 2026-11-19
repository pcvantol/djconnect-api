// Separate public verification tooling; never in the browser or product graph.
import {readFile,readdir} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {readPrivate,need,checkDirectory} from './local-native-files.mjs';
import {verifyPackageTree,digest} from './receiver-interop-inputs.mjs';
export const toolsFixture=join(dirname(fileURLToPath(import.meta.url)),'browser-interop');
export const toolsManifest=JSON.parse(await readFile(join(toolsFixture,'tool-inputs-v1.json')));
need(toolsManifest.schema_version===1&&toolsManifest.scope==='BROWSER_QUALIFICATION_TOOLING_NOT_PRODUCT_DEPENDENCIES');
need(Object.keys(toolsManifest).sort().join(',')==='engines,fixture_hashes,installed_hashes,metadata_links,package_integrities,schema_version,scope');
need(Object.keys(toolsManifest.installed_hashes).length===192);
export async function verifyTools(dir){
 await checkDirectory(dir);need(JSON.stringify((await readdir(dir.path)).sort())==='["node_modules","package-lock.json","package.json"]');
 for(const [name,hash]of Object.entries(toolsManifest.fixture_hashes)){
  need(name==='package.json'||name==='package-lock.json');need(digest(await readPrivate(dir,name,65536))===hash);
 }
 const lock=JSON.parse(await readPrivate(dir,'package-lock.json',65536));
 need(Object.keys(lock.packages).sort().join(',')===',node_modules/jsqr,node_modules/playwright,node_modules/playwright-core');
 for(const [name,hash]of Object.entries(toolsManifest.package_integrities))need(lock.packages['node_modules/'+name].integrity===hash);
 return verifyPackageTree(dir,toolsManifest.installed_hashes,8388608,toolsManifest.metadata_links);
}
export function moduleURL(dir,name){
 need(name==='playwright'||name==='jsqr');return pathToFileURL(join(dir.path,'node_modules',name,name==='playwright'?'index.mjs':'dist/jsQR.js')).href;
}
