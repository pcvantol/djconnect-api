// Host-only immutable public consumer fixtures, never product imports.
import {constants as F} from 'node:fs';
import {open,readFile,readdir,lstat,readlink} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {need,checkDirectory,readPrivate} from './local-native-files.mjs';

export const fixture=join(dirname(fileURLToPath(import.meta.url)),'receiver-interop');
export const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
export const manifest=JSON.parse(await readFile(join(fixture,'interop-inputs-v1.json')));
need(manifest.schema_version===1&&manifest.receiver_sha==='39844ebf8499261e26bfb59d4a871408957df4a8');
need(manifest.scope==='ACTUAL_RECEIVER_NODE_TO_ACTUAL_API_WORKER_FIXTURE_TRANSPORT_NO_NATIVE_BROWSER_EDGE_OR_HA_POSITIVE'&&manifest.receiver_repository==='pcvantol/djconnect-vibecast-receiver');
need(Object.keys(manifest).sort().join(',')==='dependency_integrity,fixture_hashes,installed_hashes,receiver_lock_sha256,receiver_repository,receiver_sha,receiver_sources,schema_version,scope');
need(Object.keys(manifest.receiver_sources).length===3&&Object.keys(manifest.installed_hashes).length===110);
export async function emptyDirectory(dir){await checkDirectory(dir);need((await readdir(dir.path)).length===0);}
async function tree(root,prefix,hashes,links){
 const directory=await lstat(join(root,prefix));need(directory.isDirectory()&&!directory.isSymbolicLink()&&directory.uid===process.getuid());
 const result=[];
 for(const name of (await readdir(join(root,prefix))).sort()){
  const relative=prefix?prefix+'/'+name:name,s=await lstat(join(root,relative));
  need(s.uid===process.getuid());
  if(Object.hasOwn(links,relative)){need(s.isSymbolicLink()&&s.nlink===1&&await readlink(join(root,relative))===links[relative]);result.push(relative);continue;}
  need(!s.isSymbolicLink());
  if(s.isDirectory()){need([...Object.keys(hashes),...Object.keys(links)].some(p=>p.startsWith(relative+'/')));result.push(...await tree(root,relative,hashes,links));}
  else{need(s.isFile()&&s.nlink===1);result.push(relative);}
 }
 return result;
}
async function installedFile(dir,path,max){
 need(/^node_modules\/(jose|qrcode-generator|playwright|playwright-core|jsqr)\/[A-Za-z0-9_./-]+$/.test(path)&&!path.split('/').includes('..'));
 const file=await open(join(dir.path,path),F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
 try{
  const before=await file.stat();need(before.isFile()&&before.nlink===1&&before.uid===process.getuid()&&before.size>0&&before.size<=max);
  const bytes=Buffer.alloc(before.size+1),{bytesRead}=await file.read(bytes,0,bytes.length,0),after=await file.stat();
  need(bytesRead===before.size&&after.size===before.size&&after.mtimeMs===before.mtimeMs&&after.ctimeMs===before.ctimeMs);return bytes.subarray(0,bytesRead);
 }finally{await file.close();}
}
// Shared host-only fingerprint primitive for two immutable public QA manifests.
export async function verifyPackageTree(dir,hashes,max=1048576,links={}){
 need(Number.isSafeInteger(max)&&max>0&&max<=8388608);await checkDirectory(dir);
 const cliLinks={'node_modules/.bin/playwright':'../playwright/cli.js','node_modules/.bin/playwright-core':'../playwright-core/cli.js'};
 need(Object.keys(links).length===0||JSON.stringify(links)===JSON.stringify(cliLinks));
 const all=await tree(dir.path,'node_modules',hashes,links);
 need(Object.keys(links).every(path=>all.includes(path)));
 const installed=all.filter(p=>p!=='node_modules/.package-lock.json'&&!Object.hasOwn(links,p)).sort();
 need(JSON.stringify(installed)===JSON.stringify(Object.keys(hashes).sort()));
 for(const [path,sha256]of Object.entries(hashes))need(digest(await installedFile(dir,path,max))===sha256);
 await checkDirectory(dir);return installed.length;
}
export async function verifyInputs(dir){
 await checkDirectory(dir);
 const expected=[...Object.values(manifest.receiver_sources).map(v=>v.leaf),'package.json','package-lock.json','node_modules'].sort();
 need(JSON.stringify((await readdir(dir.path)).sort())===JSON.stringify(expected));
 for(const {leaf,sha256}of Object.values(manifest.receiver_sources))need(digest(await readPrivate(dir,leaf,65536))===sha256);
 for(const [leaf,sha256]of Object.entries(manifest.fixture_hashes))need(digest(await readPrivate(dir,leaf,65536))===sha256);
 const lock=JSON.parse(await readPrivate(dir,'package-lock.json',65536));
 need(Object.keys(lock.packages).sort().join(',')===',node_modules/jose,node_modules/qrcode-generator');
 for(const [name,integrity]of Object.entries(manifest.dependency_integrity))need(lock.packages['node_modules/'+name].integrity===integrity);
 const installed=await verifyPackageTree(dir,manifest.installed_hashes);
 // These exact source imports were read and independently reviewed. There is
 // no dynamic receiver import, Node builtin, arbitrary URL or extra package.
 const expectedImports={'rendezvous.mjs':['jose','qrcode-generator','./wire.mjs'],'wire.mjs':['./wire-schema.mjs'],'wire-schema.mjs':[]};
 for(const [leaf,imports]of Object.entries(expectedImports)){
  const source=(await readPrivate(dir,leaf,65536)).toString('utf8');
  need(!/\bimport\s*\(|\brequire\s*\(/.test(source));
  const actual=[...source.matchAll(/^import\s+.*?from\s+['"]([^'"]+)['"];?$/gm)].map(m=>m[1]);need(JSON.stringify(actual)===JSON.stringify(imports));
 }
 await checkDirectory(dir);
 return {receiver_sources:3,installed_package_files:installed};
}
