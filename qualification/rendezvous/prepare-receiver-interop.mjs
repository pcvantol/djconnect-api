// Explicit public network preparation only; separate from offline execution.
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {privateDirectory,writePrivate,need} from './local-native-files.mjs';
import {fixture,manifest,digest,emptyDirectory} from './receiver-interop-inputs.mjs';
import {repo} from './local-native-runtime.mjs';

async function main(){
 need(process.argv.length===3);process.umask(0o077);
 const dir=await privateDirectory(process.argv[2],repo);await emptyDirectory(dir);
 for(const [path,{leaf,sha256}]of Object.entries(manifest.receiver_sources)){
  need(['bootstrap/src/rendezvous.mjs','bootstrap/src/wire.mjs','bootstrap/src/wire-schema.mjs'].includes(path));
  const url='https://raw.githubusercontent.com/pcvantol/djconnect-vibecast-receiver/'+manifest.receiver_sha+'/'+path;
  const response=await fetch(url,{redirect:'manual',credentials:'omit',signal:AbortSignal.timeout(5000)});
  need(response.status===200&&!response.redirected&&response.body);
  const reader=response.body.getReader(),chunks=[];let size=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;need(size<=65536);chunks.push(value);}}finally{await reader.cancel().catch(()=>{});}
  const bytes=Buffer.concat(chunks);need(digest(bytes)===sha256);await writePrivate(dir,leaf,bytes);
 }
 for(const [leaf,sha256]of Object.entries(manifest.fixture_hashes)){
  need(leaf==='package.json'||leaf==='package-lock.json');const bytes=await readFile(join(fixture,leaf));need(digest(bytes)===sha256);await writePrivate(dir,leaf,bytes);
 }
 console.log('PUBLIC_PINNED_RECEIVER_INPUTS_PREPARED; explicit isolated npm ci required');
}
main().catch(()=>{console.error('RECEIVER_INTEROP_PREPARATION_REJECTED; partial private inputs retained; no automatic retry');process.exitCode=1;});
