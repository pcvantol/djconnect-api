import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {need,privateDirectory,writePrivate} from './local-native-files.mjs';
import {emptyDirectory,digest} from './receiver-interop-inputs.mjs';
import {toolsFixture,toolsManifest} from './browser-interop-tools.mjs';
import {repo} from './local-native-runtime.mjs';
async function main(){
 need(process.argv.length===3);process.umask(0o077);
 const dir=await privateDirectory(process.argv[2],repo);await emptyDirectory(dir);
 for(const [name,hash]of Object.entries(toolsManifest.fixture_hashes)){
  need(name==='package.json'||name==='package-lock.json');const bytes=await readFile(join(toolsFixture,name));need(digest(bytes)===hash);await writePrivate(dir,name,bytes);
 }
 console.log('PINNED_BROWSER_TOOL_FIXTURE_PREPARED; explicit isolated npm ci and browser installation required');
}
main().catch(()=>{console.error('BROWSER_TOOL_PREPARATION_REJECTED; no automatic retry');process.exitCode=1;});
