/** Explicit source-maintenance operation. Never invoked by build/qualification.
 * Review the resulting source/installed/graph hash delta before publication. */
import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {dir,root,sha,load} from './package-lib.mjs';
const p=join(dir,'source-inputs.json'),policy=await load(p);for(const name of Object.keys(policy.inputs_sha256))policy.inputs_sha256[name]=sha(await readFile(join(root,name)));
await writeFile(p,JSON.stringify(policy,null,2)+'\n');console.log('Explicit source-input pins updated; review required.');
